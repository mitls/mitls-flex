(*
 * Copyright 2015 INRIA and Microsoft Corporation
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *)

#light "off"

module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream
open Error
open TLSError

#if ideal
type fpred = DeltaFragment of epoch * stream * range * delta
#endif

type preFragment = {frag: epoch * stream * delta}
type fragment = preFragment
type plain = fragment

let fragment e s r d =
    let i = mk_id e in
    let f = {frag = e,s,d} in
    #if ideal
    Pi.assume (DeltaFragment(e,s,r,d));
    #endif
    let s' = append e s r d in
    (f,s')

let check (e:epoch) (e':epoch) = ()

let delta e s r f =
    let (e',s',d) = f.frag in
    // the following idealization is reindexing.
    #if ideal
    if auth e then
      // typechecking relies on e = e' & s = s':
      // they both follow from Auth(e), implying Sent(e,s,r,f) hence ?d. f.frag = (e,s,d)
      let s'' = append e s r d in
      (d,s'')
    else
      // we coerce d to the local epoch

      let raw = deltaRepr e' s' r d in
      let d' = deltaPlain e s r raw in
      let s'' = append e s r d' in
      (d',s'')
    #else
      // we could skip this append
      let s'' = append e s r d in
      (d,s'')
    #endif

let plain i r b =
  let e = TLSInfo.unAuthIdInv i in
  let s = DataStream.init e in
  let d = DataStream.deltaPlain e s r b in
  {frag = (e,s,d)}

let repr (i:id) r f =
  let (e',s,d) = f.frag in
  DataStream.deltaRepr e' s r d

let makeExtPad (i:id) (r:range) (f:fragment) =
#if TLSExt_extendedPadding
    if TLSExtensions.hasExtendedPadding i then
        let (e',s,d) = f.frag in

        let b = DataStream.deltaBytes e' s r d in
        let len = length b in
        let pad = extendedPad i r len in
        let padded = pad@|b in
        let d = DataStream.createDelta e' s r padded in
        {frag = (e',s,d)}
    else
#endif
        f

let parseExtPad (i:id) (r:range) (f:fragment) : Result<fragment> =
#if TLSExt_extendedPadding
    if TLSExtensions.hasExtendedPadding i then
        let (e',s,d) = f.frag in
        let b = DataStream.deltaBytes e' s r d in
        match TLSConstants.vlsplit 2 b with
        | Error(x) -> Error(x)
        | Correct(res) ->
            let (_,b) = res in
            let d = DataStream.createDelta e' s r b in
            correct ({frag = (e',s,d)})
    else
#endif
        correct f

#if ideal
let widen (i:id) (r0:range) (f0:fragment) =
    let r1 = rangeClass i r0 in
    let (e,s,d0) = f0.frag in
    let d1 = DataStream.widen e s r0 r1 d0 in
    let (f1,_) = fragment e s r1 d1 in
    f1
#endif
