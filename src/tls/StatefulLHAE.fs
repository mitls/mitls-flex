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

module StatefulLHAE

// implemented using LHAE with a sequence number

open Bytes
open Error
open TLSError
open TLSInfo
open StatefulPlain
open Range

type state = {
  key: LHAE.LHAEKey;
  history: history
}
type reader = state
type writer = state

let GEN ki =
  let w,r = LHAE.GEN ki in
  let h = emptyHistory ki in
  ( { key = r; history = h},
    { key = w; history = h})
let COERCE ki (rw:rw) b =
  let k  = LHAE.COERCE ki rw b in
  let h = emptyHistory ki in
  { key = k; history = h}
let LEAK ki (rw:rw) s = LHAE.LEAK ki rw s.key

let history (ki:id) (rw:rw) s = s.history

type cipher = LHAE.cipher

let encrypt (ki:id) (w:writer) (ad0:adata) (r:range) (f:plain) =
  let h = w.history in
  let ad = LHAEPlain.makeAD ki h ad0 in
  let p = LHAEPlain.StatefulPlainToLHAEPlain ki h ad0 ad r f in
  let k,c = LHAE.encrypt ki w.key ad r p in
  let h = extendHistory ki ad0 h r f in
  let w = {key = k; history = h} in
  (w,c)

let decrypt (ki:id) (r:reader) (ad0:adata) (e:cipher) =
  let h = r.history in
  let ad = LHAEPlain.makeAD ki h ad0 in
  let res = LHAE.decrypt ki r.key ad e in
  match res with
    | Correct(x) ->
          let (k,rg,p) = x in
          let f = LHAEPlain.LHAEPlainToStatefulPlain ki h ad0 ad rg p in
          let h = extendHistory ki ad0 h rg f in
          let r' = {history = h; key = k} in
          correct ((r',rg,f))
    | Error(e) -> Error(e)
