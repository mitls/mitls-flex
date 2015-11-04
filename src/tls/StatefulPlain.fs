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

module StatefulPlain
open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo
open Range

type cadata = cbytes
type adata = bytes

let makeAD (i:id) ct =
    let pv   = pv_of_id i in
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0
    then bct
    else bct @| bver

let parseAD (i:id) ad =
    let pv = pv_of_id i in
    if pv = SSL_3p0 then
        let pct = parseCT ad in
        match pct with
        | Error x -> unexpected "[parseAD] should never parse failing"
        | Correct(ct) -> ct
    else
        if length ad = 3 then
            let (bct, bver) = Bytes.split ad 1 in
            match parseCT bct with
            | Error x -> unexpected "[parseAD] should never parse failing"
            | Correct(ct) ->
                (match parseVersion bver with
                | Error x -> unexpected "[parseAD] should never parse failing"
                | Correct(ver) ->
                    if pv <> ver then
                        unexpected "[parseAD] should never parse failing"
                    else ct)
        else
            unexpected "[parseAD] should never parse failing"

type fragment = {contents: TLSFragment.fragment}

type prehistory = list<(adata * range * fragment)>
type history = (nat * prehistory)

type plain = fragment

let consHistory (i:id) (h:prehistory) (d:adata) (r:range) (f:fragment) =
#if ideal
    (d,r,f)::h
#else
    h
#endif

let emptyHistory (i:id): history = (0,[])
let extendHistory (i:id) d (sh:history) (r:range) f =
  let (seqn,h) = sh in
  let s' = seqn+1 in
  let nh = consHistory i h d r f in
  let res = (s',nh) in
  res

let plain (i:id) (h:history) (ad:adata) (r:range) (b:bytes) =

    let ct = parseAD i ad in
    {contents = TLSFragment.fragment i ct r b}
let reprFragment (i:id) (ad:adata) (r:range) (f:plain) =
    let ct = parseAD i ad in
    let x = f.contents in
    TLSFragment.reprFragment i ct r x
let repr i (h:history) ad r f = reprFragment i ad r f

let makeExtPad (i:id) (ad:adata) (r:range) f =
    let ct = parseAD i ad in
    let p = f.contents in
    let p = TLSFragment.makeExtPad i ct r p in
    {contents = p}

let parseExtPad (i:id) (ad:adata) (r:range) f =
    let ct = parseAD i ad in
    let p = f.contents in
    match TLSFragment.parseExtPad i ct r p with
    | Error(x) -> Error(x)
    | Correct(p) -> correct ({contents = p})

#if ideal
let widen i ad r f =
    let ct = parseAD i ad in
    let f1 = TLSFragment.widen i ct r f.contents in
    {contents = f1}
#endif

let RecordPlainToStAEPlain (e:epoch) (ct:ContentType) (ad:adata) (h:TLSFragment.history) (sh:history) (rg:range) f = {contents = f}
let StAEPlainToRecordPlain (e:epoch) (ct:ContentType) (ad:adata) (h:TLSFragment.history) (sh:history) (rg:range) f = f.contents
