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

module LHAEPlain
open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo
open Range

type adata = bytes

let makeAD (i:id) ((seqn,h):StatefulPlain.history) ad =
    let bn = bytes_of_seq seqn in
    bn @| ad

// We statically know that ad is big enough
let parseAD (i:id) ad =
    let (snb,ad) = Bytes.split ad 8 in
    ad

type fragment = {contents:StatefulPlain.fragment}
type plain = fragment

let plain (i:id) (ad:adata) (rg:range) b =
    let ad = parseAD i ad in
    let h = StatefulPlain.emptyHistory i in
    let p = StatefulPlain.plain i h ad rg b in
    {contents =  p}

let reprFragment (i:id) (ad:adata) (rg:range) p =
    let ad = parseAD i ad in
    StatefulPlain.reprFragment i ad rg p.contents

let repr i ad rg p = reprFragment i ad rg p

let StatefulPlainToLHAEPlain (i:id) (h:StatefulPlain.history)
    (ad:StatefulPlain.adata) (ad':adata) (r:range) f = {contents = f}
let LHAEPlainToStatefulPlain (i:id) (h:StatefulPlain.history)
    (ad:StatefulPlain.adata) (ad':adata) (r:range) f = f.contents

let makeExtPad id ad rg p =
    let ad = parseAD id ad in
    let c = p.contents in
    let c = StatefulPlain.makeExtPad id ad rg c in
    {contents = c}

let parseExtPad id ad rg p =
    let ad = parseAD id ad in
    let c = p.contents in
    match StatefulPlain.parseExtPad id ad rg c with
    | Error(x) -> Error(x)
    | Correct(c) -> correct ({contents = c})

#if ideal
let widen i ad r f =
    let ad' = parseAD i ad in
    let f' = StatefulPlain.widen i ad' r f.contents in
    {contents = f'}
#endif
