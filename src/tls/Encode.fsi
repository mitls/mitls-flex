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

module Encode

open Bytes
open Error
open TLSError
open TLSInfo
open TLSConstants
open Range

type plain
val plain: id -> LHAEPlain.adata -> nat -> bytes -> plain
val repr:  id -> LHAEPlain.adata -> range -> plain -> bytes

val mac: id -> MAC.key -> LHAEPlain.adata -> range -> LHAEPlain.plain -> plain
val verify: id -> MAC.key -> LHAEPlain.adata -> range -> plain -> Result<LHAEPlain.plain>

val decodeNoPad_bytes: id -> LHAEPlain.adata -> range -> nat -> lbytes -> rbytes * MAC.tag
val verify_MACOnly: id -> MAC.key -> LHAEPlain.adata -> range -> nat -> rbytes -> MAC.tag ->
    Result<range*LHAEPlain.plain>

#if ideal
val widen: id -> LHAEPlain.adata -> range -> plain -> plain
#endif
