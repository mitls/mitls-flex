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
open TLSInfo
open Range
open TLSError

type adata = bytes
type fragment
type plain = fragment

val plain: id -> adata -> range -> bytes -> plain
val repr:  id -> adata -> range -> plain -> bytes

val makeAD: id -> StatefulPlain.history -> StatefulPlain.adata -> adata
val parseAD: id -> adata -> StatefulPlain.adata
val StatefulPlainToLHAEPlain: id -> StatefulPlain.history -> StatefulPlain.adata -> adata -> range -> StatefulPlain.plain -> plain
val LHAEPlainToStatefulPlain: id -> StatefulPlain.history -> StatefulPlain.adata -> adata -> range -> plain -> StatefulPlain.plain

val makeExtPad:  id -> adata -> range -> plain -> plain
val parseExtPad: id -> adata -> range -> plain -> Result<plain>

#if ideal
val widen: id -> adata -> range -> fragment -> fragment
#endif
