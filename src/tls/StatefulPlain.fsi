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
open TLSConstants
open TLSInfo
open Range
open Error
open TLSError

type adata = bytes

type fragment
type prehistory = list<(adata * range * fragment)>
type history  = (nat * prehistory)
type plain = fragment

//------------------------------------------------------------------------------
val plain: id -> history -> adata -> range -> bytes -> plain
val reprFragment:  id -> adata -> range -> fragment -> bytes
val repr:  id -> history -> adata -> range -> plain -> bytes

//------------------------------------------------------------------------------
val emptyHistory: id -> history
val extendHistory: id -> adata -> history -> range -> fragment -> history

val makeAD: id -> ContentType -> adata
val RecordPlainToStAEPlain: epoch -> ContentType -> adata -> TLSFragment.history -> history -> range -> TLSFragment.plain -> plain
val StAEPlainToRecordPlain: epoch -> ContentType -> adata -> TLSFragment.history -> history -> range -> plain -> TLSFragment.plain

val makeExtPad:  id -> adata -> range -> fragment -> fragment
val parseExtPad: id -> adata -> range -> fragment -> Result<fragment>

#if ideal
val widen: id -> adata -> range -> fragment -> fragment
#endif
