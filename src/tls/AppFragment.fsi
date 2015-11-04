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
open TLSError

type preFragment
type fragment = preFragment
val fragment: epoch -> stream -> range -> delta -> fragment * stream
val delta: epoch -> stream -> range -> fragment -> delta * stream
type plain = fragment

val plain: id -> range -> bytes -> fragment
val repr:  id -> range -> fragment -> bytes

val makeExtPad:  id -> range -> fragment -> fragment
val parseExtPad: id -> range -> fragment -> Result<fragment>

#if ideal
val widen: id -> range -> fragment -> fragment
#endif
