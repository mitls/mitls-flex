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

module HSFragment
open Bytes
open TLSInfo
open Range
open Error
open TLSError

type stream

type fragment
type plain = fragment

val fragmentRepr: id -> range -> fragment -> bytes
val fragmentPlain: id -> range -> bytes -> fragment

val extend: id -> stream -> range -> fragment -> stream
val init: id -> stream

val reStream: id -> stream -> range -> plain -> stream -> plain

val makeExtPad:  id -> range -> fragment -> fragment
val parseExtPad: id -> range -> fragment -> Result<fragment>

#if ideal
val widen: id -> range -> range -> fragment -> fragment
#endif
