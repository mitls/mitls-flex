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

module Range

open Bytes
open TLSInfo

type range = nat * nat
type rbytes = bytes
val sum: range -> range -> range

val ivSize: id -> nat
val fixedPadSize: id -> nat
val maxPadSize: id -> nat
#if TLSExt_extendedPadding
val extendedPad: id -> range -> nat -> bytes
#endif
val targetLength: id -> range -> nat
val cipherRangeClass: id -> nat -> range
val rangeClass: id -> range -> range
