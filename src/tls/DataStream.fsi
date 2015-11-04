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

module DataStream
open TLSInfo
open Bytes
open Error
open TLSError
open Range

val splitRange: epoch -> range -> range * range

type stream
type delta

// The following two functions are used only by the application.
// They are never called from TLS.
val createDelta: epoch -> stream -> range -> rbytes -> delta
val deltaBytes: epoch -> stream -> range -> delta -> rbytes

val init: epoch -> stream
val append: epoch -> stream -> range -> delta -> stream
val split: epoch -> stream -> range -> range -> delta -> delta * delta
val deltaPlain: epoch -> stream -> range -> rbytes -> delta
val deltaRepr: epoch -> stream -> range -> delta -> rbytes

#if ideal
val widen: epoch -> stream -> range -> range -> delta -> delta
#endif
