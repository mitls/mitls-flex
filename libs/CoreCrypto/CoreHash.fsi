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

module CoreHash
open Bytes

type engine

val name   : engine -> string
val digest : engine -> bytes -> bytes

val md5engine    : unit -> engine
val sha1engine   : unit -> engine
val sha256engine : unit -> engine
val sha384engine : unit -> engine
val sha512engine : unit -> engine

val md5    : bytes -> bytes
val sha1   : bytes -> bytes
val sha256 : bytes -> bytes
val sha384 : bytes -> bytes
val sha512 : bytes -> bytes
