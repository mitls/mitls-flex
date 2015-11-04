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

module CoreHMac
open Bytes

type engine
type key = bytes

val name   : engine -> string
val mac    : engine -> bytes -> bytes

val md5engine    : key -> engine
val sha1engine   : key -> engine
val sha256engine : key -> engine
val sha384engine : key -> engine
val sha512engine : key -> engine

val md5    : key -> bytes -> bytes
val sha1   : key -> bytes -> bytes
val sha256 : key -> bytes -> bytes
val sha384 : key -> bytes -> bytes
val sha512 : key -> bytes -> bytes
