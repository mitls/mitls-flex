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

module DHDB

open Bytes

// p, g, q, true  => prime(p) /\ prime(q) /\ g^q mod p = 1 /\ p = 2*q + 1
// p, g, q, false => prime(p) /\ prime(q) /\ g^q mod p = 1 /\ ?j. p = j*q + 1 /\ length(q) >= threshold
type Key   = bytes * bytes // p, g
type Value = bytes * bool  // q, safe_prime?

type dhdb

val defaultFileName: string

val create: string -> dhdb
val select: dhdb -> Key -> Value option
val insert: dhdb -> Key -> Value -> dhdb
val remove: dhdb -> Key -> dhdb
val keys  : dhdb -> Key list
val merge : dhdb -> string -> dhdb
