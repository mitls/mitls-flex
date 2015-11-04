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

module DB

type db

type key   = string
type value = string

exception DBError of string

val opendb  : string -> db
val closedb : db -> unit
val put     : db -> key -> value -> unit
val get     : db -> key -> value option
val remove  : db -> key -> bool
val all     : db -> (key * value) list
val keys    : db -> key list
val merge   : db -> string -> unit
val tx      : db -> (db -> 'a) -> 'a
