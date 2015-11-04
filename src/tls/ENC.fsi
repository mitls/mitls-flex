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

module ENC

open Bytes
open TLSInfo

type state
type encryptor = state
type decryptor = state

val GEN:    id -> encryptor * decryptor
val LEAK:   id -> rw -> state -> bytes * bytes
val COERCE: id -> rw -> bytes -> bytes-> state

type cipher = bytes

val ENC: id -> encryptor -> LHAEPlain.adata -> Range.range -> Encode.plain -> (encryptor * cipher)
val DEC: id -> decryptor -> LHAEPlain.adata -> cipher -> (decryptor * Encode.plain)
