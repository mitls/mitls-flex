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

module LHAE

open Bytes
open Error
open TLSError
open TLSInfo
open LHAEPlain
open Range

type LHAEKey
type encryptor = LHAEKey
type decryptor = LHAEKey

type cipher = bytes

val GEN: id -> encryptor * decryptor
val COERCE: id -> rw -> bytes -> LHAEKey
val LEAK: id -> rw -> LHAEKey -> bytes

val encrypt: id -> encryptor -> adata ->
             range -> plain -> (encryptor * cipher)
val decrypt: id -> decryptor -> adata ->
             cipher -> Result<(decryptor * range * plain)>
