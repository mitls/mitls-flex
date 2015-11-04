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

module StatefulLHAE

open Bytes
open Error
open TLSError
open TLSInfo
open Range
open StatefulPlain

type state
type reader = state
type writer = state

val GEN:     id -> reader * writer
val COERCE:  id -> rw -> bytes -> state
val LEAK:    id -> rw -> state -> bytes

val history: id -> rw -> state -> history

type cipher = LHAE.cipher

val encrypt: id -> writer ->  adata -> range -> plain -> (writer * cipher)
val decrypt: id -> reader ->  adata -> cipher -> Result<(reader * range * plain)>
