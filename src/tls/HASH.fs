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

module HASH

open Bytes
open TLSConstants

(* Parametric hash algorithm (implements interface) *)
let hash' alg data =
    match alg with
    | NULL    -> data
    | MD5SHA1 -> (CoreHash.md5 data) @| (CoreHash.sha1 data)
    | MD5     -> (CoreHash.md5    data)
    | SHA     -> (CoreHash.sha1   data)
    | SHA256  -> (CoreHash.sha256 data)
    | SHA384  -> (CoreHash.sha384 data)

let hash alg data =
  let h = hash' alg data in
  let l = length h in
  let exp = hashSize alg in
  if l = exp then h
  else Error.unexpected "CoreHash returned a hash of an unexpected size"
