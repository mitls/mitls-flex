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

module CoreRandom

open Org.BouncyCastle.Security

let provider = new SecureRandom()

let random (i : int) =
    if i < 0 then
        invalidArg "length" "must be non-negative";

    let bytes = Array.create i 0uy in
        lock provider (fun () -> provider.NextBytes(bytes, 0, i));
        Bytes.abytes bytes
