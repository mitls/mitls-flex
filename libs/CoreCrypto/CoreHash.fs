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

open CryptoProvider

(* ---------------------------------------------------------------------- *)
type engine = HashEngine of MessageDigest

let name (HashEngine engine) =
    engine.Name

let digest (HashEngine engine) (b : bytes) =
    abytes (engine.Digest (cbytes b))

(* ---------------------------------------------------------------------- *)
let md5engine    () = HashEngine (CoreCrypto.Digest "MD5"   )
let sha1engine   () = HashEngine (CoreCrypto.Digest "SHA1"  )
let sha256engine () = HashEngine (CoreCrypto.Digest "SHA256")
let sha384engine () = HashEngine (CoreCrypto.Digest "SHA384")
let sha512engine () = HashEngine (CoreCrypto.Digest "SHA512")

(* ---------------------------------------------------------------------- *)
let dohash (factory : unit -> engine) (x : bytes) =
    let engine = factory () in
        (digest engine x)

let md5    x = dohash md5engine    x
let sha1   x = dohash sha1engine   x
let sha256 x = dohash sha256engine x
let sha384 x = dohash sha384engine x
let sha512 x = dohash sha512engine x
