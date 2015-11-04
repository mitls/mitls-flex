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

module HMAC

open Bytes
open TLSConstants

type key = bytes
type data = bytes
type mac = bytes

(* SSL/TLS constants *)

let ssl_pad1_md5  = createBytes 48 0x36
let ssl_pad2_md5  = createBytes 48 0x5c
let ssl_pad1_sha1 = createBytes 40 0x36
let ssl_pad2_sha1 = createBytes 40 0x5c

(* SSL3 keyed hash *)

let sslKeyedHashPads alg =
  match alg with
    | MD5 -> (ssl_pad1_md5, ssl_pad2_md5)
    | SHA -> (ssl_pad1_sha1, ssl_pad2_sha1)
    | _   -> Error.unexpected "[sslKeyedHashPads] invoked on unsupported algorithm"

let sslKeyedHash alg key data =
    let (pad1, pad2) = sslKeyedHashPads alg in
    let dataStep1 = key @| pad1 @| data in
    let step1 = HASH.hash alg dataStep1 in
    let dataStep2 = key @| pad2 @| step1 in
    HASH.hash alg dataStep2

let sslKeyedHashVerify alg key data expected =
    let result = sslKeyedHash alg key data in
    equalBytes result expected

(* Parametric keyed hash *)

let hmac alg key data =
    match alg with
    | MD5     -> (CoreHMac.md5    key data)
    | SHA     -> (CoreHMac.sha1   key data)
    | SHA256  -> (CoreHMac.sha256 key data)
    | SHA384  -> (CoreHMac.sha384 key data)
    | NULL    -> Error.unexpected "[HMAC] Invalid hash (NULL) for HMAC"
    | MD5SHA1 -> Error.unexpected "[HMAC] Invalid hash (MD5SHA1) for HMAC"

let hmacVerify alg key data expected =
    let result = hmac alg key data in
    equalBytes result expected

(* Top level MAC function *)

let tls_mac a k d =
    match a with
    | MA_HMAC(alg) ->
        let h = hmac alg k d in
        let l = length h in
        let exp = macSize a in
          if l = exp then h
          else Error.unexpected "CoreHMac returned a MAC of unexpected size"
    | MA_SSLKHASH(alg) ->
        let h = sslKeyedHash alg k d in
        let l = length h in
        let exp = macSize a in
          if l = exp then h
          else Error.unexpected "sslKeyedHash returned a MAC of unexpected size"

let tls_macVerify a k d t =
    match a with
    | MA_HMAC(alg) -> hmacVerify alg k d t
    | MA_SSLKHASH(alg) -> sslKeyedHashVerify alg k d t
