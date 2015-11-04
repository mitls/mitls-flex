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

module RSAKey

open Bytes

type pk = { pk : CoreACiphers.pk }
type sk = { sk : CoreACiphers.sk }

type pred = | SK_PK of sk * pk

#if ideal

let honest_log = ref[]
let honest (pk:pk): bool = failwith "only used in ideal implementation, unverified"
let strong (pv:TLSConstants.ProtocolVersion): bool = failwith "only used in ideal implementation, unverified"
#endif

type modulus  = bytes
type exponent = bytes

let gen () : (pk * sk) =
    let csk, cpk = CoreACiphers.gen_key () in
    let sk = {sk = csk} in
    let pk = {pk = cpk} in
    Pi.assume(SK_PK(sk,pk));
    pk, sk

let coerce (pk:pk) (csk:CoreACiphers.sk) =
    let sk= {sk = csk} in
    Pi.assume(SK_PK(sk,pk));
    sk

let repr_of_rsapkey ({ pk = pk }) = pk
let repr_of_rsaskey ({ sk = sk }) = sk

let create_rsapkey ((m, e) : modulus * exponent) = { pk = CoreACiphers.RSAPKey(m, e) }
//let create_rsaskey ((m, e) : modulus * exponent) = { sk = CoreACiphers.RSASKey(m, e) }
