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

module Cert

open Bytes
open Error
open TLSError
open UntrustedCert

type hint = UntrustedCert.hint
type cert = UntrustedCert.cert

type chain = UntrustedCert.chain
type sign_cert = option<(chain * Sig.alg * Sig.skey)>
type enc_cert  = option<(chain * RSAKey.sk)>

val for_signing : list<Sig.alg> -> hint -> list<Sig.alg> -> sign_cert
val for_key_encryption : list<Sig.alg> -> hint -> enc_cert

val get_public_signing_key : cert -> Sig.alg -> Result<Sig.pkey>
val get_public_encryption_key : cert -> Result<RSAKey.pk>

val get_chain_public_signing_key : chain -> Sig.alg -> Result<Sig.pkey>
val get_chain_public_encryption_key : chain -> Result<RSAKey.pk>

val is_chain_for_signing : chain -> bool
val is_chain_for_key_encryption : chain -> bool

val get_hint : chain -> option<hint>
val validate_cert_chain : list<Sig.alg> -> chain -> bool
val parseCertificateList: bytes -> Result<chain>
val certificateListBytes: chain -> bytes
