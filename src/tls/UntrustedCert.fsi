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

module UntrustedCert

open Bytes
open Error
open TLSError
open TLSConstants

val OID_RSAEncryption : string
val OID_SHAWithRSAEncryption : string
val OID_SHA256WithRSAEncryption : string
val OID_DSASignatureKey : string

val oid_of_keyalg: sigAlg -> string

type X509Certificate2
type hint = string
type cert = bytes
type chain = list<cert>

val x509_is_for_signing: X509Certificate2 -> bool

val x509_verify: X509Certificate2 -> bool
val x509_chain: X509Certificate2 -> list<X509Certificate2>

val x509_check_key_sig_alg_one: list<Sig.alg> -> X509Certificate2 -> bool

val x509_to_secret_key: X509Certificate2 -> option<CoreSig.sigskey>
val x509_to_public_key: X509Certificate2 -> option<CoreSig.sigpkey>

val x509_is_for_key_encryption: X509Certificate2 -> bool

val x509_export_public: X509Certificate2 -> bytes

val cert_to_x509: cert -> option<X509Certificate2>

val chain_to_x509list: chain -> option<list<X509Certificate2>>

val x509list_to_chain: list<X509Certificate2> -> chain

(* First argument (list<Sig.alg>) gives the allowed signing alg. used for
 * signing the keys of the chain.
 *)

val validate_x509_chain: list<Sig.alg> -> chain -> bool

val validate_x509list: X509Certificate2 -> list<X509Certificate2> -> bool

val is_for_signing:        cert -> bool
val is_for_key_encryption: cert -> bool

val find_sigcert_and_alg: list<Sig.alg> -> hint -> list<Sig.alg> -> option<(X509Certificate2 * Sig.alg)>
val find_enccert: list<Sig.alg> -> hint -> option<X509Certificate2>

val get_chain_key_algorithm: chain -> option<sigAlg>

val get_name_info: X509Certificate2 -> string
