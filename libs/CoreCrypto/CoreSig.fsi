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

module CoreSig
open Bytes

(* ------------------------------------------------------------------------ *)
type sighash =
| SH_MD5
| SH_SHA1
| SH_SHA256
| SH_SHA384

type sigalg =
| CORE_SA_RSA
| CORE_SA_DSA
| CORE_SA_ECDSA

(* ------------------------------------------------------------------------ *)
type sigskey =
| SK_RSA of CoreKeys.rsaskey
| SK_DSA of CoreKeys.dsaskey
| SK_ECDH of CoreKeys.ecdhskey

type sigpkey =
| PK_RSA of CoreKeys.rsapkey
| PK_DSA of CoreKeys.dsapkey
| PK_ECDH of CoreKeys.ecdhpkey

val sigalg_of_skey : sigskey -> sigalg
val sigalg_of_pkey : sigpkey -> sigalg

(* ------------------------------------------------------------------------ *)
type text = bytes
type sigv = bytes

val gen    : sigalg -> sigpkey * sigskey
val sign   : sighash option -> sigskey -> text -> sigv
val verify : sighash option -> sigpkey -> text -> sigv -> bool
