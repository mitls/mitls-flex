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

module Sig

open Bytes
open TLSConstants

(* ------------------------------------------------------------------------ *)
type alg   = sigHashAlg

type text = bytes
type sigv = bytes

(* ------------------------------------------------------------------------ *)
type skey
type pkey

val honest: alg -> pkey -> bool

val create_pkey: alg -> CoreSig.sigpkey -> pkey

val sigalg_of_skeyparams : CoreSig.sigskey -> sigAlg
val sigalg_of_pkeyparams : CoreSig.sigpkey -> sigAlg

(* ------------------------------------------------------------------------ *)
val gen    : alg -> pkey * skey
val sign   : alg -> skey -> text -> sigv
val verify : alg -> pkey -> text -> sigv -> bool
val coerce : alg -> pkey -> CoreSig.sigskey -> skey
val leak   : alg -> skey -> CoreSig.sigskey
