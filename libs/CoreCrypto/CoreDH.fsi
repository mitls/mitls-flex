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

module CoreDH

open Bytes
open Error
open CoreKeys
open DHDB

val defaultPQMinLength: (nat*nat)

(* ------------------------------------------------------------------------ *)
val check_p_g: nat -> nat -> nat -> bytes -> bytes -> (string,bytes) optResult
val check_p_g_q: nat -> nat -> nat -> bytes -> bytes -> bytes -> (string,bool) optResult

(* ------------------------------------------------------------------------ *)
val check_params : dhdb -> nat -> nat * nat -> bytes -> bytes -> (string,dhdb*dhparams) optResult
val check_element: dhparams -> bytes -> bool
val gen_key      : dhparams -> dhskey * dhpkey
// less efficient implementation, in case q is not available
val gen_key_pg   : bytes -> bytes -> dhskey * dhpkey
val agreement    : bytes -> dhskey -> dhpkey -> bytes

(* ------------------------------------------------------------------------ *)
// Throws exceptions in case of error
// (file not found, parsing error, unsafe parameters...)
val load_default_params   : string -> dhdb -> nat -> nat * nat -> dhdb*dhparams

(* Constant groups as defined in draft-ietf-tls-negotiated-dl-dhe *)
val dhe2432: dhparams
val dhe3072: dhparams
val dhe4096: dhparams
val dhe6144: dhparams
val dhe8192: dhparams
