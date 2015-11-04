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

module CoreKeys
open Bytes
type modulus  = bytes
type exponent = bytes

type rsapkey = modulus * exponent
type rsaskey = modulus * exponent

type dsaparams = { p : bytes; q : bytes; g : bytes; }

type dsapkey = bytes * dsaparams
type dsaskey = bytes * dsaparams

type dhparams = { dhp : bytes; dhg : bytes; dhq : bytes; safe_prime : bool }

type dhpkey = bytes
type dhskey = bytes

type ecprime = { ecp_prime : string; ecp_order : string; ecp_a : string; ecp_b : string; ecp_gx : string; ecp_gy : string; ecp_bytelen : int; ecp_id : bytes; }
type eccurve =
| EC_PRIME of ecprime

type ecpoint = { ecx : bytes; ecy : bytes; }
type ecdhparams = { curve: eccurve; compression: bool; }
type ecdhpkey = ecpoint
type ecdhskey = bytes
