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

module Nonce

open Bytes
open Error
open TLSConstants

let timestamp () = bytes_of_int 4 (Date.secondsFromDawn ())

let random (n:nat) =
  let r = CoreRandom.random n in
  let l = length r in
  if l = n then r
  else unexpected "CoreRandom.random returned incorrect number of bytes"

let noCsr = random 64 // a constant value, with negligible probability of being sampled, excluded by idealization

#if ideal
let log = ref []
#endif

let mkHelloRandom_int (pv: ProtocolVersion) =
#if tls13
    match pv with
    | TLS_1p3 -> random 32
    | TLS_1p2 | TLS_1p1
    | TLS_1p0 | SSL_3p0 ->
#endif
      timestamp() @| random 28

let rec mkHelloRandom pv: bytes =
    let cr = mkHelloRandom_int pv in
    //#begin-idealization
    #if ideal
    if List.memr !log cr then
        mkHelloRandom pv // we formally retry to exclude collisions.
    else
        (log := cr::!log;
        cr)
    #else
    //#end-idealization
    cr
    #endif
