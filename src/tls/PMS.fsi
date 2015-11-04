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

module PMS

open Bytes
open TLSConstants
open Error
open TLSError
open DHGroup
open CoreKeys

type rsarepr = bytes
type rsaseed = {seed: rsarepr}
type rsapms =
#if ideal
  | IdealRSAPMS of rsaseed
#endif
  | ConcreteRSAPMS of rsarepr

type dhrepr = bytes
type dhseed = {seed: dhrepr}

type dhpms =
#if ideal
  | IdealDHPMS of dhseed
#endif
  | ConcreteDHPMS of dhrepr

#if ideal
val honestRSAPMS: RSAKey.pk -> TLSConstants.ProtocolVersion -> rsapms -> bool
#endif

val genRSA: RSAKey.pk -> TLSConstants.ProtocolVersion -> rsapms

val coerceRSA: RSAKey.pk -> ProtocolVersion -> rsarepr -> rsapms
val leakRSA: RSAKey.pk -> ProtocolVersion -> rsapms -> rsarepr

#if ideal
val honestDHPMS: bytes -> bytes -> elt -> elt -> dhpms -> bool
#endif

val sampleDH: dhparams -> DHGroup.elt -> DHGroup.elt -> dhpms

val coerceDH: dhparams -> DHGroup.elt -> DHGroup.elt -> DHGroup.elt -> dhpms
val coerceECDH: ecdhparams  -> ECGroup.point -> ECGroup.point -> bytes -> dhpms

(* Used when generating key material from the MS.
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)

type pms =
  | RSAPMS of RSAKey.pk * ProtocolVersion * rsapms
  | DHPMS of CommonDH.parameters * CommonDH.element * CommonDH.element * dhpms
