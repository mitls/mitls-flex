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

module PRF

open Bytes
open TLSConstants
open TLSInfo

type repr = bytes
type ms
type masterSecret = ms

#if ideal
val sample: msId -> ms
#endif

//#begin-coerce
val coerce: msId -> repr -> ms
//#end-coerce
val leak: msId -> ms -> repr

val deriveKeys: id -> id -> ms -> Role -> StatefulLHAE.state * StatefulLHAE.state

val keyCommit: csrands -> ProtocolVersion -> aeAlg -> negotiatedExtensions -> unit
val keyGenClient: id -> id -> ms -> StatefulLHAE.writer * StatefulLHAE.reader
val keyGenServer: id -> id -> ms -> StatefulLHAE.writer * StatefulLHAE.reader

val makeVerifyData:  SessionInfo -> ms -> Role -> bytes -> bytes
val checkVerifyData: SessionInfo -> ms -> Role -> bytes -> bytes -> bool

val ssl_certificate_verify: SessionInfo -> ms -> TLSConstants.sigAlg -> bytes -> bytes
