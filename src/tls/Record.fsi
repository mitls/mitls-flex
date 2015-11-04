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

module Record

open Bytes
open Tcp
open TLSConstants
open Error
open TLSError
open TLSInfo
open Range

/// Implements stateful AE on top of LHAE,
/// managing sequence numbers and the binary record format

type ConnectionState
type sendState = ConnectionState
type recvState = ConnectionState

val initConnState: epoch -> rw -> StatefulLHAE.state -> ConnectionState
val nullConnState: epoch -> rw -> ConnectionState

val parseHeader: bytes -> Result<(ContentType * ProtocolVersion * nat)>
val makePacket: ContentType -> ProtocolVersion -> bytes -> bytes

val recordPacketOut: epoch -> sendState -> ProtocolVersion -> range -> ContentType -> TLSFragment.fragment -> (sendState * bytes)
val recordPacketIn : epoch -> recvState -> ContentType -> bytes -> Result<(recvState * range * TLSFragment.fragment)>

val history: epoch -> rw -> ConnectionState -> TLSFragment.history
