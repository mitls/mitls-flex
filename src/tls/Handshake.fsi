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

(* Handshake protocol *)
module Handshake

open Error
open TLSError
open TLSInfo
open TLSConstants
open Range

// protocol state
type hs_state
type nextState = hs_state

(* Control Interface *)
// Create instance for a fresh connection (without resumption)
val init: Role -> config -> (ConnectionInfo * hs_state)

// Create instance for a fresh connection (Client-only, resuming some other sessions)
val resume: sessionID -> config -> (ConnectionInfo * hs_state)

// Idle client starts a full handshake on the current connection
val rehandshake: ConnectionInfo -> hs_state -> config -> bool * hs_state

// Idle client starts an abbreviated handshake resuming the current session
val rekey:       ConnectionInfo -> hs_state -> config -> bool * hs_state

// (Idle) Server requests an handshake
val request:  ConnectionInfo -> hs_state -> config -> bool * hs_state

val invalidateSession: ConnectionInfo -> hs_state -> hs_state

(* Network Interface *)

[<NoEquality;NoComparison>]
type outgoing =
  | OutIdle of hs_state
  | OutSome of range * HSFragment.fragment * hs_state
  | OutCCS of  range * HSFragment.fragment (* the unique one-byte CCS *) *
               ConnectionInfo * StatefulLHAE.state * hs_state
  | OutFinished of range * HSFragment.fragment * hs_state
  | OutComplete of range * HSFragment.fragment * hs_state
val next_fragment: ConnectionInfo  -> hs_state -> outgoing

(* Receiving Handshake and CCS fragments *)

[<NoEquality;NoComparison>]
type incoming = (* the fragment is accepted, and... *)
  | InAck of hs_state
  | InVersionAgreed of hs_state * ProtocolVersion
  | InQuery of Cert.chain * bool * hs_state
  | InFinished of hs_state
  | InComplete of hs_state
  | InError of alertDescription * string * hs_state
val recv_fragment: ConnectionInfo -> hs_state -> range -> HSFragment.fragment -> incoming
val authorize: ConnectionInfo -> hs_state -> Cert.chain -> incoming

[<NoEquality;NoComparison>]
type incomingCCS =
  | InCCSAck of ConnectionInfo * StatefulLHAE.state * hs_state
  | InCCSError of alertDescription * string * hs_state
val recv_ccs     : ConnectionInfo -> hs_state -> range -> HSFragment.fragment -> incomingCCS

val getMinVersion: ConnectionInfo -> hs_state -> ProtocolVersion

val negotiate: list<'a> -> list<'a> -> option<'a> when 'a:equality
