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

module Alert

open Error
open TLSError
open TLSInfo
open Range

[<NoEquality;NoComparison>]
type pre_al_state
type state = pre_al_state

type ALFragReply =
    | EmptyALFrag
    | ALFrag of range * HSFragment.fragment
    | LastALFrag of range * HSFragment.fragment * alertDescription
    | LastALCloseFrag of range * HSFragment.fragment

[<NoEquality;NoComparison>]
type alert_reply =
    | ALAck of state
    | ALFatal of alertDescription * state
    | ALWarning of alertDescription * state
    | ALClose_notify of state

val alertBytes: alertDescription -> Bytes.bytes
val parseAlert: Bytes.bytes -> Result<alertDescription>

val init: ConnectionInfo -> state

val send_alert: ConnectionInfo -> state -> alertDescription -> state

val next_fragment: ConnectionInfo -> state -> (ALFragReply * state)

val recv_fragment: ConnectionInfo -> state -> range -> HSFragment.fragment -> Result<alert_reply>

val is_incoming_empty: ConnectionInfo -> state -> bool
val reset_incoming: ConnectionInfo -> state -> ConnectionInfo -> state
val reset_outgoing: ConnectionInfo -> state -> ConnectionInfo -> state
