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

module AppData

open TLSInfo
open Bytes
open Error
open TLSError
open DataStream
open Range

type app_state

val inStream:  ConnectionInfo -> app_state -> stream
val outStream: ConnectionInfo -> app_state -> stream

val init:           ConnectionInfo -> app_state
val writeAppData:   ConnectionInfo -> app_state -> range -> AppFragment.fragment -> stream -> app_state
val next_fragment:  ConnectionInfo -> app_state -> option<(range * AppFragment.fragment * app_state)>
val clearOutBuf:    ConnectionInfo -> app_state -> app_state

val recv_fragment:  ConnectionInfo -> app_state -> range -> AppFragment.fragment -> delta * app_state

val reset_incoming: ConnectionInfo -> app_state -> ConnectionInfo -> app_state
val reset_outgoing: ConnectionInfo -> app_state -> ConnectionInfo -> app_state
