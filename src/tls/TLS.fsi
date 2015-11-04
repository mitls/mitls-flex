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

module TLS

open Bytes
open Error
open TLSError
open Dispatch
open TLSInfo
open Tcp
open DataStream

type Connection = Dispatch.Connection

type ioresult_i =
    | ReadError of option<alertDescription> * string
    | Close     of Tcp.NetworkStream
    | Fatal     of alertDescription
    | Warning   of nextCn * alertDescription
    | CertQuery of nextCn * query * bool
    | CompletedFirst  of Connection
    | CompletedSecond of Connection
    | Read      of nextCn * msg_i
    | DontWrite of Connection

type ioresult_o =
    | WriteError    of option<alertDescription> * string
    | WriteComplete of nextCn
    | MustRead      of Connection

(* Event-driven interface *)

val read     : Connection -> ioresult_i
val write    : Connection -> msg_o -> ioresult_o
val full_shutdown : Connection -> Connection
val half_shutdown : Connection -> unit

val connect : NetworkStream -> config -> Connection
val resume  : NetworkStream -> sessionID -> config -> Connection

val rehandshake : Connection -> config -> bool * nextCn
val rekey       : Connection -> config -> bool * nextCn
val request     : Connection -> config -> bool * nextCn

val accept           : TcpListener   -> config -> Connection
val accept_connected : NetworkStream -> config -> Connection

val authorize: Connection -> query -> ioresult_i
val refuse:    Connection -> query -> unit

val getEpochIn:  Connection -> epoch
val getEpochOut: Connection -> epoch
val getSessionInfo: epoch -> SessionInfo
val getInStream:  Connection -> stream
val getOutStream: Connection -> stream
