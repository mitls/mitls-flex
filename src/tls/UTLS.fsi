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

module UTLS

open Error
open TLSError
open Bytes
open TLSInfo
open Dispatch

type rawfd   = Tcp.NetworkStream
type fd      = int
type queryhd = int

val EI_BADHANDLE  : int
val EI_BADCERTIDX : int
val EI_READERROR  : int
val EI_CLOSE      : int
val EI_FATAL      : int
val EI_WARNING    : int
val EI_CERTQUERY  : int
val EI_HANDSHAKEN : int
val EI_DONTWRITE  : int
val EI_WRITEERROR : int
val EI_MUSTREAD   : int
val EI_HSONGOING  : int

val canwrite : fd -> int
val read     : fd -> int * bytes
val write    : fd -> bytes -> int
val shutdown : fd -> unit

val connect          : rawfd -> config -> fd
val accept_connected : rawfd -> config -> fd
