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

module Tcp

open Bytes
open Error

type NetworkStream
type TcpListener

(* Create a network stream from a given stream.
   Only used by the application interface TLSharp. *)
val create: System.IO.Stream -> NetworkStream

(* Get the underlying stream.
   Only used by the FlexTLS application *)
val getStream: NetworkStream -> System.IO.Stream

(* Server side *)

val listen: string -> int -> TcpListener
val acceptTimeout: int -> TcpListener -> NetworkStream
val accept: TcpListener -> NetworkStream
val stop: TcpListener -> unit

(* Client side *)

val connectTimeout: int -> string -> int -> NetworkStream
val connect: string -> int -> NetworkStream

(* Input/Output *)

val read: NetworkStream -> int -> (string,bytes) optResult
val write: NetworkStream -> bytes -> (string,unit) optResult
val close: NetworkStream -> unit
