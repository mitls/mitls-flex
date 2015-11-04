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

module PwToken

// ------------------------------------------------------------------------
open Bytes
open TLSInfo
open DataStream
open Range

// ------------------------------------------------------------------------
type token
type username = string

val create   : unit -> token
val register : username -> token -> unit
val verify   : username -> token -> bool
val guess    : bytes -> token

// ------------------------------------------------------------------------
type delta = DataStream.delta

val MaxTkReprLen : int

val tk_repr  : epoch -> stream -> username -> token -> delta
val tk_plain : epoch -> stream -> range -> delta -> (username * token) option

val rp_repr  : epoch -> stream -> bool -> delta
val rp_plain : epoch -> stream -> range -> delta -> bool
