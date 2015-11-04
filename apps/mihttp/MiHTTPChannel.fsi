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

module MiHTTPChannel

open Bytes
open MiHTTPData

type channelid = bytes
type hostname  = string

type channel_infos = {
    channelid : bytes;
    hostname  : hostname;
}

type channel

(* Channels statically bound to a hostname *)
type rchannel = channel

type auth =
| ACert of string

type cstate = {
    c_channelid   : cbytes;
    c_hostname    : hostname;
    c_credentials : string option;
}

type request = { uri: string; }

val save_channel    : channel -> cstate
val restore_channel : cstate -> channel

val cinfos : channel -> channel_infos

val connect : hostname -> channel
val request : channel -> auth option -> string -> unit
val poll    : channel -> (request * cdocument) option
