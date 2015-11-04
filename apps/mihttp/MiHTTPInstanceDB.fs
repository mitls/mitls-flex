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

module MiHTTPInstanceDB

open Bytes
open Serialization
open MiHTTPChannel

let dbname = "http-instances.sqlite3"

let save (c : channel) =
    let state = save_channel c in
    let key   = serialize<cbytes> state.c_channelid in
    let value = serialize<cstate> state in

    let doit (db : DB.db) =
        ignore (DB.remove db key);
        DB.put db key value
    in

    let db = DB.opendb dbname in
    try
        DB.tx db doit
    finally
        DB.closedb db

let restore (id : channelid) =
    let key   = serialize<cbytes> (cbytes id) in

    let doit (db : DB.db) =
        DB.get db key
            |> Option.map deserialize<cstate>
            |> Option.map MiHTTPChannel.restore_channel
    in

    let db = DB.opendb dbname in
    try
        DB.tx db doit
    finally
        DB.closedb db
