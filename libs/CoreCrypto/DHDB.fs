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

module DHDB

open Bytes

open Serialization

type Key   = bytes * bytes
type Value = bytes * bool

type dhdb = {
    filename: string;
}

let defaultFileName = "dhparams-db.bin"

(* ------------------------------------------------------------------------------- *)
let create (filename:string) =
    let self = {
        filename = filename;
    }
    DB.closedb (DB.opendb self.filename)
    self

(* ------------------------------------------------------------------------------- *)
let remove self key =
    let key = serialize<Key> key in

    let db  = DB.opendb self.filename in

    try
        DB.tx db (fun db -> ignore (DB.remove db key));
        self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let select self key =
    let key = serialize<Key> key in

    let select (db : DB.db) =
        DB.get db key
            |> Option.map deserialize<Value>

    let db = DB.opendb self.filename in

    try
        DB.tx db select
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let insert self key v =
    let key = serialize<Key> key in
    let v   = serialize<Value> v in

    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key v in

    let db = DB.opendb self.filename in

    try
        DB.tx db insert; self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let keys self =
    let aout =
        let db = DB.opendb self.filename in

        try
            DB.tx db (fun db -> DB.keys db)
        finally
            DB.closedb db
    in
        List.map deserialize<Key> aout

(* ------------------------------------------------------------------------------- *)
let merge self db1 =
    let db = DB.opendb self.filename in

    try
        DB.tx db (fun db -> DB.merge db db1); self
    finally
        DB.closedb db
