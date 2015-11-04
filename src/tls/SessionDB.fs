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

module SessionDB

open Bytes
open TLSInfo
open Date

(* ------------------------------------------------------------------------------- *)
type StorableSession = SessionInfo * PRF.masterSecret * epoch
type SessionIndex = sessionID * Role * Cert.hint

#if ideal
type entry = sessionID * Role * Cert.hint * StorableSession
type t = list<entry>

let create (c:config) : t = []

let insert (db:t) sid r h sims : t = (sid,r,h,sims)::db

let rec select (db:t) sid r h =
  match db with
  | (sid',r',h',sims)::db when sid=sid' && r=r' && h=h'  -> Some(sims)
  | _::db                                                -> select db sid r h
  | []                                                   -> None

let rec remove (db:t) sid r h =
  match db with
  | (sid',r',h',sims)::db when sid=sid' && r=r' && h=h' -> remove db sid r h
  | e::db                                               -> e::remove db sid r h
  | []                                                  -> []

let rec getAllStoredIDs (db:t) =
  match db with
  | (sid,r,h,sims)::db -> (sid,r,h)::getAllStoredIDs db
  | []                 -> []
#else

open Serialization

type t = {
    filename: string;
    expiry: TimeSpan;
}

(* ------------------------------------------------------------------------------- *)
module Option =
    begin
    let filter (f : 'a -> bool) (x : option<'a>) =
        match x with
        | None -> None
        | Some x when f x -> Some x
        | Some x -> None
    end

(* ------------------------------------------------------------------------------- *)
let create poptions =
    let self = {
        filename = poptions.sessionDBFileName;
          expiry = poptions.sessionDBExpiry;
    } in

    DB.closedb (DB.opendb self.filename);
    self

(* ------------------------------------------------------------------------------- *)
let remove self sid role hint =
    let key = serialize<SessionIndex> (sid,role,hint) in
    let db  = DB.opendb self.filename in

    try
        DB.tx db (fun db -> ignore (DB.remove db key));
        self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let select self sid role hint =
    let key = serialize<SessionIndex> (sid,role,hint) in

    let select (db : DB.db) =
        let filter_record ((sinfo, ts) : StorableSession * DateTime) =
            let expires = addTimeSpan ts self.expiry in

            if greaterDateTime expires (now()) then
                Some sinfo
            else
                (ignore (DB.remove db key);
                None)
        in

        DB.get db key
            |> Option.map deserialize<StorableSession*DateTime>
            |> Option.bind filter_record
    in

    let db = DB.opendb self.filename in

    try
        DB.tx db select
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let insert self sid role hint value =
    let key = serialize<SessionIndex> (sid,role,hint) in
    let insert (db : DB.db) =
        match DB.get db key with
        | Some _ -> ()
        | None   -> DB.put db key (serialize<StorableSession*DateTime> (value, now ())) in
    let db = DB.opendb self.filename in
    try
        DB.tx db insert; self
    finally
        DB.closedb db

(* ------------------------------------------------------------------------------- *)
let getAllStoredIDs self =
    let aout =
        let db = DB.opendb self.filename in

        try
            DB.tx db (fun db -> DB.keys db)
        finally
            DB.closedb db
    in
        List.map deserialize<SessionIndex> aout

#endif
