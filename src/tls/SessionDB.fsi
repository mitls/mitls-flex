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

open TLSInfo
open Date

type StorableSession = SessionInfo * PRF.masterSecret * epoch
type SessionIndex = sessionID * Role * Cert.hint

#if ideal
type entry = sessionID * Role * Cert.hint * StorableSession
type t = list<entry>
#else
type t
#endif

val create: config -> t
val select: t -> sessionID -> Role -> Cert.hint -> option<StorableSession>
val insert: t -> sessionID -> Role -> Cert.hint -> StorableSession -> t
val remove: t -> sessionID -> Role -> Cert.hint -> t

val getAllStoredIDs: t -> list<SessionIndex>
