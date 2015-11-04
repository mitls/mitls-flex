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

module List

open Bytes

let fold (op: bytes-> bytes-> bytes) state data = List.fold op state data
let filter f l = List.filter f l
let foldBack (f:bytes -> bytes -> bytes) bl s = List.foldBack f bl s
let exists f l = List.exists f l
let memr l x = List.exists (fun y -> x = y) l
let choose f l = List.choose f l
let tryFind f l = List.tryFind f l
let listLength (l:'a list) = l.Length
let listHead (l:'a list) = l.Head
let find f l = List.find f l
let map f l = List.map f l
