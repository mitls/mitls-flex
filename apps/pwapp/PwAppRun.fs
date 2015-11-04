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

module PwAppRun

open System
open System.Threading

let servname = "mitls.example.org"
let my       = "xxxxxxxxxxxxxxxx"
let token    = PwToken.create ()
let _        = PwToken.register my token

let server () =
    try
        printfn "S: %A" (PwApp.response servname)
    with e ->
        printfn "E: %A" e

let client () =
    let r = (PwApp.request servname my token) in
        printfn "C: %A" r

let program () =
    let tserver = new Thread(new ThreadStart(server))

    tserver.Name <- "Server"; tserver.Start ()
    Thread.Sleep 1000; client ();
    Thread.Sleep -1

let _ =
    program ()
