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

(* ------------------------------------------------------------------------ *)
open System

(* ------------------------------------------------------------------------ *)
[<EntryPoint>]
let main args =
    if Array.length args >= 1 then
        let hostname = args.[0] in
        let requests = List.tail (List.ofArray args) in

        let channel = MiHTTPChannel.connect hostname in
        requests
            |> List.iter (fun request -> MiHTTPChannel.request channel None request)
        let rec wait () =
            match MiHTTPChannel.poll channel with
            | None -> Async.RunSynchronously (Async.Sleep 500)
            | Some (_, (_, d)) -> fprintfn stderr "%s\n" (Bytes.iutf8 (Bytes.abytes d))
            wait ()
        in
            wait (); 0
    else
        1
