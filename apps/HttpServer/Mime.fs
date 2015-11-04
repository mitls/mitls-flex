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

module Mime

open System
open System.IO
open System.Text
open System.Text.RegularExpressions

type mime = string

type MimeMap () =
    let mutable mimes : Map<string, string> = Map.empty

    static member CanonizeExt (ext : string) =
        let ext = ext.ToLowerInvariant() in
            if ext.StartsWith(".") then ext else "." + ext

    member self.Bind (ext : string) (mime : mime) =
        let ext = MimeMap.CanonizeExt(ext) in
            if ext = "." then begin
                raise (ArgumentException ("cannot bind empty extension"))
            end;
            mimes <- Map.add ext mime mimes

    member self.Lookup (ext : string) =
        mimes.TryFind (MimeMap.CanonizeExt ext)

let of_stream (stream : Stream) =
    let process_line = fun line ->
        match Regex.Replace(line, "#.*$", "").Trim() with
        | "" -> None
        | _  ->
            match List.ofArray (Regex.Split(line, "\s+")) with
            | [] -> failwith "MimeMap.of_stream"
            | ctype :: exts -> Some (ctype, exts)
    in
        use reader = new StreamReader(stream, Encoding.ASCII)
        let mime = MimeMap () in

        let _ =
            for line in Utils.IO.ReadAllLines reader do
                match process_line line with
                | Some (ctype, exts) ->
                    exts |> List.iter (fun ext -> mime.Bind ext ctype)
                | None -> ()
        in
            mime

let of_file (filename : string) =
    use stream = File.Open(filename, FileMode.Open, FileAccess.Read)
    of_stream stream
