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

module MiHTTPCookie

open Bytes

type cookie = {
  name   : string;
  value  : string;
  domain : string;
  path   : string;
  maxage : int;
  secure : bool;
}

type ckenv = {
    path   : string;
    domain : string;
}

exception InvalidCookie

let as_key_value (s : string) =
    match MiHTTPUtils.split_and_strip '=' 2 s with
    | [k] -> (k, None)
    | [k; v] -> (k, Some v)
    | _ -> raise InvalidCookie

let validate_domain (ckenv : ckenv) (domain : string) =
    if domain <> ckenv.domain then
        raise InvalidCookie

let validate_path (ckenv : ckenv) (path : string) =
    if path <> ckenv.path then
        raise InvalidCookie

let parse_option1 ckenv cookie ((k, v) : string * string option) =
    match k.ToLower (), v with
    | "max-age", Some v ->
        match (try Some (int v) with _ -> None) with
        | None -> raise InvalidCookie
        | Some i when i < 0 -> raise InvalidCookie
        | Some i -> { cookie with maxage = i; }
    | "domain", Some v ->
        validate_domain ckenv v
        { cookie with domain = v; }
    | "path", Some v ->
        validate_path ckenv v
        { cookie with path = v; }
    | "secure", None ->
        { cookie with secure = true; }
    | _ -> raise InvalidCookie

let rec parse_options ckenv cookie seen os =
    match os with
    | [] -> cookie
    | (k, v) :: os ->
        if List.exists (fun x -> x = k) seen then
            raise InvalidCookie
        let options = parse_option1 ckenv cookie (k, v) in
            parse_options ckenv cookie (k::seen) os

let parse_1_exn ckenv v : cookie =
    let v = v |> (MiHTTPUtils.split_and_strip ';' 0) in
    let v = v |> List.map as_key_value in

    match v with
    | (k, Some v) :: tl ->
        let cookie = {
            name = k; value = v; domain = ckenv.domain;
            path = ckenv.path; maxage = -1; secure = false; } in
        parse_options ckenv cookie [] tl
    | _ -> raise InvalidCookie

let parse ckenv v : cookie list =
    let v = v |> iutf8 |> (MiHTTPUtils.split_and_strip ',' 0) in
    let v = List.map (parse_1_exn ckenv) v in
        v
