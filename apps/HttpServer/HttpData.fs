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

module HttpData

open System
open System.IO
open System.Net
open System.Text

open HttpHeaders

type http_version =
| HTTPV_10
| HTTPV_11
| HTTPV_Other of string

let httpversion_of_string = function
| "1.0"   -> HTTPV_10
| "1.1"   -> HTTPV_11
| version -> HTTPV_Other version

let string_of_httpversion = function
| HTTPV_10      -> "1.0"
| HTTPV_11      -> "1.1"
| HTTPV_Other v -> v

type HttpServerConfig = {
    docroot    : string;
    mimesmap   : Mime.MimeMap;
    localaddr  : IPEndPoint;
    tlsoptions : TLSInfo.config option;
    servname   : string;
}

type HttpBody =
| HB_Raw    of byte[]
| HB_Stream of Stream * int64

let http_body_length = function
| HB_Raw    bytes       -> int64 bytes.Length
| HB_Stream (_, length) -> length

type HttpResponse = {
    code    : HttpCode.httpcode;
    headers : HttpHeaders      ;
    body    : HttpBody         ;
}

type HttpRequest = {
    version : http_version;
    mthod   : string      ;
    path    : string      ;
    headers : HttpHeaders ;
}

let http_response_of_code = fun code ->
    let message = HB_Raw (Encoding.ASCII.GetBytes (HttpCode.http_message code)) in
    let headers = HttpHeaders.OfList [("Content-Type", "text/plain;charset=US-ASCII")] in
        { code    = code    ;
          headers = headers ;
          body    = message }
