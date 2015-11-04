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

val parse : ckenv -> bytes -> cookie list
