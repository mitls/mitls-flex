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

module CoreECDH

open Bytes
open CoreKeys

val gen_key : ecdhparams -> ecdhskey * ecdhpkey
val agreement : ecdhparams -> ecdhskey -> ecdhpkey -> bytes
val serialize : ecdhpkey -> bytes
val is_on_curve : ecdhparams -> ecpoint -> bool
