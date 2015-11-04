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

module ECGroup

open Bytes
open CoreKeys

open TLSConstants

/// payload of the ec_curve extension
type ec_all_curve =
| EC_CORE of ec_curve
| EC_UNKNOWN of int
| EC_EXPLICIT_PRIME
| EC_EXPLICIT_BINARY

/// payload of the ec_point_format extension
type point_format =
| ECP_UNCOMPRESSED
| ECP_UNKNOWN of int

type point = ecpoint

val getParams : ec_curve -> ecdhparams
val parse_curve : bytes -> ecdhparams option
val curve_id : ecdhparams -> bytes
val curve_name : ecdhparams -> ec_curve
val serialize_point : ecdhparams -> point -> bytes
val parse_point : ecdhparams -> bytes -> point option
val checkElement: ecdhparams -> point -> point option
