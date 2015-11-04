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

module DHGroup

open Bytes
open Error
open TLSError
#if ideal

let defaultDHPrimeConfidence = 80
let load_default_params (pem_file:string) (dhdb:DHDB.dhdb) (_: int * int) : DHDB.dhdb * CoreKeys.dhparams =
  failwith "specification only"

#else
open DHDBManager
#endif

type elt = bytes

#if ideal
type preds = | Elt of bytes * bytes * elt
type predPP = | PP of bytes * bytes

let goodPP_log = ref([]: list<CoreKeys.dhparams>)
#if verify
let goodPP (dhp:CoreKeys.dhparams) : bool = failwith "only used in ideal implementation, unverified"
#else
let goodPP dhp =  List.memr !goodPP_log dhp
#endif

let pp (dhp:CoreKeys.dhparams) : CoreKeys.dhparams =
#if verify
    Pi.assume(PP(dhp.dhp,dhp.dhg));
#else
    goodPP_log := (dhp ::!goodPP_log);
#endif
    dhp
#endif

let genElement dhp: elt =
    let (_, e) = CoreDH.gen_key dhp in
#if verify
    Pi.assume (Elt(dhp.dhp,dhp.dhg,e));
#endif
    e

let checkParams dhdb minSize p g =
    match CoreDH.check_params dhdb defaultDHPrimeConfidence minSize p g with
    | Error(x) -> Error(AD_insufficient_security,x)
    | Correct(res) ->
        let (dhdb,dhp) = res in
#if ideal
        let dhp = pp(dhp) in
        let rp = dhp.dhp in
        let rg = dhp.dhg in
        if rp <> p || rg <> g then
            failwith "Trusted code returned inconsitent value"
        else
#endif
        correct (dhdb,dhp)

let checkElement dhp (b:bytes): option<elt> =
    if CoreDH.check_element dhp b then
        (
#if verify
        Pi.assume(Elt(dhp.dhp,dhp.dhg,b));
#endif
        Some(b))
    else
        None

let defaultDHparams file dhdb minSize =
    let (dhdb,dhp) = load_default_params file dhdb minSize in
#if ideal
    let dhp = pp(dhp) in
#endif
    (dhdb,dhp)
