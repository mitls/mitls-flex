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

module DH

open Bytes
open CommonDH

#if ideal
// Local predicate definitions
type predHE = HonestExponential of bytes * bytes * elt
#endif

#if ideal
// log of honestly generated elements
type honest_entry = (dhparams * elt)
let honest_log = ref([]: list<honest_entry>)
#if verify
let honest dhp gx = failwith "only used in ideal implementation, unverified"
#else
let honest dhp gx = List.exists (fun el-> el = (dhp,gx)) !honest_log
#endif

let safeDH (dhp:dhparams) (gx:elt) (gy:elt): bool =
    honest dhp gx && honest dhp gy && goodPP dhp
#endif

#if ideal
// log for looking up good pms values using their id
type entry = dhparams * elt * elt * PMS.dhpms
let log: list<entry> ref = ref []
let rec assoc (dhp:dhparams) (gx:elt) (gy:elt) entries: option<PMS.dhpms> =
    match entries with
    | []                      -> None
    | (dhp',gx',gy', pms)::entries when dhp=dhp' && gx=gx' && gy=gy' -> Some(pms)
    | _::entries              -> assoc dhp gx gy entries
#endif

let genKey (dhp : parameters) : element * secret =
    match dhp with
    | DHP_P(dhp) ->
        let (x,e) = CoreDH.gen_key dhp in
        #if ideal
        #if verify
        Pi.assume(Elt(dhp.dhp,dhp.dhg,e));
        Pi.assume(HonestExponential(dhp.dhp,dhp.dhg,e));
        #else
        honest_log := (dhp,e)::!honest_log;
        #endif
        #endif
        ({dhe_nil with dhe_p = Some e}, Key (x))
    | DHP_EC(ecdhp) ->
        let (x,e) = CoreECDH.gen_key ecdhp in
        ({dhe_nil with dhe_ec = Some e}, Key(x))

let serverGenDH filename dhdb minSize =
    let (dhdb,dhp) = DHGroup.defaultDHparams filename dhdb minSize in
    let (e,s) = genKey (DHP_P(dhp)) in
    (Some dhdb, DHP_P dhp, e, s)

let serverGenECDH curve =
    let dhp = DHP_EC(ECGroup.getParams curve) in
    let (e,s) = genKey dhp in
    ((None : DHDB.dhdb option), dhp, e, s)

let clientGenExp (dhp : parameters) (gs : element) =
    let (gc,c) = genKey dhp in
    let (Key ck) = c in
    match dhp with
    | DHP_P(dhp) ->
        let p = dhp.dhp in
        let pms = CoreDH.agreement p ck (get_p gs) in
        //#begin-ideal
        #if ideal
        if safeDH dhp gs gc then
          match assoc dhp gs gc !log with
          | Some(pms) -> (gc,pms)
          | None ->
                     let pms=PMS.sampleDH dhp gs gc in
                     log := (dhp,gs,gc,pms)::!log;
                     (gc,pms)
        else
          (Pi.assume(DHGroup.Elt(dhp.dhp,dhp.dhg,pms));
          let dpms = PMS.coerceDH dhp gs gc pms in
          (gc,dpms))
        //#end-ideal
        #else
        let dpms = PMS.coerceDH dhp (get_p gs) (get_p gc) pms in
        (gc,dpms)
        #endif
    | DHP_EC(ecp) ->
        let pms = CoreECDH.agreement ecp ck (get_ec gs) in
        let dpms = PMS.coerceECDH ecp (get_ec gs) (get_ec gc) pms in
        (gc, dpms)

let serverExp (dhp : parameters) (gs : element) (gc : element) (sk : secret) =
    let (Key s) = sk in
    match dhp with
    | DHP_P(dhp) ->
        let p = dhp.dhp in
        let pms = CoreDH.agreement p s (get_p gc) in
        //#begin-ideal
        #if ideal
        if safeDH dhp gs gc then
          match assoc dhp gs gc !log with
          | Some(pms) -> pms
          | None ->
                     let pms=PMS.sampleDH dhp gs gc in
                     log := (dhp,gs,gc,pms)::!log;
                     pms
        else
          (Pi.assume(DHGroup.Elt(dhp.dhp,dhp.dhg,pms));
          let dpms = PMS.coerceDH dhp gs gc pms in
          dpms)
        //#end-ideal
        #else
        let dpms = PMS.coerceDH dhp (get_p gs) (get_p gc) pms in
        dpms
        #endif
    | DHP_EC(ecp) ->
        let pms = CoreECDH.agreement ecp s (get_ec gc) in
        let dpms = PMS.coerceECDH ecp (get_ec gs) (get_ec gc) pms in
        dpms

let serialize (e:element) : bytes =
    match e with
    | {dhe_p = Some x; dhe_ec = None; } -> TLSConstants.vlbytes 2 x
    | {dhe_p = None; dhe_ec = Some p; } -> TLSConstants.vlbytes 1 (CoreECDH.serialize p)
    | _ -> failwith "(impossible)"
