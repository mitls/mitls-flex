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

module TLSFragment

open Error
open TLSError
open Bytes
open TLSInfo
open TLSConstants
open Range

type fragment =
    | FHandshake of HSFragment.fragment //Cf Handshake.fragment
    | FCCS of HSFragment.fragment
    | FAlert of HSFragment.fragment
    | FAppData of AppFragment.fragment
type plain = fragment

type history = {
  handshake: HSFragment.stream;
  ccs:       HSFragment.stream;
  alert:     HSFragment.stream;
  appdata:   DataStream.stream
}

let emptyHistory e =
    let i = mk_id e in
    let es = HSFragment.init i in
    let ehApp = DataStream.init e in
    { handshake = es;
      ccs = es;
      alert = es;
      appdata = ehApp}

let handshakeHistory (e:epoch) h = h.handshake
let ccsHistory (e:epoch) h = h.ccs
let alertHistory (e:epoch) h = h.alert

let fragment i ct rg b =
    match ct with
    | Handshake          -> FHandshake(HSFragment.fragmentPlain i rg b)
    | Change_cipher_spec -> FCCS(HSFragment.fragmentPlain i rg b)
    | Alert              -> FAlert(HSFragment.fragmentPlain i rg b)
    | Application_data   -> FAppData(AppFragment.plain i rg b)

let plain e (ct:ContentType) (h:history) (rg:range) b =
      let i = mk_id e in
        fragment i ct rg b

let reprFragment i (ct:ContentType) (rg:range) frag =
    match frag with
    | FHandshake(f) -> HSFragment.fragmentRepr i rg f
    | FCCS(f)       -> HSFragment.fragmentRepr i rg f
    | FAlert(f)     -> HSFragment.fragmentRepr i rg f
    | FAppData(f)   -> AppFragment.repr i rg f

let repr e ct (h:history) rg frag =
  let i = mk_id e in
  reprFragment i ct rg frag

let HSPlainToRecordPlain    (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FHandshake(f)
let CCSPlainToRecordPlain   (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FCCS(f)
let AlertPlainToRecordPlain (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FAlert(f)
let AppPlainToRecordPlain   (e:epoch) (h:history) (r:range) (f:AppFragment.plain)= FAppData(f)

let RecordPlainToHSPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FHandshake(f) -> f
    | FCCS(_)
    | FAlert(_)
    | FAppData(_)   -> unreachable "[RecordPlainToHSPlain] invoked on an invalid fragment"
let RecordPlainToCCSPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FCCS(f)       -> f
    | FHandshake(_)
    | FAlert(_)
    | FAppData(_)   -> unreachable "[RecordPlainToCCSPlain] invoked on an invalid fragment"
let RecordPlainToAlertPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FAlert(f)     -> f
    | FHandshake(_)
    | FCCS(_)
    | FAppData(_)   -> unreachable "[RecordPlainToAlertPlain] invoked on an invalid fragment"
let RecordPlainToAppPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FAppData(f)   -> f
    | FHandshake(_)
    | FCCS(_)
    | FAlert(_)     -> unreachable "[RecordPlainToAppPlain] invoked on an invalid fragment"

let extendHistory (e:epoch) ct ss r frag =
  let i = mk_id e in
  match ct,frag with
    | Handshake,FHandshake(f)      -> let s' = HSFragment.extend i ss.handshake r f in
                                      {ss with handshake = s'}
    | Alert,FAlert(f)              -> let s' = HSFragment.extend i ss.alert r f in
                                      {ss with alert = s'}
    | Change_cipher_spec,FCCS(f)   -> let s' = HSFragment.extend i ss.ccs r f in
                                      {ss  with ccs = s'}
    | Application_data,FAppData(f) -> let d,s' = AppFragment.delta e ss.appdata r f in
                                      {ss with appdata = s'}
    | _,_                          -> unexpected "[extendHistory] invoked on an invalid contenttype/fragment"

let makeExtPad i ct r frag =
    match ct,frag with
    | Handshake,FHandshake(f)      -> let f = HSFragment.makeExtPad  i r f in FHandshake(f)
    | Alert,FAlert(f)              -> let f = HSFragment.makeExtPad  i r f in FAlert(f)
    | Change_cipher_spec,FCCS(f)   -> let f = HSFragment.makeExtPad  i r f in FCCS(f)
    | Application_data,FAppData(f) -> let f = AppFragment.makeExtPad i r f in FAppData(f)
    | _,_                          -> unexpected "[makeExtPad] invoked on an invalid contenttype/fragment"

let parseExtPad i ct r frag : Result<fragment> =
    match ct,frag with
    | Handshake,FHandshake(f) ->
        (match HSFragment.parseExtPad i r f with
        | Error(x) -> Error(x)
        | Correct(f) -> Correct (FHandshake(f)))
    | Alert,FAlert(f) ->
        (match HSFragment.parseExtPad i r f with
        | Error(x) -> Error(x)
        | Correct(f) -> Correct (FAlert(f)))
    | Change_cipher_spec,FCCS(f) ->
        (match HSFragment.parseExtPad i r f with
        | Error(x) -> Error(x)
        | Correct(f) -> Correct (FCCS(f)))
    | Application_data,FAppData(f) ->
        (match AppFragment.parseExtPad i r f with
        | Error(x) -> Error(x)
        | Correct(f) -> Correct (FAppData(f)))
    | _,_ -> unexpected "[parseExtPad] invoked on an invalid contenttype/fragment"

#if ideal
let widen i ct r0 f0 =
    let r1 = rangeClass i r0 in
    match ct,f0 with
    | Handshake,FHandshake(f)      -> let f1 = HSFragment.widen i r0 r1 f in
                                      FHandshake(f1)
    | Alert,FAlert(f)              -> let f1 = HSFragment.widen i r0 r1 f in
                                      FAlert(f1)
    | Change_cipher_spec,FCCS(f)   -> let f1 = HSFragment.widen i r0 r1 f in
                                      FCCS(f1)
    | Application_data,FAppData(f) -> let f1 = AppFragment.widen i r0 f in
                                      FAppData(f1)
    | _,_                          -> unexpected "[widen] invoked on an invalid contenttype/fragment"

#endif
