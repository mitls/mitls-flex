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

module SmackTLS
open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets
open TLSConstants
open Bytes
open Error
open TLSInfo
open FlexAlert
open FlexServerKeyExchange

#nowarn "25"
open NLog
open System.Threading

let log = LogManager.GetLogger("file");

let mutable spv = Some TLS_1p0

exception UnsupportedScenario of System.Exception

(*no of configs = 280
no of web configs = 12
no of traces = 280
no of web traces = 12
no of duplicate traces = 10
no of duplicate web traces = 0
no of unique traces = 25
no of unique web traces = 7
no of deviant web traces = 17
no of unique deviant web traces = 9
no of skipped web traces = 67
no of repeated web traces = 221
no of all web traces = 298
no of client_cert web traces = 114
no of client_nocert web traces = 39
no of server web traces = 145
*)
let cfuns = ref [];

let tr1 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (1,tr1)::!cfuns;

let tr3 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (3,tr3)::!cfuns;

let tr4 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (4,tr4)::!cfuns;

let tr5 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (5,tr5)::!cfuns;

let tr6 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (6,tr6)::!cfuns;

let tr7 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (7,tr7)::!cfuns;

let tr8 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (8,tr8)::!cfuns;

let tr9 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (9,tr9)::!cfuns;

let tr10 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (10,tr10)::!cfuns;

let tr11 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (11,tr11)::!cfuns;

let tr12 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (12,tr12)::!cfuns;

let tr13 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (13,tr13)::!cfuns;

let tr14 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (14,tr14)::!cfuns;

let tr15 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (15,tr15)::!cfuns;

let tr16 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (16,tr16)::!cfuns;

let tr30 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (30,tr30)::!cfuns;

let tr31 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (31,tr31)::!cfuns;

let tr32 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (32,tr32)::!cfuns;

let tr33 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (33,tr33)::!cfuns;

let tr34 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (34,tr34)::!cfuns;

let tr35 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (35,tr35)::!cfuns;

let tr36 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (36,tr36)::!cfuns;

let tr37 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (37,tr37)::!cfuns;

let tr38 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (38,tr38)::!cfuns;

let tr39 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (39,tr39)::!cfuns;

let tr40 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (40,tr40)::!cfuns;

let tr41 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (41,tr41)::!cfuns;

let tr42 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (42,tr42)::!cfuns;

let tr43 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (43,tr43)::!cfuns;

let tr44 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (44,tr44)::!cfuns;

let tr45 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (45,tr45)::!cfuns;

let tr46 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (46,tr46)::!cfuns;

let tr47 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (47,tr47)::!cfuns;

let tr48 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (48,tr48)::!cfuns;

let tr49 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (49,tr49)::!cfuns;

let tr50 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (50,tr50)::!cfuns;

let tr51 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (51,tr51)::!cfuns;

let tr52 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (52,tr52)::!cfuns;

let tr53 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (53,tr53)::!cfuns;

let tr54 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (54,tr54)::!cfuns;

let tr55 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (55,tr55)::!cfuns;

let tr56 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (56,tr56)::!cfuns;

let tr57 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (57,tr57)::!cfuns;

let tr58 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (58,tr58)::!cfuns;

let tr59 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (59,tr59)::!cfuns;

let tr60 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (60,tr60)::!cfuns;

let tr61 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (61,tr61)::!cfuns;

let tr62 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (62,tr62)::!cfuns;

let tr63 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (63,tr63)::!cfuns;

let tr64 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (64,tr64)::!cfuns;

let tr65 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (65,tr65)::!cfuns;

let tr66 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (66,tr66)::!cfuns;

let tr91 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (91,tr91)::!cfuns;

let tr92 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (92,tr92)::!cfuns;

let tr93 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (93,tr93)::!cfuns;

let tr94 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (94,tr94)::!cfuns;

let tr95 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (95,tr95)::!cfuns;

let tr96 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (96,tr96)::!cfuns;

let tr97 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (97,tr97)::!cfuns;

let tr98 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (98,tr98)::!cfuns;

let tr99 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (99,tr99)::!cfuns;

let tr100 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (100,tr100)::!cfuns;

let tr101 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (101,tr101)::!cfuns;

let tr102 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (102,tr102)::!cfuns;

let tr103 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (103,tr103)::!cfuns;

let tr104 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,chain,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,fcver   = FlexCertificateVerify.send(st,nsc.si,salg,skey,ms=nsc.secrets.ms) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (104,tr104)::!cfuns;

let tr105 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (105,tr105)::!cfuns;

let tr106 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (106,tr106)::!cfuns;

let tr107 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (107,tr107)::!cfuns;

let tr108 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (108,tr108)::!cfuns;

let tr109 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (109,tr109)::!cfuns;

let tr110 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (110,tr110)::!cfuns;

let tr111 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (111,tr111)::!cfuns;

let tr112 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (112,tr112)::!cfuns;

let tr113 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (113,tr113)::!cfuns;

let tr114 st (Some(chain, salg, skey)) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcertC   = FlexCertificate.send(st,Client,[],nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (114,tr114)::!cfuns;

let cert_funs = !cfuns

cfuns := [];

let tr118 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (118,tr118)::!cfuns;

let tr119 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (119,tr119)::!cfuns;

let tr120 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (120,tr120)::!cfuns;

let tr124 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (124,tr124)::!cfuns;

let tr125 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (125,tr125)::!cfuns;

let tr126 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Client st.hs_log in
  let st,ffC = FlexFinished.send(st,verify_data) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (126,tr126)::!cfuns;

let tr136 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (136,tr136)::!cfuns;

let tr137 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (137,tr137)::!cfuns;

let tr138 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (138,tr138)::!cfuns;

let tr139 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (139,tr139)::!cfuns;

let tr140 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (140,tr140)::!cfuns;

let tr141 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendDHE(st,nsc) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (141,tr141)::!cfuns;

let tr148 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (148,tr148)::!cfuns;

let tr149 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (149,tr149)::!cfuns;

let tr150 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (150,tr150)::!cfuns;

let tr151 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (151,tr151)::!cfuns;

let tr152 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (152,tr152)::!cfuns;

let tr153 st (None) =
  let fch = {FlexConstants.nullFClientHello with pv = spv; ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in
  let st,nsc,fch   = FlexClientHello.send(st,fch) in
  let st,nsc,fsh   =
   (try
      FlexServerHello.receive(st,fch,nsc=nsc,checkVD=false)
    with
    | e -> raise (UnsupportedScenario(e))) in
  let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
  let st,fshd      = FlexServerHelloDone.receive(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

cfuns := (153,tr153)::!cfuns;

let nocert_funs = !cfuns

let sfuns = ref [];

let tr154 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let verify_data2  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Server st.hs_log in
  let st,ffS  = FlexFinished.send(st,verify_data2) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (154,tr154)::!sfuns;

let tr156 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let verify_data2  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Server st.hs_log in
  let st,ffS  = FlexFinished.send(st,verify_data2) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (156,tr156)::!sfuns;

let tr157 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (157,tr157)::!sfuns;

let tr158 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (158,tr158)::!sfuns;

let tr159 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (159,tr159)::!sfuns;

let tr160 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (160,tr160)::!sfuns;

let tr161 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (161,tr161)::!sfuns;

let tr162 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (162,tr162)::!sfuns;

let tr163 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (163,tr163)::!sfuns;

let tr164 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (164,tr164)::!sfuns;

let tr165 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (165,tr165)::!sfuns;

let tr166 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (166,tr166)::!sfuns;

let tr167 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (167,tr167)::!sfuns;

let tr179 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (179,tr179)::!sfuns;

let tr180 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (180,tr180)::!sfuns;

let tr181 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (181,tr181)::!sfuns;

let tr182 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (182,tr182)::!sfuns;

let tr183 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (183,tr183)::!sfuns;

let tr184 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (184,tr184)::!sfuns;

let tr185 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (185,tr185)::!sfuns;

let tr186 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (186,tr186)::!sfuns;

let tr187 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,fcver   = FlexCertificateVerify.receive(st,nsc,[salg],check_log=true) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (187,tr187)::!sfuns;

let server_cert_funs = !sfuns

sfuns := [];

let tr191 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (191,tr191)::!sfuns;

let tr193 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (193,tr193)::!sfuns;

let tr194 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (194,tr194)::!sfuns;

let tr198 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let verify_data2  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Server st.hs_log in
  let st,ffS  = FlexFinished.send(st,verify_data2) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (198,tr198)::!sfuns;

let tr199 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (199,tr199)::!sfuns;

let tr200 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (200,tr200)::!sfuns;

let tr201 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let verify_data2  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Server st.hs_log in
  let st,ffS  = FlexFinished.send(st,verify_data2) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (201,tr201)::!sfuns;

let tr206 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let verify_data2  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Server st.hs_log in
  let st,ffS  = FlexFinished.send(st,verify_data2) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (206,tr206)::!sfuns;

let tr207 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let verify_data2  = FlexSecrets.makeVerifyData nsc.si nsc.secrets.ms Server st.hs_log in
  let st,ffS  = FlexFinished.send(st,verify_data2) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (207,tr207)::!sfuns;

let tr217 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (217,tr217)::!sfuns;

let tr218 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (218,tr218)::!sfuns;

let tr219 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (219,tr219)::!sfuns;

let tr220 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (220,tr220)::!sfuns;

let tr221 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (221,tr221)::!sfuns;

let tr222 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (222,tr222)::!sfuns;

let tr223 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (223,tr223)::!sfuns;

let tr224 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (224,tr224)::!sfuns;

let tr225 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (225,tr225)::!sfuns;

let tr226 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (226,tr226)::!sfuns;

let tr227 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (227,tr227)::!sfuns;

let tr228 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (228,tr228)::!sfuns;

let tr229 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (229,tr229)::!sfuns;

let tr230 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (230,tr230)::!sfuns;

let tr231 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (231,tr231)::!sfuns;

let tr232 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (232,tr232)::!sfuns;

let tr233 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (233,tr233)::!sfuns;

let tr234 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (234,tr234)::!sfuns;

let tr235 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (235,tr235)::!sfuns;

let tr236 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (236,tr236)::!sfuns;

let tr237 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (237,tr237)::!sfuns;

let tr238 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (238,tr238)::!sfuns;

let tr239 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (239,tr239)::!sfuns;

let tr240 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (240,tr240)::!sfuns;

let tr241 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (241,tr241)::!sfuns;

let tr242 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (242,tr242)::!sfuns;

let tr243 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (243,tr243)::!sfuns;

let tr244 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (244,tr244)::!sfuns;

let tr245 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (245,tr245)::!sfuns;

let tr246 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc,(salg,skey)) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveDHE(st,nsc) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (246,tr246)::!sfuns;

let tr277 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (277,tr277)::!sfuns;

let tr278 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (278,tr278)::!sfuns;

let tr279 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (279,tr279)::!sfuns;

let tr280 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (280,tr280)::!sfuns;

let tr281 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (281,tr281)::!sfuns;

let tr282 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (282,tr282)::!sfuns;

let tr283 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (283,tr283)::!sfuns;

let tr284 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (284,tr284)::!sfuns;

let tr285 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (285,tr285)::!sfuns;

let tr286 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (286,tr286)::!sfuns;

let tr287 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (287,tr287)::!sfuns;

let tr288 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (288,tr288)::!sfuns;

let tr289 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (289,tr289)::!sfuns;

let tr290 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (290,tr290)::!sfuns;

let tr291 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (291,tr291)::!sfuns;

let tr292 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (292,tr292)::!sfuns;

let tr293 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (293,tr293)::!sfuns;

let tr294 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (294,tr294)::!sfuns;

let tr295 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (295,tr295)::!sfuns;

let tr296 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (296,tr296)::!sfuns;

let tr297 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (297,tr297)::!sfuns;

let tr298 st chain salg skey rsakey =
  let st,nsc,fch = FlexClientHello.receive(st,checkVD=false) in
  let fsh = {FlexConstants.nullFServerHello with pv = spv; ciphersuite = Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
  let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,fsh=fsh) in
  let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
  let st,fcreq = FlexCertificateRequest.send(st,nsc) in
  let st,fshd      = FlexServerHelloDone.send(st) in
  let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
  let st,nsc,fcke   = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=rsakey) in
  let st,_,_ = FlexCCS.receive(st) in
  let st = FlexState.installReadKeys st nsc in
  let st,ffC = FlexFinished.receive(st,nsc,Client) in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let st,_  = FlexCCS.send(st) in
  let st = FlexState.installWriteKeys st nsc in
  let _ = FlexAlert.receive(st) in
  ()

sfuns := (298,tr298)::!sfuns;

let server_nocert_funs = !sfuns

let mutable focus : int option = None

let runClients (server_name:string) (port:int) (certs:option<string>) (delay:int) =
  let funs,args =
    match certs with
    | None -> nocert_funs,None
    | Some(hint) ->
      match Cert.for_signing FlexConstants.sigAlgs_ALL hint [(SA_RSA,MD5SHA1)] with
      | None -> failwith "Failed to retrieve certificate data"
      | Some(c,a,s) -> cert_funs,Some(c,a,s)
  in
  List.iter (fun (n,f) ->
     if focus = Some n || focus = None then
       log.Info(sprintf "BEGIN deviant trace %d" n);
        Thread.Sleep(delay);
       let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port,timeout=2000) in
       try
         f st args;
         log.Info(sprintf "END SUCCESS deviant trace %d" n);
         Tcp.close st.ns
       with
         | UnsupportedScenario(e) ->
           (log.Info ("unsupported: "^(e.Message));
           log.Info(sprintf "END UNSUPPORTED deviant trace %d" n);
           Tcp.close st.ns)
         | e ->
           (log.Info ("exception: "^(e.Message));
           log.Info(sprintf "END FAILURE deviant trace %d" n);
           Tcp.close st.ns)) funs

let runServers port hint certs =
  let funs = if certs then server_cert_funs else server_nocert_funs in
  let l = Tcp.listen "0.0.0.0" port in
  let chain,salg,skey,rsakey =
    let chain,salg,skey =
      match Cert.for_signing FlexConstants.sigAlgs_ALL hint [(SA_RSA,MD5SHA1)] with
      | None -> failwith "Failed to retrieve certificate data"
      | Some(c,a,s) -> c,a,s
    let chain',rsakey =
      match Cert.for_key_encryption FlexConstants.sigAlgs_ALL hint with
      | None -> failwith "Failed to retrieve certificate data"
      | Some(c,s) -> c,s
    if chain = chain' then
      chain,salg,skey,rsakey
    else
      failwith "Internal error"
  List.iter (fun (n,f) ->
    if focus = Some n || focus = None then

      log.Info(sprintf "BEGIN deviant trace %d" n);
      let st,_ = FlexConnection.serverOpenTcpConnection(l,hint,timeout=2000) in
      try
        f st chain salg skey rsakey;
        log.Info(sprintf "END SUCCESS deviant trace %d" n);
        Tcp.close st.ns
      with
        | UnsupportedScenario(e) ->
          (log.Info ("unsupported: "^(e.Message));
          log.Info(sprintf "END UNSUPPORTED deviant trace %d" n);
          Tcp.close st.ns)
        | e ->
          (log.Info ("exception: "^(e.Message));
          log.Info(sprintf "END FAILURE deviant trace %d" n);
          Tcp.close st.ns)) funs
