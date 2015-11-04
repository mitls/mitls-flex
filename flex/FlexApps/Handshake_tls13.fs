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

module FlexApps.Handshake_tls13

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexClientKeyShare
open FlexServerHello
open FlexServerKeyShare
open FlexCertificate
open FlexServerHelloDone
open FlexCertificateVerify
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets

type Handshake_tls13 =
    class

    static member client (address:string, ?cn:string, ?port:int) : state =
        let cn = defaultArg cn address in
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // We need to use the negotiable groups extension for TLS 1.3
        let cfg = {defaultConfig with maxVer = TLS_1p3; negotiableDHGroups = [DHE2432; DHE3072; DHE4096; DHE6144; DHE8192]} in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(address,cn,port,cfg.maxVer) in

        // We want to ensure a ciphersuite
        let fch = {FlexConstants.nullFClientHello with
            pv = Some(cfg.maxVer);
            ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch,cfg) in
        let st,nsc,fcks  = FlexClientKeyShare.send(st,nsc) in

        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fsks  = FlexServerKeyShare.receive(st,nsc) in

        // Peer advertises that it will encrypt the traffic
        let st,_,_       = FlexCCS.receive(st) in
        let st           = FlexState.installReadKeys st nsc in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in

        let st,scertv    = FlexCertificateVerify.receive(st,nsc,FlexConstants.sigAlgs_ALL) in

        let st,ffS       = FlexFinished.receive(st,nsc,Server) in

        // We advertise that we will encrypt the traffic
        let st,_         = FlexCCS.send(st) in
        let st           = FlexState.installWriteKeys st nsc in

        let st,ffC       = FlexFinished.send(st,nsc,Client) in
        st

    static member server (address:string, ?cn:string, ?port:int) : state =
        let cn = defaultArg cn address in
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // We need to use the negotiable groups extension for TLS 1.3
        let cfg = {defaultConfig with maxVer = TLS_1p3; negotiableDHGroups = [DHE2432; DHE3072; DHE4096; DHE6144; DHE8192]} in

        // Resolve cn to a cert and key pair

        match Cert.for_signing FlexConstants.sigAlgs_ALL cn FlexConstants.sigAlgs_RSA with
        | None -> failwith "Failed to retrieve certificate data"
        | Some(chain,sigAlg,skey) ->

        // Start TCP connection listening to a client
        let st,_ = FlexConnection.serverOpenTcpConnection(address,cn,port,cfg.maxVer) in

        let st,nsc,fch   = FlexClientHello.receive(st) in
        if not ( List.exists (fun x -> x = TLS_DHE_RSA_WITH_AES_128_GCM_SHA256) (FlexClientHello.getCiphersuites fch)) then
            failwith (perror __SOURCE_FILE__ __LINE__ "Unsuitable ciphersuite")
        else

        let st,nsc,fcke  = FlexClientKeyShare.receive(st,nsc) in

        let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,cfg=cfg) in
        let st,nsc,fske  = FlexServerKeyShare.send(st,nsc) in

        // We advertise that we will encrypt the traffic
        let st,_         = FlexCCS.send(st) in
        let st           = FlexState.installWriteKeys st nsc in
        let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in

        let st,scertv    = FlexCertificateVerify.send(st,nsc.si,sigAlg,skey) in

        let st,ffS       = FlexFinished.send(st,nsc,Server) in

        // Peer advertise that it will encrypt the traffic
        let st,_,_       = FlexCCS.receive(st) in
        let st           = FlexState.installReadKeys st nsc in

        let st,ffC       = FlexFinished.send(st,nsc,Client) in
        st

    end

//
//        WORK IN PROGRESS FOR TLS 1.3 Draft 7
//
//
//        static member client (address:string, cn:string, port:int) : state =
//
//        // We need to use the negotiable groups extension for TLS 1.3
//        let cfg = {defaultConfig with maxVer = TLS_1p3;
//          negotiableDHGroups = [DHE2432; DHE3072; DHE4096; DHE6144; DHE8192]} in
//
//        // Start TCP connection with the server
//        let st,_ = FlexConnection.clientOpenTcpConnection(address,cn,port,cfg.maxVer) in
//
//        // We want to ensure a ciphersuite
//        let fch = {FlexConstants.nullFClientHello with
//            pv = Some(cfg.maxVer);
//            ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]) } in
//
//        let st,nsc,fch   = FlexClientHello.send(st,fch,cfg) in
//        let st,nsc,fcks  = FlexClientKeyShare.send(st,nsc) in
//
//        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
//        let st,nsc,fsks  = FlexServerKeyShare.receive(st,nsc) in
//
//        // Peer advertises that it will encrypt the traffic
//        let st           = FlexState.installReadKeys st nsc in
//        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
//        let st,nsc,scertv = FlexCertificateVerify.receive(st,nsc,FlexConstants.sigAlgs_ALL) in
//        let st,nsc,ffS   = FlexFinished.receive(st,nsc,Server) in
//
//        // We advertise that we will encrypt the traffic
//        let st           = FlexState.installWriteKeys st nsc in
//        let st,nsc,ffC   = FlexFinished.send(st,nsc,Client) in
//
//        // Install the application data keys
//        let st           = FlexState.installReadKeys st nsc in
//        let st           = flexstate.installwritekeys st nsc in
//        st
