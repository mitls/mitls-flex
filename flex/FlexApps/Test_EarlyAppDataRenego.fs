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

module FlexApps.Test_EarlyAppDataRenego

open Bytes
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexRecord
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexAppData
open FlexState
open FlexSecrets
open FlexHandshake


type Test_EarlyAppDataRenego =
    class

    /// CLIENT - Run full RSA Handshake with server authentication only
    static member client (address:string, ?port:int, ?st:state, ?timeout:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let timeout = defaultArg timeout 0 in

        // Start TCP connection with the server if no state is provided by the user
        let st,_ =
            match st with
            | None -> FlexConnection.clientOpenTcpConnection(address,address,port,timeout=timeout)
            | Some(st) -> st,TLSInfo.defaultConfig
        in

        // First Handshake using a typical RSA Key Exchange
        let fch = {FlexConstants.nullFClientHello with
            ciphersuites = Some([TLS_RSA_WITH_AES_128_GCM_SHA256]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
        let st,_         = FlexCCS.send(st) in
        let st           = FlexState.installWriteKeys st nsc in
        let st,ffC       = FlexFinished.send(st,nsc,Client) in
        let st,_,_       = FlexCCS.receive(st) in
        let st           = FlexState.installReadKeys st nsc in
        let st,ffS       = FlexFinished.receive(st,nsc,Server) in


        // Renegotiation
        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in

        // Send inexpected application data
        let st           = FlexAppData.send_http_get(st) in

        // Check if application data is returned by the peer
        let st,bytes     = FlexAppData.receive(st) in
        st

    end
