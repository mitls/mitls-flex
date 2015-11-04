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

module FlexApps.Attack_Alert_Warning

open Bytes
open Error
open TLSInfo
open TLSConstants

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

type Attack_Alert_Warning =
    class

    /// Run full RSA Handshake with server side authentication only *)
    static member client (server_name:string, ?port:int, ?st:state) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection with the server if no state is provided by the user
        let st,_ =
            match st with
            | None -> FlexConnection.clientOpenTcpConnection(server_name,server_name,port)
            | Some(st) -> st,TLSInfo.defaultConfig
        in

        // Typical RSA key exchange messages

        // Ensure we use RSA
        let fch = {FlexConstants.nullFClientHello with
            ciphersuites = Some([TLS_RSA_WITH_AES_128_GCM_SHA256]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in

        // Inject a warning handshake failure alert
        let st = FlexState.updateOutgoingAlertBuffer st (abytes [|1uy;40uy|]) in
        let st = FlexRecord.FlexRecord.send(st,Alert) in

        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
        let st,_         = FlexCCS.send(st) in

        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in

        let st,ffC       = FlexFinished.send(st,nsc,Client) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let st,ffS       = FlexFinished.receive(st,nsc,Server) in
        st

    end
