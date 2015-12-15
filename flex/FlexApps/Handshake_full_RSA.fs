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

module FlexApps.Handshake_full_RSA

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
open FlexAlert

/// Run full RSA handshakes, complying with TLS_RSA_WITH_AES_128_GCM_SHA256
type Handshake_full_RSA =
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

        // Typical RSA key exchange messages

        // Ensure we use RSA
        let fch = {FlexConstants.nullFClientHello with
            ciphersuites = Some([TLS_RSA_WITH_AES_128_GCM_SHA256]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
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
        let st           = FlexAlert.send(st,TLSError.AD_close_notify) in
        st

    /// CLIENT - Run full RSA Handshake with mutual server and client authentication *)
    static member client_with_auth (address:string, cn_hint:string, ?port:int, ?timeout:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let timeout = defaultArg timeout 0 in
        let chain,salg,skey =
            match Cert.for_signing FlexConstants.sigAlgs_ALL cn_hint FlexConstants.sigAlgs_RSA with
            | None -> failwith "Failed to retrieve certificate data"
            | Some(c,a,s) -> c,a,s
        in
        Handshake_full_RSA.client_with_auth (address,chain,salg,skey,port,timeout)

    static member client_with_auth (address:string, chain:Cert.chain, salg:Sig.alg, skey:Sig.skey, ?port:int, ?timeout:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let timeout = defaultArg timeout 0 in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(address,address,port,timeout=timeout) in

        // Typical RSA key exchange messages

        // Ensure we use RSA
        let fch = {FlexConstants.nullFClientHello with
            ciphersuites = Some([TLS_RSA_WITH_AES_128_GCM_SHA256]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in

        // Client authentication
        let st,nsc,fcertC = FlexCertificate.send(st,Client,chain,nsc) in
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
        let st,fcver     = FlexCertificateVerify.send(st,nsc.si,salg,skey) in

        // Advertise that we will encrypt the trafic from now on
        let st,_         = FlexCCS.send(st) in

        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in

        let st,ffC       = FlexFinished.send(st,nsc,Client) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let st,ffS       = FlexFinished.receive(st,nsc,Server) in
        st

    /// SERVER - Run full RSA Handshake with server side authentication only
    static member server (listening_address:string, ?cn_hint:string, ?port:int, ?timeout:int) : state =
        let timeout = defaultArg timeout 0 in
        let cn_hint = defaultArg cn_hint listening_address in
        let port = defaultArg port FlexConstants.defaultTCPPort in
        match Cert.for_key_encryption FlexConstants.sigAlgs_RSA cn_hint with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Private key not found for the given CN: %s" cn_hint))
        | Some(chain,sk) -> Handshake_full_RSA.server(listening_address,chain,sk,port,timeout)

    static member server (listening_address:string, chain:Cert.chain, sk:RSAKey.sk, ?port:int, ?timeout:int) : state =
        let timeout = defaultArg timeout 0 in
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn_hint =
            match Cert.get_hint chain with
            | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Could not parse given certficate")
            | Some(cn_hint) -> cn_hint
        in

        // Accept TCP connection from the client
        let st,cfg = FlexConnection.serverOpenTcpConnection(listening_address,cn_hint,port,timeout=timeout) in

        // Start typical RSA key exchange
        let st,nsc,fch   = FlexClientHello.receive(st) in

        // Sanity check: our preferred ciphersuite is there
        if not (List.exists (fun cs -> cs = TLS_RSA_WITH_AES_128_GCM_SHA256) (FlexClientHello.getCiphersuites fch)) then
            failwith (perror __SOURCE_FILE__ __LINE__ "No suitable ciphersuite given")
        else

        // Ensure we send our preferred ciphersuite
        let fsh = { FlexConstants.nullFServerHello with
            ciphersuite = Some(TLS_RSA_WITH_AES_128_GCM_SHA256)} in

        let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc,fsh) in
        let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
        let st,fshd      = FlexServerHelloDone.send(st) in
        let st,nsc,fcke  = FlexClientKeyExchange.receiveRSA(st,nsc,fch,sk=sk) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st          = FlexState.installReadKeys st nsc in

        let st,ffC      = FlexFinished.receive(st,nsc,Client) in

        // Advertise that we will encrypt the trafic from now on
        let st,_   = FlexCCS.send(st) in

        // Start encrypting
        let st     = FlexState.installWriteKeys st nsc in

        let _      = FlexFinished.send(st,nsc,Server) in
        st

    /// SERVER - Run full RSA Handshake with mutual server and client authentication
    static member server_with_client_auth (listening_address:string, ?cn_hint:string, ?port:int, ?timeout:int) : state =
        let timeout = defaultArg timeout 0 in
        let cn_hint = defaultArg cn_hint listening_address in
        let port = defaultArg port FlexConstants.defaultTCPPort in
        match Cert.for_key_encryption FlexConstants.sigAlgs_RSA cn_hint with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Private key not found for the given CN: %s" cn_hint))
        | Some(chain,sk) -> Handshake_full_RSA.server_with_client_auth(listening_address,chain,sk,port)

    static member server_with_client_auth (listening_address:string, chain:Cert.chain, sk:RSAKey.sk, ?port:int, ?timeout:int) : state =
        let timeout = defaultArg timeout 0 in
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn_hint =
            match Cert.get_hint chain with
            | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Could not parse given certficate")
            | Some(cn_hint) -> cn_hint
        in

        // Accept TCP connection from the client
        let st,cfg = FlexConnection.serverOpenTcpConnection(listening_address,cn_hint,port,timeout=timeout) in

        // Start typical RSA key exchange
        let st,nsc,fch   = FlexClientHello.receive(st) in

        // Sanity check: our preferred ciphersuite and protovol version are there
        if ( not (List.exists (fun cs -> cs = TLS_RSA_WITH_AES_128_GCM_SHA256) (FlexClientHello.getCiphersuites fch)) ) || (FlexClientHello.getPV fch) <> TLS_1p2 then
            failwith (perror __SOURCE_FILE__ __LINE__ "No suitable ciphersuite given")
        else

        // Ensure we send our preferred ciphersuite
        let fsh = { FlexConstants.nullFServerHello with
            ciphersuite = Some(TLS_RSA_WITH_AES_128_GCM_SHA256) } in

        let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc,fsh) in
        let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
        let st,fcreq     = FlexCertificateRequest.send(st,nsc) in
        let st,fshd      = FlexServerHelloDone.send(st) in

        // Client authentication
        let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
        let st,nsc,fcke  = FlexClientKeyExchange.receiveRSA(st,nsc,(FlexClientHello.getPV fch)) in
        let st,fcver     = FlexCertificateVerify.receive(st,nsc,fcreq) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let st,ffC       = FlexFinished.receive(st,nsc,Client) in

        // Advertise that we will encrypt the trafic from now on
        let st,_         = FlexCCS.send(st) in

        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in

        let st,ffS       = FlexFinished.send(st,nsc,Server) in
        st

    end
