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

module FlexApps.Script

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexAlert
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexServerKeyExchange
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets

type Script =
    class

    (* CLIENT - Run a full Handshake RSA with server side authentication only *)
    static member run () : state =

        // Peer information
        let address = "www.google.com" in
        let port = FlexConstants.defaultTCPPort in
        let timeout = 0 in

        Handshake_full_ECDHE.Handshake_full_ECDHE.client(address,port)

    end
