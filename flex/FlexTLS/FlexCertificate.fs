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

module FlexTLS.FlexCertificate

open NLog

open Error
open TLSInfo
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake

/// <summary>
/// Module receiving, sending and forwarding TLS Certificate messages.
/// </summary>
type FlexCertificate =
    class

    /// <summary>
    /// Receive a Certificate message from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="role"> Behaviour is either Client or Server </param>
    /// <param name="nsc"> Optional Next security context object updated with new data </param>
    /// <returns> Updated state * next security context * FCertificate message </returns>
    static member receive (st:state, role:Role, ?nsc:nextSecurityContext) : state * nextSecurityContext * FCertificate =
        LogManager.GetLogger("file").Info("# CERTIFICATE : FlexCertificate.receive");
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let si = nsc.si in
        let st,hstype,payload,to_log = FlexHandshake.receive(st) in
        match hstype with
        | HT_certificate  ->
            (match parseClientOrServerCertificate payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (chain) ->
                let cert : FCertificate = { chain = chain; payload = to_log } in
                let si =
                    match role with
                    | Server ->
                        { si with
                          client_auth = true;
                          clientID = chain;
                        }
                    | Client ->
                        { si with serverID = chain; }
                in
                let nsc = { nsc with si = si } in
                LogManager.GetLogger("file").Debug(sprintf "--- Payload : %A" (Bytes.hexString(payload)));
                (st,nsc,cert)
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected handshake type: %A" hstype))

    /// <summary>
    /// Prepare a Certificate message that will not be sent to the network
    /// </summary>
    /// <param name="cert"> Certificate chain </param>
    /// <returns> FCertificate record </returns>

    static member prepare (chain:Cert.chain) : FCertificate =
        let payload = HandshakeMessages.serverCertificateBytes chain in
        let fcert = {chain = chain; payload = payload } in
        fcert

    static member send(st:state, role:Role, nsc:nextSecurityContext, cfg:config, ?fp:fragmentationPolicy) : state * nextSecurityContext * FCertificate =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let cn =
            match role with
            | Client -> cfg.client_name
            | Server -> cfg.server_name in
        if cn = "" then
            failwith (perror __SOURCE_FILE__ __LINE__ "A non-empty common name must be provided in the config")
        else
        let chain,prikey =
            match role with
            | Client
            | Server when not (TLSConstants.isRSACipherSuite nsc.si.cipher_suite) ->
                // A client always makes signatures; a server on a non-RSA key exchange will perform a signature
                (match Cert.for_signing FlexConstants.sigAlgs_ALL cn FlexConstants.sigAlgs_ALL with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "A signing certificate for the cn=\"%s\" could not be found in the store" cn))
                | Some(chain,alg,key) ->
                    let key = Sig.leak alg key in
                    chain,PK_Sig(alg,key))
             | Server when TLSConstants.isRSACipherSuite nsc.si.cipher_suite ->
                // need a certificate for key encryption
                (match Cert.for_key_encryption FlexConstants.sigAlgs_RSA cn with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "A key-encryption certificate for the cn=\"%s\" could not be found in the store" cn))
                | Some(chain,key) ->
                    let key = RSAKey.repr_of_rsaskey key in
                    chain,PK_Enc(key)
                )
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "All possible cases are expected to be covered")
        in
        let st,nsc,fcrt = FlexCertificate.send(st,role,chain,nsc=nsc,fp=fp) in
        let keys = {nsc.secrets with pri_key = prikey} in
        let nsc = {nsc with secrets = keys} in
        st,nsc,fcrt

    /// <summary>
    /// Send a Certificate message to the network stream using User provided chain of certificates
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="role"> Behavior is either Client or Server </param>
    /// <param name="chain"> Certificate chain that will be send over the network </param>
    /// <param name="nsc"> Optional Next security context object updated with new data </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * next security context * FCertificate message </returns>
    static member send (st:state, role:Role, chain:Cert.chain, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FCertificate =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fcrt = {FlexConstants.nullFCertificate with chain = chain} in
        FlexCertificate.send(st,role,fcrt=fcrt,nsc=nsc,fp=fp)

    /// <summary>
    /// Send a Certificate message to the network stream using User provided chain of certificates
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="role"> Behavior is either Client or Server </param>
    /// <param name="nsc"> Next security context object updated with new data </param>
    /// <param name="fcrt"> Optional Certificate message </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * next security context * FCertificate message </returns>
    static member send (st:state, role:Role, ?nsc:nextSecurityContext, ?fcrt:FCertificate, ?fp:fragmentationPolicy) : state * nextSecurityContext * FCertificate =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fcert = defaultArg fcrt FlexConstants.nullFCertificate in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in

        let st,fcert = FlexCertificate.send(st,fcert.chain,fp) in

        let si = nsc.si in
        let si =
            match role with
            | Client ->   { si with
                            clientID = fcert.chain;
                            client_auth = true;
                          }
            | Server -> { si with serverID = fcert.chain }
        in
        let nsc = { nsc with si = si } in
        st,nsc,fcert

    /// <summary>
    /// Send a Certificate message to the network stream using User provided chain of certificates
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="cert"> Certificate chain </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FCertificate message </returns>
    static member send (st:state, chain:Cert.chain, ?fp:fragmentationPolicy) : state * FCertificate =
        LogManager.GetLogger("file").Info("# CERTIFICATE : FlexCertificate.send");
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in

        let fcert = FlexCertificate.prepare(chain) in
        let st = FlexHandshake.send(st,fcert.payload,fp) in
        st,fcert

    end
