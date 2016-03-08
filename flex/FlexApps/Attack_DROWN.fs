(*
 * Copyright 2016 INRIA and Microsoft Corporation
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

module FlexApps.Attack_DROWN

open Bytes
open Error
open TLSError
open TLSInfo
open TLSConstants
open Sig

open FlexTLS
open FlexTypes
open FlexAlert
open FlexConstants
open FlexConnection
open FlexRecord
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone


//See http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html
type cipherSuiteName =
  | SSL_CK_RC4_128_WITH_MD5		
  | SSL_CK_RC4_128_EXPORT40_WITH_MD5	
  | SSL_CK_RC2_128_CBC_WITH_MD5		
  | SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
  | SSL_CK_IDEA_128_CBC_WITH_MD5	
  | SSL_CK_DES_64_CBC_WITH_MD5		
  | SSL_CK_DES_192_EDE3_CBC_WITH_MD5
  | SSL_CK_RC4_64_WITH_MD5

let cipherSuiteBytes cs =
  match cs with
  | SSL_CK_RC4_128_WITH_MD5              -> abytes [| 0x01uy; 0x00uy; 0x80uy |]
  | SSL_CK_RC4_128_EXPORT40_WITH_MD5	 -> abytes [| 0x02uy; 0x00uy; 0x80uy |] 
  | SSL_CK_RC2_128_CBC_WITH_MD5		 -> abytes [| 0x03uy; 0x00uy; 0x80uy |] 
  | SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 -> abytes [| 0x04uy; 0x00uy; 0x80uy |] 
  | SSL_CK_IDEA_128_CBC_WITH_MD5	 -> abytes [| 0x05uy; 0x00uy; 0x80uy |] 
  | SSL_CK_DES_64_CBC_WITH_MD5		 -> abytes [| 0x06uy; 0x00uy; 0x40uy |] 
  | SSL_CK_DES_192_EDE3_CBC_WITH_MD5	 -> abytes [| 0x07uy; 0x00uy; 0xc0uy |]
  | SSL_CK_RC4_64_WITH_MD5		 -> abytes [| 0x08uy; 0x00uy; 0x80uy |]

let ssl2ExportCipherSuites =
  [ SSL_CK_RC4_128_EXPORT40_WITH_MD5;	
    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5;
    SSL_CK_DES_64_CBC_WITH_MD5;	
    SSL_CK_RC4_64_WITH_MD5
  ]

let rsaCipherSuites =
   [ TLS_RSA_WITH_NULL_MD5;
     TLS_RSA_WITH_NULL_SHA;
     TLS_RSA_WITH_NULL_SHA256;
     TLS_RSA_WITH_RC4_128_MD5;
     TLS_RSA_WITH_RC4_128_SHA;
     TLS_RSA_WITH_3DES_EDE_CBC_SHA;
     TLS_RSA_WITH_AES_128_CBC_SHA;
     TLS_RSA_WITH_AES_256_CBC_SHA;
     TLS_RSA_WITH_AES_128_CBC_SHA256;
     TLS_RSA_WITH_AES_256_CBC_SHA256
   ]

let rec cipherSuitesBytes css =
    match css with
    | [] -> empty_bytes
    | cs::css -> cipherSuiteBytes cs @|
                 cipherSuitesBytes css

type messageType =
  | ClientHello
  | ServerHello

let mtByte (mt:messageType) : byte =
  match mt with
  | ClientHello -> 1uy
  | ServerHello -> 4uy

let parseMessageType (b:byte) =
  match b with
  | 1uy -> correct ClientHello
  | 4uy -> correct ServerHello
  | _   -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Unknown message type")


type Attack_DROWN =
    class

    static member parseHeader (st:state) : int * bool * int * messageType =
      match Tcp.read st.ns 3 with
      | Error x -> failwith (perror __SOURCE_FILE__ __LINE__ x)
      | Correct bs ->
      	let b0,b1,b2 = split2 bs 1 1 in
      	let b0 = cbyte b0 in
	let b1 = cbyte b1 in
	let b2 = cbyte b2 in
	let short = (b0 &&& 0x80uy) <> 0x00uy in
      	if short then
	  let len = (int(b0 &&& 0x7fuy) <<< 8) + int b1 in
	  match parseMessageType b2 with
	  | Correct(mt) -> len, false, 0, mt
	  | _ -> failwith "Unexpected message type"
	else
	  let len = (int(b0 &&& 0x3fuy) <<< 8) + int b1 in
	  let is_escape = (b0 &&& 0x40uy) <> 0x00uy in
	  let padlen = int b2 in
	  match Tcp.read st.ns 1 with
	  | Error x -> failwith (perror __SOURCE_FILE__ __LINE__ x)
      	  | Correct b3 ->
	     match parseMessageType (cbyte b3) with
	     | Correct(mt) -> len, is_escape, padlen, mt
	     | _ -> failwith "Unexpected message type" 


    static member getServerhello (st:state, len:int) : bytes =
       match Tcp.read st.ns len with
       | Error x -> failwith (perror __SOURCE_FILE__ __LINE__ x)
       | Correct payload ->
         let _,ct,payload = split2 payload 1 1 in
	 if cbyte ct <> 0x01uy then
	    failwith "Unexpected certificate type"
	 else
	   let ver,clen,payload = split2 payload 2 2 in
	   if ver <> abyte2 ( 0uy, 2uy ) then
	     failwith "Unexpected protocol version"
	   else
	     let clen = int_of_bytes clen in    
	     let cslen,cidlen,payload = split2 payload 2 2 in
	     let cert,_ = split payload clen in
	     cert

    static member run (address:string, port:int) : unit =
    	let cn = address in

	let st,_ =
	  try
	    FlexConnection.clientOpenTcpConnection(address,cn,port,SSL_3p0,timeout=0)
	  with
	  | _ ->
	    printf "TCP connection refused\n";
	    exit 0
	in

	let ct  = abyte 0x80uy in        // msb set (2-byte record length)
	let hmt = abyte 1uy in           // ClientHello
	let ver = abyte2 ( 0uy, 2uy ) in // versionBytes SSL_2p0 in
	let cs  = cipherSuitesBytes ssl2ExportCipherSuites in
	let sid = empty_bytes in
	let cr  = Nonce.random 16 in
	let cslen  = bytes_of_int 2 (length cs) in
	let sidlen = bytes_of_int 2 (length sid) in
	let crlen  = bytes_of_int 2 (length cr) in
	let ch = hmt @| ver @| cslen @| sidlen @| crlen @| cs @| sid @| cr in 
	let ch = ct @| vlbytes 1 ch in

        match Tcp.write st.ns ch with
        | Error x -> failwith x
        | Correct() ->

 	let len, _, padlen, mt = 
	  try
            Attack_DROWN.parseHeader(st)
	  with
	  | _ ->
	   begin
	   printf "We couldn't determine if %s is vulnerable to the DROWN attack.\n" cn; 
	   printf "It doesn't accept SSL2 export ciphersuites on port %d.\n" port;
	   printf "The server may be vulnerable if it uses SSL2 in some other protocol\n";
	   exit 0
	   end
	in

	if mt <> ServerHello then
   	begin
	   printf "We couldn't determine if %s is vulnerable to the DROWN attack.\n" cn; 
	   printf "It doesn't accept SSL2 export ciphersuites on port %d.\n" port;
	   printf "The server may be vulnerable if it uses SSL2 export ciphersuites\n";
	   printf "in some other protocol\n";
	   exit 0
	end
	else

	let cert = Attack_DROWN.getServerhello(st, len-1) in
	
	printf "SSL2 Cert: %s\n" (hexString cert);

	match Cert.get_public_encryption_key cert with
	| Error(_,x) -> failwith x
	| Correct(pk1) ->

	match pk1.pk with
	| CoreACiphers.RSAPKey pk1 ->
	//printf "%s\n %s\n" (hexString (fst pk1)) (hexString (snd pk1));
	Tcp.close st.ns;

        let st,_ = FlexConnection.clientOpenTcpConnection(address,address,port,timeout=0) in

        let fch = {FlexConstants.nullFClientHello with ciphersuites = Some(rsaCipherSuites) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
	let fcert =
	  try
            let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
            let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
            let st,fshd      = FlexServerHelloDone.receive(st) in
	    fcert
	  with
	  | _ ->
	   begin
	   printf "We couldn't determine if %s is vulnerable to the DROWN attack.\n" cn; 
	   printf "It does accept SSL2 export ciphersuites on port %d, but not SSL3/TLS.\n" port;
	   printf "The server may be vulnerable if the RSA key used for SSL2 export\n";
	   printf "ciphersuites is used in some other protocol\n";
	   exit 0
	   end
	in

	match fcert.chain with
	| [] -> failwith "no certificate"
	| cert :: _ -> 
	printf "SSL3/TLS Cert: %s\n" (hexString cert);

	match Cert.get_public_encryption_key cert with
	| Error(_,x) -> failwith x
	| Correct(pk2) ->

 	match pk2.pk with
	| CoreACiphers.RSAPKey pk2 ->
	//printf "%s\n %s\n" (hexString (fst pk2)) (hexString (snd pk2));

	if equalBytes (fst pk1) (fst pk2) && equalBytes (snd pk1) (snd pk2) then
	begin
	   printf "%s is vulnerable to the DROWN attack.\n" cn;
	   printf "It accepts SSL2 export ciphersuites and uses the same RSA key for SSL3/TLS.\n"
	end
	else
	begin
	   printf "We couldn't determine if %s is vulnerable to the DROWN attack.\n" cn; 
	   printf "It accepts SSL2 export ciphersuites and SSL3/TLS on port %d,\n" port;
	   printf "but uses different RSA keys for each.\n";
	   printf "The server may be vulnerable if the RSA key used for SSL2 export\n";
	   printf "ciphersuites is used in some other protocol\n"
	end
	   
end
