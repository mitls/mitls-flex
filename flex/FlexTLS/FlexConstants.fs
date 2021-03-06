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

module FlexTLS.FlexConstants

open Bytes
open Error
open TLSInfo
open TLSConstants
open CoreKeys

open FlexTypes

/// <summary>
/// Module for constant values and initialization values
/// </summary>
type FlexConstants =
    class

    /// <summary> Diffie Hellman default negotiated group (TLS 1.3) </summary>
    static member defaultTLS13group = TLSInfo.defaultConfig.negotiableDHGroups.Head

    /// <summary> Elliptic Curve Diffie Hellman default curve and associated compression </summary>
    static member defaultECDHcurve = ECC_P256
    static member defaultECDHcurveCompression = false

    /// <summary> Default TCP port, used to listen or to connect to </summary>
    static member defaultTCPPort = 443

    /// <summary> Default TCP port for malicious server, used to listen </summary>
    static member defaultTCPMaliciousPort = 6666

    /// <summary> Default protocol version </summary>
    static member defaultProtocolVersion = TLS_1p2

    /// <summary> Default fragmentation policy </summary>
    static member defaultFragmentationPolicy = All(fragmentLength)

    /// <summary> Default ECDHE ciphersuites </summary>
    static member defaultECDHECiphersuites = [
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
        TLS_ECDHE_RSA_WITH_RC4_128_SHA;]

    /// <summary> Default DHE ciphersuites </summary>
    static member defaultDHECiphersuites = [
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384;
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256;
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256;
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256;
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA;
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA;
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA;
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA;]

    /// <summary> Default RSA ciphersuites </summary>
    static member defaultRSACiphersuites = [
        TLS_RSA_WITH_AES_256_GCM_SHA384;
        TLS_RSA_WITH_AES_128_GCM_SHA256;
        TLS_RSA_WITH_AES_256_CBC_SHA256;
        TLS_RSA_WITH_AES_128_CBC_SHA256;
        TLS_RSA_WITH_AES_256_CBC_SHA;
        TLS_RSA_WITH_AES_128_CBC_SHA;
        TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        TLS_RSA_WITH_RC4_128_SHA;
        TLS_RSA_WITH_RC4_128_MD5;
        TLS_RSA_WITH_NULL_SHA256;
        TLS_RSA_WITH_NULL_SHA;
        TLS_RSA_WITH_NULL_MD5;]

    /// <summary> All supported signature algorithms </summary>

    static member sigAlgs_ALL = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL);(SA_DSA, SHA)]

    /// <summary> Signature algorithms suitable for RSA ciphersuites </summary>

    static member sigAlgs_RSA = [(SA_RSA, SHA);(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, NULL)]

    /// <summary> Redefine TLSConstants ciphersuite name parsing to ignore SCSV ciphersuites </summary>

    static member names_of_cipherSuites css =
        match css with
        | [] -> correct []
        | h::t ->
            if contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV [h] then
                match FlexConstants.names_of_cipherSuites t with
                | Error(x,y) -> Error(x,y)
                | Correct(rem) -> correct(rem)
            else
                match name_of_cipherSuite h with
                | Error(x,y) -> Error(x,y)
                | Correct(n) ->
                    match FlexConstants.names_of_cipherSuites t with
                    | Error(x,y) -> Error(x,y)
                    | Correct(rem) -> correct (n::rem)

    /// <summary> Default minimum accepted size for DH parameters </summary>
    static member minDHSize = TLSInfo.defaultConfig.dhPQMinLength

    /// <summary> Default minimum accepted size for ECDH curve </summary>
    static member minECDHSize = 256

    /// <summary> Default DH database name </summary>
    static member dhdb = DHDB.create "dhparams-db.bin"

    /// <summary> Default DH params </summary>
    static member defaultDHParams =
        let _,dhparams = CoreDH.load_default_params "default-dh.pem" FlexConstants.dhdb DHDBManager.defaultDHPrimeConfidence FlexConstants.minDHSize in
        dhparams

    /// <summary> Default ECDH params </summary>
    static member defaultECDHParams = CommonDH.DHP_EC(ECGroup.getParams FlexConstants.defaultECDHcurve)

    /// <summary> Default DH key exchange parameters, with default DH group and empty DH shares </summary>
    static member nullKexDH = {
        pg = (FlexConstants.defaultDHParams.dhp,FlexConstants.defaultDHParams.dhg);
        x  = empty_bytes;
        gx = empty_bytes;
        gy = empty_bytes;
    }

    /// <summary> Default ECDH key exchange parameters, with default ECDH group and empty DH shares </summary>
    static member nullKexECDH = {
        curve = FlexConstants.defaultECDHcurve;
        comp = FlexConstants.defaultECDHcurveCompression;
        x = empty_bytes;
        ecp_x = empty_bytes,empty_bytes;
        ecp_y = empty_bytes,empty_bytes;
    }

    /// <summary> Empty HelloRequest message </summary>
    static member nullFHelloRequest : FHelloRequest = {
        payload = empty_bytes;
    }

    /// <summary> Default ClientHello message </summary>
    /// <remarks>
    /// Sending this message will produce a client hello with
    /// - Highest supported protocol version
    /// - Fresh client randomness
    /// - Empty session identifier
    /// - Default ciphersuites and compression method
    /// - All extensions enabled by the default configuration
    /// </remarks>
    static member nullFClientHello : FClientHello = {
        pv   = Some(defaultConfig.maxVer);
        rand = empty_bytes;
        sid  = None;
        ciphersuites =  (match FlexConstants.names_of_cipherSuites defaultConfig.ciphersuites with
                        | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
                        | Correct(s) -> Some(s));
        comps = Some(defaultConfig.compressions);
        ext   = None;
        payload = empty_bytes;
    }

    /// <summary> Default ServerHello message </summary>
    /// <remark>
    /// Sending this message together with a filled ClientHello message
    /// will perform some basic negotiation and send a valid ServerHello with
    /// fresh server randomness.
    /// </remarks>
    static member nullFServerHello : FServerHello = {
        pv   = None;
        rand = empty_bytes;
        sid  = None;
        ciphersuite = None;
        comp = defaultConfig.compressions.Head;
        ext  = None;
        payload = empty_bytes;
    }

    /// <summary> Empty Certificate message </summary>
    static member nullFCertificate : FCertificate = {
        chain = [];
        payload = empty_bytes;
    }

    /// <summary> Empty CertificateRequest message </summary>
    static member nullFCertificateRequest : FCertificateRequest = {
        certTypes = [RSA_sign; DSA_sign];
        sigAlgs = [];
        names   = [];
        payload = empty_bytes;
    }

    /// <summary> Empty CertificateVerify message </summary>

    static member nullFCertificateVerify : FCertificateVerify = {
        sigAlg    = FlexConstants.sigAlgs_RSA.Head;
        signature = empty_bytes;
        payload   = empty_bytes;
    }

    /// <summary> Empty ServerKeyExchange message, for DH key exchange </summary>

    static member nullFServerKeyExchangeDHx : FServerKeyExchange = {
        sigAlg = FlexConstants.sigAlgs_RSA.Head;
        signature = empty_bytes;
        kex     = DH(FlexConstants.nullKexDH);
        payload = empty_bytes;
    }

    /// <summary> Empty FServerHelloDone message </summary>
    static member nullFServerHelloDone : FServerHelloDone =  {
        payload = empty_bytes;
    }

    /// <summary> Empty ClientKeyExchange message, for RSA key exchange </summary>
    static member nullFClientKeyExchangeRSA : FClientKeyExchange = {
        kex     = RSA(empty_bytes);
        payload = empty_bytes;
    }

    /// <summary> Empty ClientKeyExchange message, for DH key exchange </summary>
    static member nullFClientKeyExchangeDH : FClientKeyExchange = {
        kex     = DH(FlexConstants.nullKexDH);
        payload = empty_bytes;
    }

    /// <summary> Default ChangeCipherSpecs message </summary>
    static member nullFChangeCipherSpecs : FChangeCipherSpecs = {
        payload = HandshakeMessages.CCSBytes;
    }

    /// <summary> Empty Finished message </summary>
    static member nullFFinished : FFinished = {
        verify_data = empty_bytes;
        payload     = empty_bytes;
    }

    /// <summary>
    /// A record that represents no negotiated extensions
    /// </summary>
    static member nullNegotiatedExtensions = {
        ne_extended_padding    = false;
        ne_extended_ms         = false;
        ne_renegotiation_info  = None;
        ne_negotiated_dh_group = None;
        ne_supported_curves = None;
        ne_supported_point_formats = None;
        ne_server_names = None;
    }

    /// <summary> Null SessionInfo </summary>
    static member nullSessionInfo = {
        clientID     = [];
        clientSigAlg = (SA_RSA,SHA);
        serverSigAlg = (SA_RSA,SHA);
        client_auth  = false;
        serverID     = [];
        sessionID    = empty_bytes;
        protocol_version = TLS_1p2;
        cipher_suite = nullCipherSuite;
        compression  = NullCompression;
        extensions   = FlexConstants.nullNegotiatedExtensions;
        init_crand   = empty_bytes;
        init_srand   = empty_bytes;
        session_hash = empty_bytes;
        pmsId        = noPmsId;
    }

    /// <summary> Null secrets </summary>

    static member nullSecrets = {
        pri_key = PK_None;
        kex     = RSA(empty_bytes);
        pms     = empty_bytes;
        ms      = empty_bytes;
        epoch_keys = empty_bytes,empty_bytes;
    }

    /// <summary> Null next Security Context </summary>
    static member nullNextSecurityContext = {
        si     = FlexConstants.nullSessionInfo;
        crand  = empty_bytes;
        srand  = empty_bytes;
        secrets = FlexConstants.nullSecrets;
        offers = [];
    }

    end
