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

module TLSInfo

open Bytes
open Date
open TLSConstants

type rw =
    | Reader
    | Writer

type sessionID = bytes
type preRole =
    | Client
    | Server
type Role = preRole

// Client/Server randomness
type random = bytes
type crand = random
type srand = random
type csrands = bytes

type cVerifyData = bytes (* ClientFinished payload *)
type sVerifyData = bytes (* ServerFinished payload *)

type sessionHash = bytes

type serverName =
| SNI_DNS of bytes
| SNI_UNKNOWN of int * bytes

// Defined here to not depend on TLSExtension
type negotiatedExtensions = {
    ne_extended_ms: bool;
    ne_extended_padding:bool;
    ne_renegotiation_info: (cVerifyData * sVerifyData) option;
#if tls13
    ne_supported_curves: ec_curve list option;
    ne_supported_point_formats: ECGroup.point_format list option;
    ne_negotiated_dh_group: option<dhGroup>;
    ne_server_names: serverName list option;
#endif
}

val ne_default : negotiatedExtensions

type pmsId
val mk_pmsId: PMS.pms -> pmsId
val noPmsId: pmsId

type SessionInfo = {
    init_crand: crand;
    init_srand: srand;
    protocol_version: ProtocolVersion;
    cipher_suite: cipherSuite;
    compression: Compression;
    extensions: negotiatedExtensions;
    pmsId: pmsId;
    session_hash: sessionHash;
    client_auth: bool;
    clientID: list<Cert.cert>;
    clientSigAlg: Sig.alg;
    serverID: list<Cert.cert>;
    serverSigAlg: Sig.alg;
    sessionID: sessionID;
    }

type msId =
   | StandardMS of pmsId * csrands * kefAlg
   | ExtendedMS of pmsId * sessionHash * kefAlg

val mk_csrands: SessionInfo -> bytes
val mk_kefAlg: SessionInfo -> kefAlg
val mk_kefAlg_extended: SessionInfo -> kefAlg
val mk_vdAlg: SessionInfo -> vdAlg
val mk_msid: SessionInfo -> msId

type id = {
  // indexes and algorithms of the session used in the key derivation
  msId   : msId;   // the index of the master secret used for key derivation
  kdfAlg : kdfAlg; // the KDF algorithm used for key derivation
  pv: ProtocolVersion; //Should be part of aeAlg
  aeAlg  : aeAlg;  // the authenticated-encryption algorithms
  csrConn: csrands;
  ext: negotiatedExtensions;
  writer : Role
  }

val macAlg_of_id: id -> macAlg
val encAlg_of_id: id -> encAlg
val pv_of_id: id -> ProtocolVersion

type abbrInfo =
    {abbr_crand: crand;
     abbr_srand: srand;
     abbr_session_hash: sessionHash;
     abbr_vd: (cVerifyData * sVerifyData) option}

type preEpoch

type epoch = preEpoch

type event =
  | KeyCommit of    csrands * ProtocolVersion * aeAlg * negotiatedExtensions
  | KeyGenClient of csrands * ProtocolVersion * aeAlg * negotiatedExtensions
  | SentCCS of Role * SessionInfo
  | SentCCSAbbr of Role * abbrInfo

val mk_id: epoch -> id
val unAuthIdInv: id -> epoch

val isInitEpoch: epoch -> bool
val epochSI: epoch -> SessionInfo
val epochAI: epoch -> abbrInfo
val epochSRand: epoch -> srand
val epochCRand: epoch -> crand
val epochCSRands: epoch -> crand

// Role is of the writer
type preConnectionInfo =
    { role: Role;
      id_rand: random;
      id_in:  epoch;
      id_out: epoch}
type ConnectionInfo = preConnectionInfo
val connectionRole: ConnectionInfo -> Role

val initConnection: Role -> bytes -> ConnectionInfo
val fullEpoch: epoch -> SessionInfo -> epoch
val abbrEpoch: epoch -> abbrInfo -> SessionInfo -> epoch -> epoch
val predEpoch: epoch -> epoch
val sinfo_to_string: SessionInfo -> string

(* Application configuration options *)

type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type config = {
    minVer: ProtocolVersion;
    maxVer: ProtocolVersion;
    ciphersuites: cipherSuites;
    compressions: list<Compression>;

    (* Handshake specific options *)

    (* Client side *)
    honourHelloReq: helloReqPolicy;
    allowAnonCipherSuite: bool;
    safe_resumption: bool;

    (* Server side *)
    request_client_certificate: bool;
    check_client_version_in_pms_for_old_tls: bool;

    (* Common *)
    safe_renegotiation: bool;
    server_name: Cert.hint;
    client_name: Cert.hint;

    (* Sessions database *)
    sessionDBFileName: string;
    sessionDBExpiry: TimeSpan;

    (* DH groups database *)
    dhDBFileName: string;
    dhDefaultGroupFileName: string;
    dhPQMinLength: nat * nat;
#if tls13
    negotiableDHGroups: list<dhGroup>;
#endif

    (* ECDH settings *)
    ecdhGroups: ec_curve list;
    }

val defaultConfig: config

val max_TLSCipher_fragment_length: nat
val fragmentLength: nat

#if ideal
val honestPMS: pmsId -> bool

val safeHS: epoch -> bool
val safeCRE: SessionInfo -> bool
val safeVD: SessionInfo -> bool
val safeHS_SI: SessionInfo -> bool
val auth: epoch -> bool

val safeKDF: id -> bool
val safe: epoch -> bool
val authId: id -> bool
val safeId : id -> bool
#endif
