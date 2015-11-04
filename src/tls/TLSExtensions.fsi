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

module TLSExtensions

open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo

// Following types only used in handshake
type clientExtension
type serverExtension

// Client side
val prepareClientExtensions: config -> ConnectionInfo -> cVerifyData -> list<clientExtension>
val clientExtensionsBytes: list<clientExtension> -> bytes
val parseServerExtensions: bytes -> Result<(list<serverExtension>)>
val negotiateClientExtensions: list<clientExtension> -> list<serverExtension> -> bool -> cipherSuite -> Result<negotiatedExtensions>

// Server side
val parseClientExtensions: bytes -> cipherSuites -> Result<(list<clientExtension>)>
val negotiateServerExtensions: list<clientExtension> -> config -> cipherSuite -> (cVerifyData * sVerifyData) -> bool -> (list<serverExtension> * negotiatedExtensions)
val serverExtensionsBytes: list<serverExtension> -> bytes

// Extension-specific
val checkClientRenegotiationInfoExtension: config -> list<clientExtension> -> cVerifyData -> bool
val checkServerRenegotiationInfoExtension: config -> list<serverExtension> -> cVerifyData -> sVerifyData -> bool
val isClientRenegotiationInfo: clientExtension -> option<cVerifyData>

#if TLSExt_sessionHash
val hasExtendedMS: negotiatedExtensions -> bool
#endif

#if tls13
val getNegotiatedDHGroup: negotiatedExtensions -> option<dhGroup>
val getOfferedDHGroups: list<clientExtension> -> option<list<dhGroup>>
#endif

#if TLSExt_extendedPadding
val hasExtendedPadding: id -> bool
#endif

// consider relocating these definitions:
val sigHashAlgBytes: Sig.alg -> bytes
val parseSigHashAlg: bytes -> Result<Sig.alg>
val sigHashAlgListBytes: list<Sig.alg> -> bytes
val parseSigHashAlgList: bytes -> Result<list<Sig.alg>>
val default_sigHashAlg: ProtocolVersion -> cipherSuite -> list<Sig.alg>
val sigHashAlg_contains: list<Sig.alg> -> Sig.alg -> bool
val cert_type_list_to_SigHashAlg: list<certType> -> ProtocolVersion -> list<Sig.alg>
val cert_type_list_to_SigAlg: list<certType> -> list<sigAlg>
val sigHashAlg_bySigList: list<Sig.alg> -> list<sigAlg> -> list<Sig.alg>
