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

module CoreCiphers
open Bytes

open CryptoProvider
open Org.BouncyCastle.Crypto.Engines
open Org.BouncyCastle.Crypto.Parameters

type key   = bytes
type iv    = bytes
type adata = bytes

let encrypt cipher omode key plain =
    let engine = CoreCrypto.BlockCipher ForEncryption cipher omode (cbytes key) in
        abytes (engine.Process (cbytes plain))

let decrypt cipher omode key encrypted =
    let engine = CoreCrypto.BlockCipher ForDecryption cipher omode (cbytes key) in
        abytes (engine.Process (cbytes encrypted))

let aes_cbc_encrypt key iv plain     = encrypt cipher.AES (Some (CBC (cbytes iv))) key plain
let aes_cbc_decrypt key iv encrypted = decrypt cipher.AES (Some (CBC (cbytes iv))) key encrypted

let des3_cbc_encrypt key iv plain     = encrypt DES3 (Some (CBC (cbytes iv))) key plain
let des3_cbc_decrypt key iv encrypted = decrypt DES3 (Some (CBC (cbytes iv))) key encrypted

let aes_gcm_encrypt key iv ad plain =
    let acipher = acipher.AES
    let amode   = GCM (cbytes iv, cbytes ad)
    let engine  = CoreCrypto.AeadCipher ForEncryption acipher amode (cbytes key) in
        abytes (engine.Process (cbytes plain))

let aes_gcm_decrypt key (iv : iv) (ad : adata) plain =
    let acipher = acipher.AES
    let amode   = GCM (cbytes iv, cbytes ad)
    let engine  = CoreCrypto.AeadCipher ForDecryption acipher amode (cbytes key) in
        try
            Some (abytes (engine.Process (cbytes plain)))
        with AEADFailure -> None

type rc4engine = RC4Engine of StreamCipher

let rc4create (key : key) =
    let engine = CoreCrypto.StreamCipher ForEncryption (* ignored *) RC4 (cbytes key) in
        RC4Engine engine

let rc4process (RC4Engine engine) (input : bytes) =
    abytes (engine.Process (cbytes input))
