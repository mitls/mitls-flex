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

module CoreDH

open Bytes
open Error

(* ------------------------------------------------------------------------ *)
open System
open System.IO
open System.Text

open Org.BouncyCastle.Math
open Org.BouncyCastle.Security
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Utilities.IO.Pem
open Org.BouncyCastle.Asn1

(* ------------------------------------------------------------------------ *)
open CoreKeys

let defaultPQMinLength = (1024, 160)

(* ------------------------------------------------------------------------ *)
let check_element dhp (ebytes:bytes) =
    let p   = new BigInteger(1, cbytes dhp.dhp)
    let e   = new BigInteger(1, cbytes ebytes)
    let pm1 = p.Subtract(BigInteger.One)
    // check e in [2,p-2]
    if ((e.CompareTo BigInteger.One) > 0) && ((e.CompareTo pm1) < 0) then
        if dhp.safe_prime then
            true
        else
            let q = new BigInteger(1, cbytes dhp.dhq)
            let r = e.ModPow(q, p)
            // For OpenSSL-generated parameters order(g) = 2q, so e^q mod p = p-1
            r.Equals(BigInteger.One) || r.Equals(pm1)
    else
        false

let check_p_g (conf:nat) (minPl:nat) (minQl:nat) pbytes gbytes : (string, bytes) optResult =
    let p = new BigInteger(1, cbytes pbytes)
    let g = new BigInteger(1, cbytes gbytes)
    let pm1 = p.Subtract(BigInteger.One)
    if (g.CompareTo BigInteger.One) > 0 && (g.CompareTo pm1) < 0 then
        let q = pm1.Divide(BigInteger.Two) in
        if minPl <= p.BitLength && minQl <= q.BitLength then
            if p.IsProbablePrime(conf) && q.IsProbablePrime(conf) then
                correct (abytes (q.ToByteArrayUnsigned()))
            else
                Error (perror __SOURCE_FILE__ __LINE__ "Group with unknown order")
        else
            Error(perror __SOURCE_FILE__ __LINE__ "Subgroup too small")
    else
        Error (perror __SOURCE_FILE__ __LINE__ "Group with small order")

let check_p_g_q (conf:nat) (minPl:nat) (minQl:nat) pbytes gbytes qbytes : (string, bool) optResult =
    let p = new BigInteger(1, cbytes pbytes)
    let q = new BigInteger(1, cbytes qbytes)
    let pm1 = p.Subtract(BigInteger.One) in
    let q' = pm1.Divide(BigInteger.Two) in
    if q.Equals(q') then
        // Potentially a safe prime, do the light check
        match check_p_g conf minPl minQl pbytes gbytes with
        | Error(x) -> Error(x)
        | Correct(_) -> correct(true)
    else
        if minPl <= p.BitLength && minQl <= q.BitLength then
            if p.IsProbablePrime(conf) && q.IsProbablePrime(conf) then
                if check_element
                    {dhp=pbytes; dhg=gbytes; dhq=qbytes; safe_prime=false}
                    gbytes then
                    correct(false)
                else
                    Error (perror __SOURCE_FILE__ __LINE__ "Group with small order")
            else
                Error (perror __SOURCE_FILE__ __LINE__ "Group with unknown order")
        else
            Error(perror __SOURCE_FILE__ __LINE__ "Subgroup too small")

let check_params dhdb conf minSize (pbytes:bytes) (gbytes:bytes) =
    match DHDB.select dhdb (pbytes, gbytes) with
    | None -> // unknown group
        let (minPl,minQl) = minSize in
        match check_p_g conf minPl minQl pbytes gbytes with
        | Error(x) -> Error(x)
        | Correct(qbytes) ->
            let dhdb = DHDB.insert dhdb (pbytes, gbytes) (qbytes, true) in
            correct (dhdb,{dhp = pbytes; dhg = gbytes; dhq = qbytes; safe_prime = true})
    | Some(qbytes,safe_prime) -> // known group
        let p = new BigInteger(1, cbytes pbytes) in
        let q = new BigInteger(1, cbytes qbytes) in
        let (minPl,minQl) = minSize in
        if p.BitLength < minPl || q.BitLength < minQl then
            Error(perror __SOURCE_FILE__ __LINE__ "Subgroup too small")
        else
            correct (dhdb,{dhp = pbytes; dhg = gbytes ; dhq = qbytes ; safe_prime = safe_prime})

(* ------------------------------------------------------------------------ *)
let gen_key_int dhparams =
    let kparams  = new DHKeyGenerationParameters(new SecureRandom(), dhparams) in
    let kgen     = new DHKeyPairGenerator() in
    kgen.Init(kparams);
    let kpair = kgen.GenerateKeyPair() in
    let pkey  = (kpair.Public  :?> DHPublicKeyParameters ) in
    let skey  = (kpair.Private :?> DHPrivateKeyParameters) in
    (abytes (skey.X.ToByteArrayUnsigned()), abytes (pkey.Y.ToByteArrayUnsigned()))

let gen_key dhp: dhskey * dhpkey =

    let dhparams = new DHParameters(new BigInteger(1, cbytes dhp.dhp), new BigInteger(1, cbytes dhp.dhg), new BigInteger(1, cbytes dhp.dhq)) in
    gen_key_int dhparams

let gen_key_pg p g =
    let dhparams = new DHParameters(new BigInteger(1, cbytes p), new BigInteger(1, cbytes g)) in
    gen_key_int dhparams

(* ------------------------------------------------------------------------ *)
let agreement p (x : dhskey) (y : dhpkey) : bytes =
    let x = new BigInteger(1, cbytes x) in
    let y = new BigInteger(1, cbytes y) in
    let p = new BigInteger(1, cbytes p) in
        abytes (y.ModPow(x, p).ToByteArrayUnsigned())

(* ------------------------------------------------------------------------ *)
let PEM_DH_PARAMETERS_HEADER = "DH PARAMETERS"

(* ------------------------------------------------------------------------ *)
let load_params (stream : Stream) : bytes*bytes =
    let reader = new PemReader(new StreamReader(stream)) in
    let obj    = reader.ReadPemObject() in

    if obj.Type <> PEM_DH_PARAMETERS_HEADER then
        raise (new SecurityUtilityException(sprintf "Wrong PEM header. Got %s" obj.Type))
    else
    let obj = DerSequence.GetInstance(Asn1Object.FromByteArray(obj.Content)) in

    if obj.Count <> 2 then
        raise (new SecurityUtilityException(sprintf "Unexpected number of DH parameters. Got %d" obj.Count))
    else
    (abytes (DerInteger.GetInstance(obj.Item(0)).PositiveValue.ToByteArrayUnsigned()),
     abytes (DerInteger.GetInstance(obj.Item(1)).PositiveValue.ToByteArrayUnsigned()))

(* ------------------------------------------------------------------------ *)
let load_params_from_file (file : string) : bytes * bytes =
    let filestream = new FileStream(file, FileMode.Open, FileAccess.Read) in
    try
        load_params filestream
    finally
        filestream.Close()

(* ------------------------------------------------------------------------ *)
let load_default_params pem_file dhdb conf minSize =
    let p,g = load_params_from_file pem_file in
    match check_params dhdb conf minSize p g with
    | Error(x) -> raise (new SecurityUtilityException(x))
    | Correct(res) -> res

(* Constant groups as defined in draft-ietf-tls-negotiated-dl-dhe *)
let dhe2432 =
    let p = new BigInteger(
                "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE13098533C8B3FFFFFFFFFFFFFFFF",
                16) in
    let g = BigInteger.Two in
    let q = p.Subtract(BigInteger.One).Divide(BigInteger.Two) in // (p-1)/2
    {dhp = abytes (p.ToByteArrayUnsigned());
     dhg = abytes (g.ToByteArrayUnsigned());
     dhq = abytes (q.ToByteArrayUnsigned());
     safe_prime = true}
let dhe3072 =
    let p = new BigInteger(
                "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF",
                16) in
    let g = BigInteger.Two in
    let q = p.Subtract(BigInteger.One).Divide(BigInteger.Two) in // (p-1)/2
    {dhp = abytes (p.ToByteArrayUnsigned());
     dhg = abytes (g.ToByteArrayUnsigned());
     dhq = abytes (q.ToByteArrayUnsigned());
     safe_prime = true}
let dhe4096 =
    let p = new BigInteger(
                "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF",
                16) in
    let g = BigInteger.Two in
    let q = p.Subtract(BigInteger.One).Divide(BigInteger.Two) in // (p-1)/2
    {dhp = abytes (p.ToByteArrayUnsigned());
     dhg = abytes (g.ToByteArrayUnsigned());
     dhq = abytes (q.ToByteArrayUnsigned());
     safe_prime = true}
let dhe6144 =
    let p = new BigInteger(
                "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF",
                16) in
    let g = BigInteger.Two in
    let q = p.Subtract(BigInteger.One).Divide(BigInteger.Two) in // (p-1)/2
    {dhp = abytes (p.ToByteArrayUnsigned());
     dhg = abytes (g.ToByteArrayUnsigned());
     dhq = abytes (q.ToByteArrayUnsigned());
     safe_prime = true}
let dhe8192 =
    let p = new BigInteger(
                "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538CD72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C8381E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E0B8CC3BDF64B10EF86B63142A3AB8829555B2F747C932665CB2C0F1CC01BD70229388839D2AF05E454504AC78B7582822846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C51AA691E0E423CFC99E9E31650C1217B624816CDAD9A95F9D5B8019488D9C0A0A1FE3075A577E23183F81D4A3F2FA4571EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D97D11D49F7A8443D0822E506A9F4614E011E2A94838FF88CD68C8BB7C5C6424CFFFFFFFFFFFFFFFF",
                16) in
    let g = BigInteger.Two in
    let q = p.Subtract(BigInteger.One).Divide(BigInteger.Two) in // (p-1)/2
    {dhp = abytes (p.ToByteArrayUnsigned());
     dhg = abytes (g.ToByteArrayUnsigned());
     dhq = abytes (q.ToByteArrayUnsigned());
     safe_prime = true}
