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

module DER

// ------------------------------------------------------------------------
open System
open Org.BouncyCastle.Asn1

// ------------------------------------------------------------------------
type dervalue =
    | Bool       of bool
    | Bytes      of Bytes.bytes
    | Utf8String of string
    | Sequence   of dervalue list

// ------------------------------------------------------------------------
exception DerEncodingFailure
exception DerDecodingFailure

// ------------------------------------------------------------------------
let get_asn1_object (bytes : byte[]) : Asn1Object =
    try
        let stream = new Asn1InputStream(bytes)
        let obj    = stream.ReadObject()

        if stream.Position <> int64(bytes.Length) then null else obj

    with _ ->
        null

// ------------------------------------------------------------------------
let rec encode_r = function
    | Bytes      bytes  -> (new DerOctetString(Bytes.cbytes bytes)  :> Asn1Encodable)
    | Utf8String string -> (new DerUtf8String (string) :> Asn1Encodable)

    | Bool  b ->
        let b = if b then 0xffuy else 0x00uy in
            ((new DerBoolean [|b|]) :> Asn1Encodable)

    | Sequence   seq    ->
        let seq = seq |> List.map encode_r in
            (new DerSequence(Array.ofList seq) :> Asn1Encodable)

let encode (x : dervalue) =
    try
        Bytes.abytes ((encode_r x).GetDerEncoded())
    with _ ->
        raise DerEncodingFailure

// ------------------------------------------------------------------------
let rec decode_r (o : Asn1Encodable) : dervalue  =
    match o with
    | (:? DerBoolean     as o) -> Bool       (o.IsTrue)
    | (:? DerOctetString as o) -> Bytes      (Bytes.abytes (o.GetOctets()))
    | (:? DerUtf8String  as o) -> Utf8String (o.GetString())
    | (:? DerSequence    as o) -> Sequence   ((Seq.cast o) |> Seq.map decode_r |> Seq.toList)
    | _                        -> raise DerDecodingFailure

let decode (bytes : Bytes.bytes) : dervalue option =
    try
        let obj = get_asn1_object (Bytes.cbytes bytes) in
            Some (decode_r obj)
    with _ ->
        None
