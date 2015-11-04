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

module FlexApps.Parsing

open TLSConstants

type ScenarioOpt    = // Normal
                      | FullHandshake
                      // SmackTLS
                      | SmackTLS
                      // Attacks
                      | Attack_FragmentedAlert | Attack_Alert_Warning | Attack_FragmentedClientHello
                      | Attack_SKIP_EarlyFinished | Attack_EarlyCCS | Attack_EarlyCCSMITM | Attack_TripleHandshake | Attack_SmallSubgroup | Attack_EarlyResume
                      | Attack_Logjam
                      // Script
                      | Script

type RoleOpt        = RoleClient | RoleServer | RoleMITM
type LogLevelOpt    = LogLevelTrace | LogLevelDebug | LogLevelInfo | LogLevelNone
type KeyExchangeOpt = KeyExchangeRSA | KeyExchangeDHE | KeyExchangeECDHE

type CommandLineOpts = {
    scenario      : option<ScenarioOpt>;
    role          : option<RoleOpt>;
    kex           : option<KeyExchangeOpt>;
    connect_addr  : string;
    connect_port  : int;
    connect_cert  : option<string>;
    connect_cert_mitls : string;
    listen_addr   : string;
    listen_port   : int;
    listen_cert   : string;
    delay         : int;
    resume        : bool;
    renego        : bool;
    timeout       : int;
    testing       : bool;
    verbosity     : LogLevelOpt;
}

let defaultOpts = {
    scenario = None;
    role = None;
    kex = None;
    connect_addr = "localhost";
    connect_port = 443;
    connect_cert = None;
    connect_cert_mitls = "rsa.cert-02.mitls.org";
    listen_addr = "localhost";
    listen_port = 4433;
    listen_cert = "rsa.cert-01.mitls.org";
    delay = 0;
    resume = false;
    renego = false;
    timeout = 7500;
    testing = false;
    verbosity = LogLevelInfo;
}

let stdout = System.Console.Out
let stderr = System.Console.Error

let flexbanner w =
    fprintf w "\n    --- FlexTLS Command Line Interface ---\n";
    fprintf w "\n"

let flexinfo w =
    flexbanner w;
    fprintf w "\n";
    fprintf w "  - Version     : FlexTLS 0.2.0\n";
    fprintf w "                  July 31, 2015\n";
    fprintf w "\n";
    fprintf w "  - Authors     : Benjamin Beurdouche & Alfredo Pironti\n";
    fprintf w "                  INRIA Paris-Rocquencourt\n";
    fprintf w "                  Team Prosecco\n";
    fprintf w "\n";
    fprintf w "  - Website     : http://www.mitls.org\n";
    fprintf w "                  http://www.smacktls.com\n"

let flexhelp w =
    flexbanner w;
    fprintf w "  -h --help     :    This help message\n";
    fprintf w "  -v --version  :    Infos about this software\n";
    fprintf w "\n";
    fprintf w "  -s --scenario : *  Scenario to execute\n";
    fprintf w "                     - Full Handshake                {fh}\n";
    fprintf w "                     - Script.fs                     {script}\n";
    fprintf w "                     - SmackTLS                      {smacktls}\n";
    fprintf w "                     - Attacks\n";
    fprintf w "                         Warning alert               {wal,warningalert}\n";
    fprintf w "                         Fragmented alert            {fal,fragmentedalert}\n";
    fprintf w "                         Fragmented Client Hello     {fch,fragmentedch}\n";
    fprintf w "                         Early CCS                   {eccs,earlyccs}\n";
    fprintf w "                         Early CCS (MITM)            {eccsm,earlyccsmitm}\n";
    fprintf w "                         Early Finished SKIP         {efin,earlyfinished}\n";
    fprintf w "                         Triple Handshake (MITM)     {ths,triplehandshake}\n";
    fprintf w "                         Small Subgroup              {sgp,smallsubgroup}\n";
    fprintf w "                         Early Resume                {eres,earlyresume}\n";
    fprintf w "                         Logjam                      {lj,logjam}\n";
    fprintf w "  --connect     : [] Connect to address (or domain) and port    (default : %s:%d)\n" defaultOpts.connect_addr defaultOpts.connect_port;
    fprintf w "  --client-cert : [] Use client authentication with the given CN\n";
    fprintf w "  --accept      : [] Accept address (or domain) and port        (default : %s:%d)\n" defaultOpts.listen_addr defaultOpts.listen_port;
    fprintf w "  --server-cert : [] Certificate CN to use if Server            (default : %s)\n" defaultOpts.listen_cert;
    fprintf w "  --delay       : [] Wait a delay between SmackTLS scenarios    (default : %dms)\n" defaultOpts.delay;
    fprintf w "\n";
    fprintf w "  *** Options for full handshake scenario ***\n";
    fprintf w "  -r --role     : []  Role\n";
    fprintf w "                     - Client                        {c,C,Client}  (default)\n";
    fprintf w "                     - Server                        {s,S,Server}\n";
    fprintf w "                     - Both                          {m,M,MITM}\n";
    fprintf w "  -k --kex      : []  Key exchange\n";
    fprintf w "                     - RSA                           {rsa,RSA}   (default)\n";
    fprintf w "                     - DHE                           {dhe,DHE}\n";
    fprintf w "                     - ECDHE                         {ec,ecdhe,ECDHE}\n";
    fprintf w "\n";
    fprintf w " *  =>  Require an argument\n";
    fprintf w " [] =>  Default will be used if not provided\n"

let private is_int (s:string) = try ignore(int s); true with _ -> false

let private parse_scenario =
  function  | "fullhandshake" | "fh"   -> Some FullHandshake
            | "script"                 -> Some Script
            | "smacktls"               -> Some SmackTLS
            | "warningalert" | "wal"   -> Some Attack_Alert_Warning
            | "fragmentedch" | "fch"   -> Some Attack_FragmentedClientHello
            | "fragmentedalert"| "fal" -> Some Attack_FragmentedAlert
            | "earlyccs" | "eccs"      -> Some Attack_EarlyCCS
            | "earlyccsmitm" | "eccsm" -> Some Attack_EarlyCCSMITM
            | "earlyfinished" | "efin" -> Some Attack_SKIP_EarlyFinished
            | "triplehandshake"| "ths" -> Some Attack_TripleHandshake
            | "smallsubgroup"| "sgp"   -> Some Attack_SmallSubgroup
            | "earlyresume" | "eres"   -> Some Attack_EarlyResume
            | "logjam" | "lj"          -> Some Attack_Logjam
            | _                        -> None

let private parse_address (s:string) =
  match s.Split [|':'|] with
  | [| a; p |] when is_int p && int p > 0 -> Some(a, int p)
  | [| a    |]                            -> Some(a, 443)
  | _                                     -> flexhelp stderr; eprintf "ERROR : invalid connect address:port\n"; None

let rec innerParseCommandLineOpts parsedArgs args : option<CommandLineOpts> =
      match args with
        | []                        -> Some(parsedArgs)
        | ("-h"|"--help")::_        -> flexhelp stdout; None
        | ("-v"|"--version")::_     -> flexinfo stdout; None
        | ("-s"|"--scenario")::s::t ->
            (match parse_scenario s with
            | Some sc ->
                  let t =
                    match t with
                    | "TLS1.2"::t when sc = SmackTLS -> SmackTLS.spv <- Some TLS_1p2;  t
                    | "TLS1.1"::t when sc = SmackTLS -> SmackTLS.spv <- Some TLS_1p1;  t
                    | "TLS1.0"::t when sc = SmackTLS -> SmackTLS.spv <- Some TLS_1p0;  t
                    | "SSL3.0"::t when sc = SmackTLS -> SmackTLS.spv <- Some SSL_3p0;  t
                    | t -> t in
                  let t =
                    match t with
                    | n::t when sc = SmackTLS && is_int n -> SmackTLS.focus <- Some (int n);  t
                    | t -> t in
                  innerParseCommandLineOpts {parsedArgs with scenario = Some sc } t

            | None -> flexhelp stderr; eprintf "ERROR : invalid scenario provided: %s\n" s; None)

        | ("-r"|"--role")::r::t ->    // consider deprecating the role options...
            (match r with
            | "Client"|"client"|"C"|"c" -> innerParseCommandLineOpts {parsedArgs with role = Some RoleClient } t
            | "Server"|"server"|"S"|"s" -> innerParseCommandLineOpts {parsedArgs with role = Some RoleServer } t
            | "MITM"|"M"|"m"            -> innerParseCommandLineOpts {parsedArgs with role = Some RoleMITM   } t
            | _                         -> flexhelp stderr; eprintf "ERROR : invalid role provided: %s\n" r; None)

        | "--connect"::addr::t ->
                let parsedArgs = if parsedArgs.role = None then { parsedArgs with role = Some RoleClient } else parsedArgs in
                (match parse_address addr with
                | Some(a,p) -> innerParseCommandLineOpts {parsedArgs with connect_addr = a; connect_port = int p} t
                | None      -> flexhelp stderr; eprintf "ERROR : invalid connect address: %s\n" addr; None)

        | "--accept"::addr::t ->
                let parsedArgs = if parsedArgs.role = None then { parsedArgs with role = Some RoleServer } else parsedArgs in
                (match parse_address addr with
                | Some(a,p) -> innerParseCommandLineOpts {parsedArgs with listen_addr = a; listen_port = p} t
                | None      -> flexhelp stderr; eprintf "ERROR : invalid accept address: %s\n" addr; None)

        | ("-k"|"--kex")::kex::t ->
            (match kex with
            | "RSA"   | "rsa"   -> innerParseCommandLineOpts {parsedArgs with kex = Some KeyExchangeRSA } t
            | "DHE"   | "dhe"   -> innerParseCommandLineOpts {parsedArgs with kex = Some KeyExchangeDHE } t
            | "ECDHE" | "ecdhe" | "ec" -> innerParseCommandLineOpts {parsedArgs with kex = Some KeyExchangeECDHE } t
            | _                 -> flexhelp stderr; eprintf "ERROR : invalid key exchange provided: %s\n" kex; None)

        | "--delay"::delay::t ->
            (match System.Int32.TryParse delay with
            | true,delay when parsedArgs.scenario = Some SmackTLS && int delay > 0 -> innerParseCommandLineOpts {parsedArgs with delay = delay} t
            | false,_ -> flexhelp stderr; eprintf "ERROR : invalid delay provided: %s\n" delay; None)

        | "--client-cert"::cn::t ->
            (match cn with
            | "mitls" -> innerParseCommandLineOpts {parsedArgs with connect_cert = Some(defaultOpts.connect_cert_mitls)} t
            | _ -> innerParseCommandLineOpts {parsedArgs with connect_cert = Some(cn)} t)
        | "--server-cert"::cn::t -> innerParseCommandLineOpts {parsedArgs with listen_cert = cn} t
        | "--resume"::t          -> innerParseCommandLineOpts {parsedArgs with resume = true} t
        | "--renego"::t          -> innerParseCommandLineOpts {parsedArgs with renego = true} t
        | _    -> flexhelp stderr; eprintf "ERROR : unrecognized options: %A\n" args; None
