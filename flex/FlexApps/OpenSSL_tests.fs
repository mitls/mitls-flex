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

module OpenSSL_tests

open FlexTLS
open FlexClientHello
open FlexRecord
open FlexConnection

let opensslTest myport dst port =

    // Start listening on localhost
    let st,_ = FlexConnection.serverOpenTcpConnection("127.0.0.1",port=myport) in
    // Get a client hello from a fully fledged implementation
    let st,_,ch = FlexClientHello.receive(st) in

    // Connect to victim
    let st,cfg = FlexConnection.clientOpenTcpConnection(dst,port=port) in
    // Forward the received client hello
    let _ = FlexRecord.send(st.ns,st.write.epoch,st.write.record,TLSConstants.Handshake,ch.payload,(FlexClientHello.getPV ch)) in

    // ... add here additional standard HS messages ...

    // Send the same client hello as before, with no extensions
    let ch = {ch with ext = Some([])} in
    let st,nsc,ch = FlexClientHello.send(st,ch) in

    // ... add here additional standard HS messages ...

    ()
