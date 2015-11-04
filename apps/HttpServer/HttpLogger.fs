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

module HttpLogger

open System
open System.Threading

type level = DEBUG | INFO | ERROR

type HttpLogger () =
    static let mutable loglevel : level = INFO

    static member private lock = new Object ()

    static member Level
        with get ()       = loglevel
        and  set newlevel = loglevel <- newlevel;

    static member private WriteLine (s : string) =
        lock HttpLogger.lock (fun () -> Console.WriteLine(s))

    static member Log level message =
        if level >= loglevel then begin
            HttpLogger.WriteLine
                (sprintf "[Thread %4d] [%A] %s"
                    Thread.CurrentThread.ManagedThreadId
                    DateTime.Now
                    message)
        end

    static member Debug message =
        HttpLogger.Log DEBUG message

    static member Info message =
        HttpLogger.Log INFO message

    static member Error message =
        HttpLogger.Log ERROR message
