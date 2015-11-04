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

module Date

type DateTime = DT of System.DateTime
type TimeSpan = TS of System.TimeSpan
let now () = DT (System.DateTime.Now)
let dawn = new System.DateTime(1970, 1, 1)
let secondsFromDawn () = (int32) (System.DateTime.UtcNow - dawn).TotalSeconds
let newTimeSpan d h m s = TS (new System.TimeSpan(d,h,m,s))
let addTimeSpan (DT(a)) (TS(b)) = DT (a + b)
let greaterDateTime (DT(a)) (DT(b)) = a > b
