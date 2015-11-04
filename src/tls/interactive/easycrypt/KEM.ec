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

(*
 * Proof of Theorem 1 in http://eprint.iacr.org/2014/182
 *
 * Theorem: if the pre-master secret KEM used in the TLS handshake is
 * both One-Way and Non-Randomizable under Plaintext-Checking Attacks,
 * then the master secret KEM, seen as an agile labeled KEM, is
 * Indistinguishable under Replayable Chosen-Ciphertext Attacks in the
 * ROM for the underlying agile KEF.
 *
 * The definition of the master secret KEM includes the countermeasure
 * against padding-oracle attacks (aka Bleichenbecher attacks) used for
 * RSA encryption with PKCS#1 padding: when decryption fails, a value for
 * the master secret is computed anyway using a random pre-master secret.
 *
 *)

require import Bool.
require import Int.
require import Real.
require import Pair.
require import FMap.
require import ISet.
require import ROM.

import Finite.
import FSet.
import Option.

(* Bare minimum *)
prover "Alt-Ergo" "Z3".

theory Agile_KEF.

  type parameter.
  type secret.
  type key.

  module type KEF = {
    proc * init() : unit
    proc extract(p:parameter, s:secret) : key
  }.

  module type Oracle = {
    proc extract(p:parameter, s:secret) : key
  }.

end Agile_KEF.

theory Agile_Labeled_KEM.

  type parameter.
  type pkey.
  type skey.
  type key.
  type label.
  type ciphertext.

  module type KEM = {
    proc init() : unit
    proc keygen() : pkey * skey
    proc enc(p:parameter, pk:pkey, t:label) : key * ciphertext
    proc dec(p:parameter, sk:skey, t:label, c:ciphertext) : key option
  }.

  theory RCCA.

    const P : parameter set.

    const pp : parameter.

    op key : key distr.

    module type Oracle = {
      proc dec(p:parameter, t:label, c:ciphertext) : key option
    }.

    module type Adversary(O:Oracle) = {
      proc choose(pk:pkey) : label
      proc guess(c:ciphertext, k:key) : bool
    }.

    module W = {
      var sk : skey
      var keys : key set
      var labels : label set
      var guess : bool
      var t : label
    }.

    module Wrap(KEM:KEM) : Oracle = {
      proc dec(p:parameter, t:label, c:ciphertext) : key option = {
        var k : key;
        var maybe_k : key option = None;
        if (!mem t W.labels /\ mem p P) {
          W.labels = add t W.labels;
          maybe_k = KEM.dec(p, W.sk, t, c);
          maybe_k =
           if (W.guess => !mem (oget maybe_k) W.keys \/ t <> W.t)
           then maybe_k else None;
        }
        return maybe_k;
      }
    }.

    module RCCA(KEM:KEM, A:Adversary) = {
      module O = Wrap(KEM)
      module A = A(O)

      proc main() : bool = {
        var b, b', valid : bool;
        var k0, k1 : key;
        var c : ciphertext;
        var pk : pkey;
        KEM.init();
        (pk, W.sk) = KEM.keygen();
        W.keys = FSet.empty;
        W.labels = FSet.empty;
        W.t = pick FSet.empty;
        W.guess = false;
        W.t = A.choose(pk);
        valid = !mem W.t W.labels;
        (k0, c) = KEM.enc(pp, pk, W.t);
        k1 = $key;
        b = ${0,1};
        W.keys = add k0 (add k1 W.keys);
        W.guess = true;
        b' = A.guess(c, if b then k1 else k0);
        return (b = b' /\ valid);
      }
    }.

  end RCCA.

  theory PCA.

    const P : parameter set.

    const pp : parameter.

    module type Oracle = {
      proc check(p:parameter, k:key, t:label, c:ciphertext) : bool
    }.

    module type OW_Adversary(O:Oracle) = {
      proc choose(pk:pkey) : label
      proc guess(c:ciphertext) : key
    }.

    module V = { var sk : skey }.

    module Wrap(KEM:KEM) : Oracle = {
      proc check(p:parameter, k:key, t:label, c:ciphertext) : bool = {
        var maybe_k : key option;
        maybe_k = KEM.dec(p, V.sk, t, c);
        return (maybe_k = Some k);
      }
    }.

    module OW_PCA(KEM:KEM, A:OW_Adversary) = {
      module O = Wrap(KEM)
      module A = A(O)

      proc main() : bool = {
        var pk : pkey;
        var t : label;
        var k, k' : key;
        var c : ciphertext;
        KEM.init();
        (pk, V.sk) = KEM.keygen();
        t = A.choose(pk);
        (k, c) = KEM.enc(pp, pk, t);
        k' = A.guess(c);
        return (k = k');
      }
    }.

    module type NR_Adversary(O:Oracle) = {
      proc choose(pk:pkey) : label
      proc guess(c:ciphertext) : ciphertext
    }.

    module NR_PCA(KEM:KEM, A:NR_Adversary) = {
      module O = Wrap(KEM)
      module A = A(O)

      proc main() : bool = {
        var pk : pkey;
        var t : label;
        var p : parameter;
        var k : key;
        var maybe_k : key option;
        var c, c' : ciphertext;
        KEM.init();
        (pk, V.sk) = KEM.keygen();
        t = A.choose(pk);
        (k, c) = KEM.enc(pp, pk, t);
        c' = A.guess(c);
        maybe_k = KEM.dec(pp, V.sk, t, c');
        return (c <> c' /\ maybe_k = Some k);
      }
    }.

  end PCA.

end Agile_Labeled_KEM.

type hash.
type version.
type label.
type pms.
type ms.

op key : ms distr.

axiom key_lossless : Distr.weight key = 1%r.

op dpms : version -> pms distr.

axiom dpms_lossless : forall pv, Distr.weight (dpms pv) = 1%r.

(* Theory for agile and labeled master-secret KEM *)
clone import Agile_Labeled_KEM as Outer_KEM with
  type parameter  <- version * hash,
  type label      <- label,
  type key        <- ms,
  op RCCA.key     <- key.

(* Theory for pre-master secret KEM with protocol version as agility param. *)
clone Agile_Labeled_KEM as Inner_KEM with
  type parameter  <- version,
  type pkey       <- Outer_KEM.pkey,
  type skey       <- Outer_KEM.skey,
  type ciphertext <- Outer_KEM.ciphertext,
  type label      <- unit,
  type key        <- pms,
  op PCA.pp       <- fst Outer_KEM.RCCA.pp.

import Inner_KEM.

(* Theory for agile KEF, indexed by a hash algorithm identifier *)
clone Agile_KEF as KEF with
  type parameter <- version * hash,
  type secret    <- pms * label,
  type key       <- ms.

(* Used for the transformation from RCCA0 to RCCA1 *)
clone LazyEager as LE with
  type from  <- version * label,
  type to    <- pms,
  op dsample <- fun (p:version * label), dpms (fst p).

(* TLS master secret KEM *)
module KEM(KEF:KEF.KEF, PMS_KEM:Inner_KEM.KEM) : Outer_KEM.KEM = {
  proc init() : unit = {
    PMS_KEM.init();
    KEF.init();
  }

  proc keygen() : pkey * skey = {
    var pk : pkey;
    var sk : skey;
    (pk, sk) = PMS_KEM.keygen();
    return (pk, sk);
  }

  proc enc(p:version * hash, pk:pkey, t:label) : ms * ciphertext = {
    var pms : pms;
    var ms : ms;
    var c : ciphertext;
    var pv : version;
    var h : hash;
    (pv, h) = p;
    (pms, c) = PMS_KEM.enc(pv, pk, ());
    ms = KEF.extract((pv, h), (pms, t));
    return (ms, c);
  }

  proc dec(p:version * hash, sk:skey, t:label, c:ciphertext) : ms option = {
    var maybe_pms : pms option;
    var pms : pms;
    var ms : ms;
    var pv : version;
    var h : hash;
    (pv, h) = p;
    maybe_pms = PMS_KEM.dec(pv, sk, (), c);
    pms = $dpms pv;
    pms = if maybe_pms = None then pms else oget maybe_pms;
    ms = KEF.extract((pv, h), (pms, t));
    return Some ms;
  }
}.

(* Agile KEF in the ROM *)
module RO_KEF : KEF.KEF = {
  var m : ((version * hash) * (pms * label), ms) map

  proc init() : unit = {
    m = FMap.empty;
  }

  proc extract(p:version * hash, s:pms * label) : ms = {
    if (!in_dom (p, s) m) m.[(p, s)] = $key;
    return oget m.[(p, s)];
  }
}.

lemma lossless_init : islossless RO_KEF.init
by (proc; wp).

lemma lossless_extract : islossless RO_KEF.extract
by (proc; if => //; rnd; skip; smt).

(* RCCA Adversary in the ROM *)
import Outer_KEM.RCCA.

module type Adversary(O1:KEF.Oracle, O2:Oracle) = {
  proc * choose(pk:pkey) : label {O2.dec O1.extract}
  proc guess(c:ciphertext, k:ms) : bool
}.

section.

  declare module PMS_KEM : Inner_KEM.KEM {RO_KEF, RCCA, PCA.NR_PCA, PCA.OW_PCA, LE.Lazy.RO, LE.Eager.RO}.

  (* Assumptions on the Pre-master secret KEM *)
  axiom stateless_pms_kem (x y:glob PMS_KEM) : x = y.

  axiom finite_version : finite univ<:version>.

  axiom finite_labels : finite univ<:label>.

  axiom finite_pms : finite univ<:pms>.

  op keypair : pkey * skey -> bool.

  op decrypt : version -> skey -> ciphertext -> pms option.

  axiom keygen_spec_rel :
    equiv [ PMS_KEM.keygen ~ PMS_KEM.keygen : true ==> ={res} /\ keypair res{1} ].

  axiom enc_spec_rel sk pk pv :
    equiv [ PMS_KEM.enc ~ PMS_KEM.enc :
      p{1} = pv /\ pk{1} = pk /\ ={pk, t} /\ keypair(pk, sk) ==>
      ={res} /\ let (k, c) = res{1} in decrypt pv sk c = Some k ].

  axiom dec_spec _sk _pv _c :
    phoare [ PMS_KEM.dec :
      p = _pv /\ sk = _sk /\ c = _c ==> res = decrypt _pv _sk _c ] = 1%r.

  (* TLS master secret KEM in the ROM for KEF *)
  local module MS_KEM = KEM(RO_KEF, PMS_KEM).

  (* RCCA adversary *)
  declare module A : Adversary {RO_KEF, PMS_KEM, RCCA, PCA.NR_PCA, PCA.OW_PCA, LE.Lazy.RO, LE.Eager.RO}.

  axiom lossless_choose (O1 <: KEF.Oracle {A}) (O2 <: Oracle {A}) :
   islossless O2.dec => islossless O1.extract => islossless A(O1, O2).choose.

  axiom lossless_guess (O1 <: KEF.Oracle {A}) (O2 <: Oracle {A}) :
    islossless O2.dec => islossless O1.extract => islossless A(O1, O2).guess.

  (*
   * Swap call to PMS_KEM.enc with A.choose in main, so as to be able
   * to abort when the challenge pms is queried to extract.
   * In addition, inline definition of MS_KEM.dec in dec oracle, and
   * replace the call to PMS_KEM.dec with its functional spec decrypt.
   *)
  local module RCCA0 = {
    module O = {
      proc dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) {
          W.labels = add t W.labels;
          (pv, h) = p;
          maybe_pms = decrypt pv W.sk c;
          pms = $dpms pv;
          pms = if maybe_pms = None then pms else oget maybe_pms;
          k = RO_KEF.extract((pv, h), (pms, t));
          maybe_k = if (W.guess => !mem k W.keys \/ t <> W.t)
                    then Some k else None;
        }
        return maybe_k;
      }
    }

    module A = A(RO_KEF, O)

    proc main() : bool = {
      var b, b', valid : bool;
      var k0, k1 : ms;
      var c : ciphertext;
      var pk : pkey;
      var pv : version;
      var pms : pms;
      var h : hash;
      MS_KEM.init();
      (pk, W.sk) = MS_KEM.keygen();
      W.keys = FSet.empty;
      W.labels = FSet.empty;
      W.t = pick FSet.empty;
      W.guess = false;
      (pv, h) = pp;
      (pms, c) = PMS_KEM.enc(pv, pk, ());
      W.t = A.choose(pk);
      valid = !mem W.t W.labels;
      k0 = RO_KEF.extract((pv, h), (pms, W.t));
      k1 = $key;
      b = ${0,1};
      W.keys = add k0 (add k1 W.keys);
      W.guess = true;
      b' = A.guess(c, if b then k1 else k0);
      return (b = b' /\ valid);
    }
  }.

  local equiv RCCA_RCCA0_dec :
    RCCA(MS_KEM, A(RO_KEF)).O.dec ~ RCCA0.O.dec :
    ={p, t, c} /\ ={glob W, glob RO_KEF} ==>
    ={res} /\ ={glob W, glob RO_KEF}.
  proof.
    proc; sp; if => //.
    inline KEM(RO_KEF, PMS_KEM).dec; sp.
    seq 1 0 : (={maybe_k, maybe_pms, pv, h, p, t, c, glob W, glob RO_KEF} /\
      maybe_k{1} = None /\
      (maybe_pms = decrypt pv W.sk c){2} /\ (t0 = t){1}).
      exists * sk{1}, pv{1}, c0{1}; elim *; intros sk pv c ? ?.
      by call{1} (dec_spec sk pv c).
    wp; call (_: ={glob W, glob RO_KEF}); first by sim.
    by wp; rnd; skip; progress; smt.
  qed.

  local equiv RCCA_RCCA0 :
    RCCA(MS_KEM, A(RO_KEF)).main ~ RCCA0.main : true ==> ={res}.
  proof.
    proc.
    swap{2} 9 -2.
    call (_: ={glob W, glob RO_KEF}).
      by apply RCCA_RCCA0_dec.
      by proc; sim.
    inline KEM(RO_KEF, PMS_KEM).enc.
    wp; rnd; rnd; wp.
    call (_: ={glob W, glob RO_KEF}); first by sim.
    seq 7 7 : (={pk, glob A, glob W, glob RO_KEF} /\ keypair(pk, W.sk){1}).
    call (_: ={glob W, glob RO_KEF}).
      by apply RCCA_RCCA0_dec.
      by proc; sim.
    inline KEM(RO_KEF, PMS_KEM).init KEM(RO_KEF, PMS_KEM).keygen
           MS_KEM.init RO_KEF.init MS_KEM.keygen.
    wp; call keygen_spec_rel; wp; call (_:true); skip.
    move=> ? ? _.
    rewrite (stateless_pms_kem (glob PMS_KEM){1} (glob PMS_KEM){2}); smt.
    sp; exists * W.sk{1}, pk0{1}, pv{1}; elim *; intros sk pk pv.
    by wp; call (enc_spec_rel sk pk pv); skip; progress; smt.
  qed.

  (* Distinguisher for transformation from lazy to eagerly sampled fake pms's *)
  local module D(Fake:LE.Eager.Types.ARO) : LE.Eager.Types.Dist(Fake) = {
    var m : ((version* hash) * (pms * label), ms) map

    module O1 = {
      proc extract(p:version * hash, s:pms * label) : ms = {
        var pms : pms;
        var t : label;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $key;
        return oget m.[(p, (pms, t))];
      }
    }

    module O2 = {
      proc dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) {
          W.labels = add t W.labels;
          (pv, h) = p;
          maybe_pms = decrypt pv W.sk c;
          if (maybe_pms = None) {
            pms = Fake.o((pv, t));
            k = O1.extract((pv, h), (pms, t));
          }
          else k = O1.extract((pv, h), (oget maybe_pms, t));
          maybe_k = if (W.guess => !mem k W.keys \/ t <> W.t)
                    then Some k else None;
        }
        return maybe_k;
      }
    }

    module A = A(O1, O2)

    proc distinguish() : bool = {
      var b, b', valid : bool;
      var k0, k1 : ms;
      var c : ciphertext;
      var pk : pkey;
      var pv : version;
      var pms : pms;
      var h : hash;
      PMS_KEM.init();
      (pk, W.sk) = MS_KEM.keygen();
      W.keys = FSet.empty;
      W.labels = FSet.empty;
      W.t = pick FSet.empty;
      W.guess = false;
      m = FMap.empty;
      (pv, h) = pp;
      (pms, c) = PMS_KEM.enc(pv, pk, ());
      W.t = A.choose(pk);
      valid = !mem W.t W.labels;
      k0 = O1.extract((pv, h), (pms, W.t));
      k1 = $key;
      b = ${0,1};
      W.keys = add k0 (add k1 W.keys);
      W.guess = true;
      b' = A.guess(c, if b then k1 else k0);
      return (b = b' /\ valid);
    }
  }.

  (* Here is where the condition !mem t labels in dec is used *)
  local equiv RCCA0_Lazy :
   RCCA0.main ~ LE.Eager.Types.IND(LE.Lazy.RO, D).main : true ==> ={res}.
  proof.
    proc.
    inline LE.Eager.Types.IND(LE.Lazy.RO, D).D.distinguish
           MS_KEM.init MS_KEM.keygen RO_KEF.init; wp.
    call (_:
      ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
      (forall t, in_dom t LE.Lazy.RO.m => mem (snd t) W.labels){2}).
    proc.
      sp; if => //; sp; if{2}; wp.
      call (_:
        ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
        (forall t, in_dom t LE.Lazy.RO.m => mem (snd t) W.labels){2}).
      by sp; if => //; try rnd.
      by inline LE.Lazy.RO.o; wp; sp; rnd; skip; progress; smt.
      call (_:
        ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
        (forall t, in_dom t LE.Lazy.RO.m => mem (snd t) W.labels){2}).
      by sp; if => //; try rnd.
      by wp; rnd{1}; skip; progress; smt.
    by proc; sp; if => //; try rnd.
    wp; rnd; rnd.
    call (_:
      ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
      (forall t, in_dom t LE.Lazy.RO.m => mem (snd t) W.labels){2}).
    by sp; if => //; try rnd.
    wp.
    call (_:
      ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
      (forall t, in_dom t LE.Lazy.RO.m => mem (snd t) W.labels){2}).
    proc.
      sp; if => //; sp; if{2}; wp.
      call (_:
        ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
        (forall t, in_dom t LE.Lazy.RO.m => mem (snd t) W.labels){2}).
      by sp; if => //; try rnd.
      by inline LE.Lazy.RO.o; wp; sp; rnd; skip; progress; smt.
      call (_:
        ={glob W} /\ RO_KEF.m{1} = D.m{2} /\
        (forall t, in_dom t LE.Lazy.RO.m => mem (snd t) W.labels){2}).
      by sp; if => //; try rnd.
      by wp; rnd{1}; skip; progress; smt.
    by proc; sp; if => //; try rnd.
    wp; call (_: true); wp; call (_: true); wp; call (_: true); wp.
    inline LE.Lazy.RO.init; wp; skip; progress.
      by apply stateless_pms_kem.
      by smt.
  qed.

  (* Eager version of RCCA0 *)
  local module RCCA1 = {
    var m : ((version * hash) * (pms * label), ms) map
    var fake : (version * label, pms) map

    module O1 = {
      proc extract(p:version * hash, s:pms * label) : ms = {
        var pms : pms;
        var t : label;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $key;
        return oget m.[(p, (pms, t))];
      }
    }

    module O2 = {
      proc dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) {
          W.labels = add t W.labels;
          (pv, h) = p;
          maybe_pms = decrypt pv W.sk c;
          if (maybe_pms = None) {
            pms = oget fake.[(pv, t)];
            k = O1.extract((pv, h), (pms, t));
          }
          else k = O1.extract((pv, h), (oget maybe_pms, t));
          maybe_k = if (W.guess => !mem k W.keys \/ t <> W.t)
                    then Some k else None;
        }
        return maybe_k;
      }
    }

    module A = A(O1, O2)

    proc sample() : unit = {
      var t : version * label;
      var labels = toFSet univ;
      fake = FMap.empty;
      while (labels <> FSet.empty) {
        t = pick labels;
        fake.[t] = $dpms (fst t);
        labels = rm t labels;
      }
    }

    proc main() : bool = {
      var b, b', valid : bool;
      var k0, k1 : ms;
      var c : ciphertext;
      var pk : pkey;
      var pv : version;
      var pms : pms;
      var h : hash;
      sample();
      PMS_KEM.init();
      (pk, W.sk) = MS_KEM.keygen();
      W.keys = FSet.empty;
      W.labels = FSet.empty;
      W.t = pick FSet.empty;
      W.guess = false;
      m = FMap.empty;
      (pv, h) = pp;
      (pms, c) = PMS_KEM.enc(pv, pk, ());
      W.t = A.choose(pk);
      valid = !mem W.t W.labels;
      k0 = O1.extract((pv, h), (pms, W.t));
      k1 = $key;
      b = ${0,1};
      W.keys = add k0 (add k1 W.keys);
      W.guess = true;
      b' = A.guess(c, if b then k1 else k0);
      return (b = b' /\ valid);
    }
  }.

  local equiv Eager_RCCA1 :
    LE.Eager.Types.IND(LE.Eager.RO, D).main ~ RCCA1.main : true ==> ={res}.
  proof.
    proc.
    inline LE.Eager.Types.IND(LE.Eager.RO, D).D.distinguish
           MS_KEM.init MS_KEM.keygen RO_KEF.init; wp.
    call (_:
      ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
    proc.
      sp; if => //; sp; if => //; wp.
      call (_:
        ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
      by sp; if => //; try rnd.
      by inline LE.Eager.RO.o; wp.
      call (_:
        ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}) => //.
      by sp; if => //; try rnd.
    by proc; sp; if => //; try rnd.
    wp; rnd; rnd.
    call (_:
      ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
    by sp; if => //; try rnd.
    wp.
    call (_:
      ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
    proc.
      sp; if => //; sp; if => //; wp.
      call (_:
        ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}).
      by sp; if => //; try rnd.
      by inline LE.Eager.RO.o; wp.
      call (_:
        ={glob W} /\ D.m{1} = RCCA1.m{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}) => //.
      by sp; if => //; try rnd.
    by proc; sp; if => //; try rnd.
    wp; call (_: true); wp; call (_: true); wp; call (_: true); wp.
    inline LE.Eager.RO.init RCCA1.sample; sp.
    while (work{1} = labels{2} /\ LE.Eager.RO.m{1} = RCCA1.fake{2}) => //.
    by wp; sp; rnd.
    skip=> ? ?.
    by rewrite (stateless_pms_kem (glob PMS_KEM){1} (glob PMS_KEM){2}); smt.
  qed.

  (** TODO: move to ISet *)
  lemma finite_prod:
    finite univ<:'a> =>
    finite univ<:'b> =>
    finite univ<:'a * 'b>.
  proof strict.
  intros=> [A eqA] [B eqB].
  exists (FSet.Product.(**) A B)=> x.
  split=> Hx; last by apply mem_univ.
  by rewrite -FSet.Product.mem_prod -eqA -eqB !mem_univ //.
  qed.
  (***)

  local equiv RCCA0_RCCA1 : RCCA0.main ~ RCCA1.main : true ==> ={res}.
  proof.
    bypr res{1} res{2} => //.
    intros &1 &2 b.
    apply (eq_trans _ Pr[LE.Eager.Types.IND(LE.Lazy.RO, D).main() @ &1: b = res]).
    by byequiv RCCA0_Lazy.
    apply (eq_trans _ Pr[LE.Eager.Types.IND(LE.Eager.RO, D).main() @ &1: b = res]).
    byequiv (LE.eagerRO D _ _) => //.
      by apply finite_prod; smt.
      by smt.
    by byequiv Eager_RCCA1.
  qed.

  local lemma Pr_RCCA0_RCCA1 &m :
    Pr[RCCA0.main() @ &m : res] = Pr[RCCA1.main() @ &m : res].
  proof.
    by byequiv RCCA0_RCCA1.
  qed.

  (*
   * Similar to RCCA1, but the decryption oracle does not query extract when
   * given an invalid ciphertext (i.e. with a randomly generated fake pms)
   *
   * This only makes a difference if the adversary queries extract directly
   * with one of the fake pms's generated internally during decryption in RCCA1.
   *
   *)
  local module RCCA2 = {
    var m : ((version * hash) * (pms * label), ms) map
    var fake : (version * label, pms) map

    module O1 = {
      proc extract(p:version * hash, s:pms * label) : ms = {
        var pms : pms;
        var t : label;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $key;
        return oget m.[(p, (pms, t))];
      }
    }

    module O2 = {
      proc dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t W.labels /\ mem p P) {
          W.labels = add t W.labels;
          (pv, h) = p;
          maybe_pms = decrypt pv W.sk c;
          if (maybe_pms = None) k = $key;
          else k = O1.extract((pv, h), (oget maybe_pms, t));
          maybe_k = if (W.guess => !mem k W.keys \/ t <> W.t)
                    then Some k else None;
        }
        return maybe_k;
      }
    }

    module A = A(O1, O2)

    proc sample() : unit = {
      var t : version * label;
      var labels = toFSet univ;
      fake = FMap.empty;
      while (labels <> FSet.empty) {
        t = pick labels;
        fake.[t] = $dpms (fst t);
        labels = rm t labels;
      }
    }

    proc main() : bool = {
      var b, b', valid : bool;
      var k0, k1 : ms;
      var c : ciphertext;
      var pk : pkey;
      var pv : version;
      var pms : pms;
      var h : hash;
      sample();
      PMS_KEM.init();
      (pk, W.sk) = MS_KEM.keygen();
      W.keys = FSet.empty;
      W.labels = FSet.empty;
      W.t = pick FSet.empty;
      W.guess = false;
      m = FMap.empty;
      (pv, h) = pp;
      (pms, c) = PMS_KEM.enc(pv, pk, ());
      W.t = A.choose(pk);
      valid = !mem W.t W.labels;
      k0 = O1.extract((pv, h), (pms, W.t));
      k1 = $key;
      b = ${0,1};
      W.keys = add k0 (add k1 W.keys);
      W.guess = true;
      b' = A.guess(c, if b then k1 else k0);
      return (b = b' /\ valid);
    }
  }.

  local equiv RCCA1_RCCA2_extract :
    RCCA1.O1.extract ~ RCCA2.O1.extract :
    !(exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2} /\
    ={p, s} /\ ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
    (forall p, in_dom p RCCA1.fake){1} /\
    (forall pv h t,
     in_dom ((pv, h), (oget RCCA1.fake.[(pv, t)], t)) RCCA1.m => mem t W.labels){1} /\
    forall pv h pms t, pms <> oget RCCA1.fake{1}.[(pv, t)] =>
      RCCA1.m{1}.[((pv, h), (pms, t))] = RCCA2.m{2}.[((pv, h), (pms, t))]
    ==>
   !(exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2} =>
      ={res} /\ ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
      (forall p, in_dom p RCCA1.fake){1} /\
      (forall pv h t,
       in_dom ((pv, h), (oget RCCA1.fake.[(pv, t)], t)) RCCA1.m => mem t W.labels){1} /\
      forall pv h pms t, pms <> oget RCCA1.fake{1}.[(pv, t)] =>
        RCCA1.m{1}.[((pv, h), (pms, t))] = RCCA2.m{2}.[((pv, h), (pms, t))].
  proof.
    proc; sp.
    case ((pms = oget RCCA2.fake.[(fst p, t)]){2}).
      (* pms = oget RCCA2.fake[t] *)
      if{1}; if{2}.
        by rnd; skip; progress; smt.
        rnd{1}; skip; progress.
          by smt.
          cut X : exists pv h t,
            in_dom ((pv, h), (oget RCCA2.fake{2}.[(pv, t)], t)) RCCA2.m{2}.
            by exists (fst p{2}), (snd p{2}), t{2}; smt.
            by smt.
          by smt.
          by smt.
        rnd{2}; skip; progress.
          by smt.
          cut X : exists pv h t,
            in_dom ((pv, h), (oget RCCA2.fake{2}.[(pv, t)], t)) RCCA2.m{2}.
            by exists (fst p{2}), (snd p{2}), t{2}; smt.
            by smt.
          by smt.
       skip; progress.
       cut X : exists pv h t,
         in_dom ((pv, h), (oget RCCA2.fake{2}.[(pv, t)], t)) RCCA2.m{2}.
         by exists (fst p{2}), (snd p{2}), t{2}; smt.
         by smt.
      (* pms <> oget RCCA2.fake[t] *)
      if => //.
        progress.
          by cut X := H2 (fst p{2}) (snd p{2}) pms{2} t{2}; smt.
          by cut X := H2 (fst p{2}) (snd p{2}) pms{2} t{2}; smt.
        by rnd; skip; progress; smt.
        skip; progress.
          by cut X := H2 (fst p{2}) (snd p{2}) pms{2} t{2}; smt.
  qed.

  local equiv RCCA1_RCCA2_dec :
    RCCA1.O2.dec ~  RCCA2.O2.dec :
    !(exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2} /\
    ={p, t, c} /\ ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
    (forall p, in_dom p RCCA1.fake){1} /\
    (forall pv h t,
     in_dom ((pv, h), (oget RCCA1.fake.[(pv, t)], t)) RCCA1.m => mem t W.labels){1} /\
    forall pv h pms t, pms <> oget RCCA1.fake{1}.[(pv, t)] =>
      RCCA1.m{1}.[((pv, h), (pms, t))] = RCCA2.m{2}.[((pv, h), (pms, t))]
    ==>
    !(exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2} =>
      ={res} /\ ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
      (forall p, in_dom p RCCA1.fake){1} /\
      (forall pv h t,
       in_dom ((pv, h), (oget RCCA1.fake.[(pv, t)], t)) RCCA1.m => mem t W.labels){1} /\
      forall pv h pms t, pms <> oget RCCA1.fake{1}.[(pv, t)] =>
        RCCA1.m{1}.[((pv, h), (pms, t))] = RCCA2.m{2}.[((pv, h), (pms, t))].
  proof.
    proc; sp; if => //.
      sp; if => //.
        inline RCCA1.O1.extract; wp; sp.
        if{1}.
          by rnd; skip; progress; smt.
          by rnd{2}; skip; progress; smt.
      wp; call RCCA1_RCCA2_extract.
      by skip; progress; smt.
  qed.

  local equiv RCCA1_RCCA2 :
    RCCA1.main ~ RCCA2.main :
    true ==>
    !(exists pv h t,
        in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2} => ={res}.
  proof.
    proc.
    seq 12 12 :
      (!(exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2} =>
      ={glob W, glob A, pk, pv, h, pms, c, valid} /\
      RCCA1.fake{1} = RCCA2.fake{2} /\
      (forall p, in_dom p RCCA1.fake){1} /\
      (forall pv h t,
        in_dom ((pv, h), (oget RCCA1.fake.[(pv, t)], t)) RCCA1.m => mem t W.labels){1} /\
      forall pv h pms t, pms <> oget RCCA1.fake{1}.[(pv, t)] =>
        RCCA1.m{1}.[((pv, h), (pms, t))] = RCCA2.m{2}.[((pv, h), (pms, t))]).
    wp; call (_:
     (exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m),
     ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
     (forall p, in_dom p RCCA1.fake){1} /\
     (forall pv h t,
       in_dom ((pv, h), (oget RCCA1.fake.[(pv, t)], t)) RCCA1.m => mem t W.labels){1} /\
     forall pv h pms t, pms <> oget RCCA1.fake{1}.[(pv, t)] =>
       RCCA1.m{1}.[((pv, h), (pms, t))] = RCCA2.m{2}.[((pv, h), (pms, t))]).
     by apply lossless_choose.
     by apply RCCA1_RCCA2_dec.
     intros &2 ?; proc; sp; if => //.
     wp; sp; inline RCCA1.O1.extract; if.
       by wp; sp; if => //; rnd; skip; smt.
       by wp; sp; if => //; rnd; skip; smt.
     intros &1; proc.
     sp; if; wp; sp => //.
     if.
       by rnd; skip; progress; smt.
       inline RCCA2.O1.extract; wp; sp; if => //.
       by rnd (fun x, true); skip; progress; smt.
       by skip; progress; smt.
     by skip; progress; smt.
     by apply RCCA1_RCCA2_extract.
     by progress; proc; wp; sp; if; try rnd; skip; smt.
     intros _; proc; sp.
     if.
       by rnd (fun x, true); skip; progress; smt.
       by skip; smt.
     wp; call (_: ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2}); wp.
     call (_:RCCA1.fake{1} = RCCA2.fake{2}).
     sim; progress; apply stateless_pms_kem.
     call (_:true); wp.
     call (_:true ==> RCCA1.fake{1} = RCCA2.fake{2} /\
                      forall p, (in_dom p RCCA1.fake){1}).
     proc; sp.
     while (={labels} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
            forall p, (!mem p labels => in_dom p RCCA1.fake){1}).
     by wp; rnd; wp; skip; progress; smt.
     by wp; skip; progress; smt.

     skip=> ? ?.
     by rewrite (stateless_pms_kem (glob PMS_KEM){1} (glob PMS_KEM){2}); progress; smt.

     case ((oget RCCA2.fake.[(pv, W.t)] = pms){2} \/
           exists pv h t, (in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2}).
     seq 1 1 : (exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2}.
     inline RCCA1.O1.extract RCCA2.O1.extract; wp; sp.
     if{1}; if{2}.
       rnd; skip; progress; elim H0 => ?.
         by exists pv{2}, h{2}, W.t{2}; smt.
         by smt.
       by rnd{1}; skip; progress; smt.
       rnd{2}; skip; progress; [smt | elim H0 => ?].
         by exists pv{2}, h{2}, W.t{2}; smt.
         by smt.
       by skip; progress; smt.
     call (_:true, true,
      (exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m){2}).
        by apply lossless_guess.
        by exfalso; smt.
        (* by apply RCCA1_dec_preserves_bad. *)
        progress; proc; sp; if => //.
        wp; sp; inline RCCA1.O1.extract; if.
          by wp; sp; if; try rnd; skip; smt.
          by wp; sp; if; try rnd; skip; smt.
          by skip; smt.
        (* by apply RCCA2_dec_preserves_bad. *)
        progress; proc; sp; if => //.
        wp; sp; inline RCCA1.O1.extract; if.
          by rnd; skip; progress; smt.
          inline RCCA2.O1.extract; wp; sp; if => //.
          by rnd (fun x, true); skip; progress; smt.
          by skip; smt.
        by skip; smt.
        by exfalso.
        (* by apply RCCA1_extract_preserves_bad. *)
        by progress; proc; wp; sp; if; try rnd; skip; smt.
        (* by apply RCCA2_extract_preserves_bad. *)
        progress; proc; sp; if.
          by rnd (fun x, true); skip; progress; smt.
          by skip; smt.
     wp; rnd; rnd; inline RCCA1.O1.extract RCCA2.O1.extract; wp; sp.
     by skip; progress; smt.

    call (_:
     (exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m),
     ={glob W} /\ RCCA1.fake{1} = RCCA2.fake{2} /\
     (forall t, in_dom t RCCA1.fake){1} /\
     (forall pv h t,
       in_dom ((pv, h), (oget RCCA1.fake.[(pv, t)], t)) RCCA1.m => mem t W.labels){1} /\
     forall pv h pms t, pms <> oget RCCA1.fake{1}.[(pv, t)] =>
       RCCA1.m{1}.[((pv, h), (pms, t))] = RCCA2.m{2}.[((pv, h), (pms, t))]).
     by apply lossless_guess.
     by apply RCCA1_RCCA2_dec.
     progress; proc; sp; if => //.
     wp; sp; inline RCCA1.O1.extract; if.
       by wp; sp; if => //; rnd; skip; smt.
       by wp; sp; if => //; rnd; skip; smt.
     intros &1; proc.
     sp; if; wp; sp => //.
     if.
       by rnd ; skip; progress; smt.
       inline RCCA2.O1.extract; wp; sp; if => //.
       by rnd (fun x, true); skip; progress; smt.
       by skip; smt.
     by skip; smt.
     by apply RCCA1_RCCA2_extract.
     by progress; proc; wp; sp; if; try rnd; skip; smt.
     by progress; proc; sp; if; try rnd (fun x, true); skip; progress; smt.

     wp; rnd; rnd.
     inline RCCA1.O1.extract RCCA2.O1.extract; wp; sp.
     if => //.
       intros ? ? ?.
       cut X : !(exists pv h t,
         in_dom ((pv, h), (oget RCCA2.fake{2}.[(pv, t)], t)) RCCA2.m{2}) by smt.
         generalize H; rewrite X => /=; progress; smt.

       rnd; skip; progress; [smt | smt | smt | smt | smt | smt | smt | smt | smt | | | ].
         cut X : !(exists pv h t, in_dom
           ((pv, h), (oget RCCA2.fake{2}.[(pv, t)], t)) RCCA2.m{2}) by smt.
         generalize H; rewrite X => /=; progress.
         by smt.
         cut X : !(exists pv h t, in_dom
           ((pv, h), (oget RCCA2.fake{2}.[(pv, t)], t)) RCCA2.m{2}) by smt.
         generalize H; rewrite X => /=; progress; smt.
         cut X : !(exists pv h t, in_dom
           ((pv, h), (oget RCCA2.fake{2}.[(pv, t)], t)) RCCA2.m{2}) by smt.
         generalize H; rewrite X => /=; progress.
         by smt.
      skip; progress; [smt | smt | smt | smt | smt | smt | | smt | smt | smt | smt | ].
        generalize H; rewrite H6 => /=; progress.
        by smt.
      cut X : !(exists pv h t, in_dom
        ((pv, h), (oget RCCA2.fake{2}.[(pv, t)], t)) RCCA2.m{2}) by smt.
        generalize H; rewrite X => /=; progress.
        generalize H7; rewrite H8 => /=; progress.
  qed.

  local lemma Pr_RCCA1_RCCA2 &m :
    Pr[RCCA1.main() @ &m : res] <=
    Pr[RCCA2.main() @ &m : res] +
    Pr[RCCA2.main() @ &m : exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m].
  proof.
    apply (Trans _
     Pr[RCCA2.main() @ &m : res \/
      exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m]).
    by byequiv RCCA1_RCCA2; smt.
    by rewrite Pr [mu_or]; smt.
  qed.

  (* Maximum number of queries to KEF extract oracle *)
  const qKEF : int.

  axiom qKEF_pos : 0 < qKEF.

  (* Assuming that fake pms's are uniformly random to have a readable bound *)
  axiom dpms_uniform pms : forall pv,
    Distr.mu_x (dpms pv) pms = 1%r / (card (toFSet univ<:pms>))%r.

  local lemma Pr_RCCA2 &m :
    Pr[RCCA2.main() @ &m : exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m] <=
    qKEF%r / (card (toFSet univ<:pms>))%r.
  proof.
   byphoare
      (_:true ==> exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m) => //.
    proc; swap 14; inline RCCA2.sample.
    (*
     * dom(m) = { (pv_1, h_1, pms_1, t_1), ..., (h_q, pms_q, t_q) }
     * q <= q_DEC + q_KEF
     *
     * Pr[exists pv h t, (pv, h, fake[pv, t], t) in dom(m)] <=
     * sum_{pv \in version, t \in labels} sum_{i=1..q}
     *   Pr[fake[pv, t] = pms_i /\ pv = pv_i /\ t = t_i] <=
     * sum_{i=1..q} Pr[fake[pv_i, t_i] = pms_i] = q / |pms|
     *)
    admit.
  qed.

  (* Global variables in RCCA3 and RCCA4 *)
  local module V = {
    var pk : pkey
    var sk : skey
    var keys : ms set
    var labels : label set
    var guess : bool
    var t : label
    var c : ciphertext
    var pms : pms

    proc init() : unit = {
      keys = FSet.empty;
      labels = FSet.empty;
      guess = false;
      t = pick FSet.empty;
      c = pick FSet.empty;
      pms = pick FSet.empty;
    }
  }.

  (*
   * This game "aborts" when the simulation fails, but still uses the PMS KEM
   * secret key to detect when to abort and implement the simulation.
   * However, all uses of the secret key for simulation could be implemented
   * using a plaintext-checking oracle instead.
   *)
  local module RCCA3 = {
    var m : ((version * hash) * (pms * label), ms) map
    var abort : bool

    module O1 = {
      proc extract(p:version * hash, s:pms * label) : ms = {
        var pms : pms;
        var t : label;
        (pms, t) = s;
        abort = abort \/ (p = pp /\ pms = V.pms);
        if (!in_dom (p, (pms, t)) m) m.[(p, (pms, t))] = $key;
        return oget m.[(p, (pms, t))];
      }
    }

    module O2 = {
      proc dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var pms : pms;
        var maybe_pms : pms option;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t V.labels /\ mem p P) {
          V.labels = add t V.labels;
          (pv, h) = p;
          maybe_pms = decrypt pv V.sk c;
          abort = abort \/
           (V.guess /\ maybe_pms <> None /\ oget maybe_pms = V.pms /\ p = pp /\ t = V.t /\ c <> V.c);
          if (!(V.guess /\ p = pp /\ t = V.t /\ c = V.c)) {
            if (maybe_pms = None) k = $key;
            else {
              pms = oget maybe_pms;
              if (!in_dom ((pv, h), (pms, t)) m) m.[((pv, h), (pms, t))] = $key;
              k = oget m.[((pv, h), (pms, t))];
            }
            maybe_k = if (V.guess => !mem k V.keys \/ t <> V.t)
                      then Some k else None;
          }
        }
        return maybe_k;
      }
    }

   module A = A(O1, O2)

    proc main() : bool = {
     var b, b', valid : bool;
     var k0, k1 : ms;
     PMS_KEM.init();
     (V.pk, V.sk) = PMS_KEM.keygen();
     V.init();
     m = FMap.empty;
     abort = false;
     (V.pms, V.c) = PMS_KEM.enc(fst pp, V.pk, ());
     V.t = A.choose(V.pk);
     valid = !mem V.t V.labels;
     k0 = $key;
     k1 = $key;
     V.keys = add k0 (add k1 V.keys);
     V.guess = true;
     b' = A.guess(V.c, k0);
     b = ${0,1};
     return (b = b' /\ valid);
   }
  }.

  (** RCCA2 -> RCCA3 **)
  local lemma RCCA2_lossless_extract : islossless RCCA2.O1.extract.
  proof.
    by proc; sp; if => //; rnd; skip; progress; smt.
  qed.

  local lemma RCCA2_lossless_dec : islossless RCCA2.O2.dec.
  proof.
    proc.
    sp; if => //.
    inline KEM(RO_KEF, PMS_KEM).dec; wp; sp.
    if => //.
      by rnd; skip; smt.
      by call (_:true ==> true) => //; apply RCCA2_lossless_extract.
  qed.

  local lemma RCCA3_lossless_extract : islossless RCCA3.O1.extract.
  proof.
    by proc; sp; if => //; rnd; skip; progress; smt.
  qed.

  local lemma RCCA3_lossless_dec : islossless RCCA3.O2.dec.
  proof.
    proc.
    sp; if => //.
    sp; if => //.
    if => //; wp.
      by rnd; skip; smt.
      by sp; if; try rnd; skip; smt.
  qed.

  local lemma RCCA3_dec_preserves_abort :
    phoare [ RCCA3.O2.dec : RCCA3.abort ==> RCCA3.abort ] = 1%r.
  proof.
    proc.
    sp; if => //.
    sp; if => //.
    if => //.
      by wp; rnd; skip; smt.
    sp; if => //; wp; try rnd; skip; smt.
  qed.

  local equiv RCCA2_RCCA3_extract_guess :
    RCCA2.O1.extract ~ RCCA3.O1.extract :
    !RCCA3.abort{2} /\
    ={p, s} /\
    keypair(V.pk, V.sk){2} /\
    V.guess{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    W.t{1} = V.t{2} /\
    W.guess{1} = V.guess{2} /\
    eq_except RCCA2.m{1} RCCA3.m{2} (pp, (V.pms, V.t)){2} /\
    in_dom (pp, (V.pms, V.t)){2} RCCA2.m{1} /\
    mem (oget RCCA2.m{1}.[(pp, (V.pms, V.t))]){2} V.keys{2} /\
    decrypt (fst pp) V.sk{2} V.c{2} = Some V.pms{2}
    ==>
    !RCCA3.abort{2} =>
      ={res} /\
      keypair(V.pk, V.sk){2} /\
      V.guess{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      W.t{1} = V.t{2} /\
      W.guess{1} = V.guess{2} /\
      eq_except RCCA2.m{1} RCCA3.m{2} (pp, (V.pms, V.t)){2} /\
      in_dom (pp, (V.pms, V.t)){2} RCCA2.m{1} /\
      mem (oget RCCA2.m{1}.[(pp, (V.pms, V.t))]){2} V.keys{2} /\
      decrypt (fst pp) V.sk{2} V.c{2} = Some V.pms{2}.
  proof.
    proc.
    sp; case (RCCA3.abort{2}).
      (* aborts *)
      if{1}; if{2}.
        by rnd; skip; smt.
        by rnd{1}; skip; smt.
        by rnd{2}; skip; smt.
        by skip; smt.
      (* doesn't abort *)
      if; first by smt.
        by wp; rnd; skip; progress; smt.
        by skip; progress; smt.
  qed.

  local equiv RCCA2_RCCA3_dec_guess :
    RCCA2.O2.dec ~ RCCA3.O2.dec :
    !RCCA3.abort{2} /\
    ={p, t, c} /\
    keypair(V.pk, V.sk){2} /\
    V.guess{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    W.t{1} = V.t{2} /\
    W.guess{1} = V.guess{2} /\
    eq_except RCCA2.m{1} RCCA3.m{2} (pp, (V.pms, V.t)){2} /\
    in_dom (pp, (V.pms, V.t)){2} RCCA2.m{1} /\
    mem (oget RCCA2.m{1}.[(pp, (V.pms, V.t))]){2} V.keys{2} /\
    decrypt (fst pp) V.sk{2} V.c{2} = Some V.pms{2}
    ==>
    !RCCA3.abort{2} =>
      ={res} /\
      keypair(V.pk, V.sk){2} /\
      V.guess{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      W.t{1} = V.t{2} /\
      W.guess{1} = V.guess{2} /\
      eq_except RCCA2.m{1} RCCA3.m{2} (pp, (V.pms, V.t)){2} /\
      in_dom (pp, (V.pms, V.t)){2} RCCA2.m{1} /\
      mem (oget RCCA2.m{1}.[(pp, (V.pms, V.t))]){2} V.keys{2} /\
      decrypt (fst pp) V.sk{2} V.c{2} = Some V.pms{2}.
  proof.
    proc.
    sp; if => //.
    wp; sp; case (RCCA3.abort{2}).
      (* aborts *)
      if{2}.
       if{1}; if{2}.
         by wp; rnd; skip; progress; smt.
         sp; if{2}; wp; try rnd; try rnd{1}; skip; progress; smt.

         call{1} (_:true ==> true); first by apply RCCA2_lossless_extract.
         by wp; rnd{2}; skip; smt.

         call{1} (_:true ==> true); first by apply RCCA2_lossless_extract.
         sp; if{2}; wp; try rnd{2}; skip; progress; smt.

         if{1}.
           by rnd{1}; skip; smt.
           call{1} (_:true ==> true); first by apply RCCA2_lossless_extract.
           by skip; smt.
      (* doesn't abort *)
      inline{1} RCCA2.O1.extract.
      if{2}.
        if => //; first by wp; rnd; skip; progress.
        wp; sp; if.
          by smt.
          by rnd; skip; progress; smt.
        skip; progress.
        by generalize H2; smt.

    if{1}; wp; sp.
      by exfalso; smt.
      if{1}.
        by rnd{1}; skip; progress; smt.
      by skip; progress; smt.
  qed.

  local equiv RCCA2_RCCA3_extract_choose :
    RCCA2.O1.extract ~ RCCA3.O1.extract :
    !RCCA3.abort{2} /\
    ={p, s} /\
    keypair(V.pk, V.sk){2} /\
    !V.guess{2} /\
    RCCA2.m{1} = RCCA3.m{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    W.t{1} = V.t{2} /\
    W.guess{1} = V.guess{2} /\
    decrypt (fst pp) V.sk{2} V.c{2} = Some V.pms{2} /\
    (forall t,
     in_dom (pp, (V.pms, t)) RCCA3.m =>
     RCCA3.abort \/ mem t V.labels){2}
    ==>
    !RCCA3.abort{2} =>
      ={res} /\
      keypair(V.pk, V.sk){2} /\
      !V.guess{2} /\
      RCCA2.m{1} = RCCA3.m{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      W.t{1} = V.t{2} /\
      W.guess{1} = V.guess{2} /\
      decrypt (fst pp) V.sk{2} V.c{2} = Some V.pms{2} /\
      (forall t,
       in_dom (pp, (V.pms, t)) RCCA3.m =>
       RCCA3.abort \/ mem t V.labels){2}.
  proof.
    proc.
    sp; case (RCCA3.abort{2}).
      by if{1}; if{2}; try rnd{1}; try rnd{2}; skip; smt.
      if => //.
        by rnd; skip; smt.
        by skip; smt.
  qed.

  local equiv RCCA2_RCCA3_dec_choose :
    RCCA2.O2.dec ~ RCCA3.O2.dec :
    !RCCA3.abort{2} /\
    ={p, t, c} /\
    keypair(V.pk, V.sk){2} /\
    !V.guess{2} /\
    RCCA2.m{1} = RCCA3.m{2} /\
    W.sk{1} = V.sk{2} /\
    W.keys{1} = V.keys{2} /\
    W.labels{1} = V.labels{2} /\
    W.t{1} = V.t{2} /\
    W.guess{1} = V.guess{2} /\
    (decrypt (fst pp) V.sk  V.c = Some V.pms){2} /\
    (forall t,
     in_dom (pp, (V.pms, t)) RCCA3.m =>
     RCCA3.abort \/ mem t V.labels){2}
    ==>
    !RCCA3.abort{2} =>
      ={res} /\
      keypair(V.pk, V.sk){2} /\
      !V.guess{2} /\
      RCCA2.m{1} = RCCA3.m{2} /\
      W.sk{1} = V.sk{2} /\
      W.keys{1} = V.keys{2} /\
      W.labels{1} = V.labels{2} /\
      W.t{1} = V.t{2} /\
      W.guess{1} = V.guess{2} /\
      (decrypt (fst pp) V.sk V.c = Some V.pms){2} /\
      (forall t,
       in_dom (pp, (V.pms, t)) RCCA3.m =>
       RCCA3.abort \/ mem t V.labels){2}.
  proof.
    proc.
    sp; if => //.
    inline{1} RCCA2.O1.extract; wp; sp.
    if{2}; last by exfalso; smt.
    if => //.
      by wp; rnd; skip; progress; smt.
      sp; if => //.
        by wp; rnd; skip; progress; smt.
        by wp; skip; progress; smt.
  qed.

  local equiv RCCA2_RCCA3 :
    RCCA2.main ~ RCCA3.main : true ==> !RCCA3.abort{2} => ={res}.
  proof.
    proc.
    swap{1} 15 -3; swap{2} 14 -6.
    seq 12 8 :
     (={b} /\ pms{1} = V.pms{2} /\ c{1} = V.c{2} /\ (pv, h){1} = pp /\
      (!RCCA3.abort{2} =>
       ={glob A} /\ W.t{1} = V.t{2} /\ RCCA2.m{1} = RCCA3.m{2} /\
       keypair(V.pk, V.sk){2} /\
       W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\ W.guess{1} = V.guess{2} /\
       (decrypt (fst pp) V.sk V.c = Some V.pms){2} /\
       (forall t, in_dom (pp, (V.pms, t)) RCCA3.m => mem t V.labels){2})).
      rnd; simplify.
      call (_:RCCA3.abort,
        keypair(V.pk, V.sk){2} /\
        !V.guess{2} /\ RCCA2.m{1} = RCCA3.m{2} /\
        W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\ W.t{1} = V.t{2} /\ W.guess{1} = V.guess{2} /\
        (decrypt (fst pp) V.sk V.c = Some V.pms){2} /\
        (forall t, in_dom (pp, (V.pms, t)) RCCA3.m =>
           RCCA3.abort \/ mem t V.labels){2}).
      by apply lossless_choose.
      by apply RCCA2_RCCA3_dec_choose.
      by progress; apply RCCA2_lossless_dec.
      by apply RCCA3_dec_preserves_abort.
      by apply RCCA2_RCCA3_extract_choose.
      by progress; apply RCCA2_lossless_extract.
      by progress; proc; sp; if; try rnd; skip; smt.
      seq 3 2 : (pk{1} = V.pk{2} /\ W.sk{1} = V.sk{2} /\ keypair(V.pk, V.sk){2}).
        inline MS_KEM.init MS_KEM.keygen; wp.
        call keygen_spec_rel; wp; call (_:true).
        (* RCCA2.sample lossless *)
        call{1} (_:true ==> true) => //.
          proc; sp; while true (card labels).
          intros _; wp; rnd; wp; skip; smt.
          by skip; progress; smt.
          by skip; progress; try apply stateless_pms_kem; smt.
        inline V.init; sp; exists * V.sk{2}, V.pk{2}; elim *; intros sk pk.
        call (enc_spec_rel sk pk (fst pp)); skip; progress.
          by smt.
          by generalize H2; smt.
          by smt.
          by smt.
          by smt.
          by smt.
          by smt.
          by smt.
      inline RCCA2.O1.extract; wp; sp.
      case (RCCA3.abort{2}).
        (* abort *)
        call (_:RCCA3.abort, RCCA3.abort{2}).
          by apply lossless_guess.
          by exfalso; smt.
          by progress; apply RCCA2_lossless_dec.
          by apply RCCA3_dec_preserves_abort.
          by exfalso; smt.
          by progress; apply RCCA2_lossless_extract.
          by progress; proc; sp; if; try rnd; skip; smt.
        wp; rnd; wp; if{1}.
          by rnd; skip; smt.
          by rnd{2}; skip; smt.
        (* !abort *)
        case (valid{1}).
          (* valid *)
          (* REMARK: here is where the validity condition is used *)
          rcondt{1} 1; first by intros _; skip; smt.
          call (_:RCCA3.abort,
           keypair(V.pk, V.sk){2} /\
           V.guess{2} /\
           W.sk{1} = V.sk{2} /\ W.keys{1} = V.keys{2} /\ W.labels{1} = V.labels{2} /\ W.t{1} = V.t{2} /\ W.guess{1} = V.guess{2} /\
           eq_except RCCA2.m{1} RCCA3.m{2} (pp, (V.pms, V.t)){2} /\
           in_dom (pp, (V.pms, V.t)){2} RCCA2.m{1} /\
           mem (oget RCCA2.m{1}.[(pp, (V.pms, V.t))]){2} V.keys{2} /\
           decrypt (fst pp) V.sk{2} V.c{2} = Some V.pms{2}).
          by apply lossless_guess.
          by apply RCCA2_RCCA3_dec_guess.
          by progress; apply RCCA2_lossless_dec.
          by apply RCCA3_dec_preserves_abort.
          by apply RCCA2_RCCA3_extract_guess.
          by progress; apply RCCA2_lossless_extract.
          by intros _; proc; sp; if; try rnd; skip; smt.
          wp; case (b{1}).
            by swap{2} 1; rnd; wp; rnd; skip; progress; smt.
            by rnd; wp; rnd; skip; progress; smt.

          (* !abort /\ !valid *)
          call{1} (_:true ==> true).
            apply (lossless_guess RCCA2.O1 RCCA2.O2).
              by apply RCCA2_lossless_dec.
              by apply RCCA2_lossless_extract.
          call{2} (_:true ==> true).
            apply (lossless_guess RCCA3.O1 RCCA3.O2).
              by apply RCCA3_lossless_dec.
              by apply RCCA3_lossless_extract.
      wp; rnd; wp; if{1}.
        by rnd; skip; progress; smt.
        by rnd{2}; skip; smt.
  qed.

  local lemma Pr_RCCA3_res &m : Pr[RCCA3.main() @ &m : res] <= 1%r / 2%r.
  proof.
    byphoare (_:true) => //.
    proc; rnd; simplify; call (_:true) => //.
    wp; rnd; rnd; wp; call (_:true) => //.
    inline V.init; call (_:true); wp; call (_:true); wp; call (_:true).
    skip; progress.
    by rewrite Bool.Dbool.mu_def /Distr.charfun; smt.
  qed.

  local lemma Pr_RCCA_RCCA2 &m :
    Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] <=
    Pr[RCCA2.main() @ &m : res] +
    Pr[RCCA2.main() @ &m : exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m].
  proof.
    apply (Trans _ Pr[RCCA0.main() @ &m : res]).
    byequiv RCCA_RCCA0 => //.
    rewrite (Pr_RCCA0_RCCA1 &m).
    apply (Trans _
     (Pr[RCCA2.main() @ &m : res] +
      Pr[RCCA2.main() @ &m : exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m])).
    apply (Pr_RCCA1_RCCA2 &m).
    smt.
  qed.

  local lemma Pr_RCCA2_RCCA3 &m :
    Pr[RCCA2.main() @ &m : res] <= 1%r / 2%r + Pr[RCCA3.main() @ &m : RCCA3.abort].
  proof.
    apply (Trans _ Pr[RCCA3.main() @ &m : res \/ RCCA3.abort]).
      by byequiv RCCA2_RCCA3; smt.
      by rewrite Pr [mu_or]; smt.
  qed.

  local lemma Pr_RCCA_RCCA3 &m :
    Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] <=
    1%r / 2%r +
    Pr[RCCA2.main() @ &m : exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m] +
    Pr[RCCA3.main() @ &m : RCCA3.abort].
  proof.
    apply (Trans _
     (Pr[RCCA2.main() @ &m : res] +
      Pr[RCCA2.main() @ &m : exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m])).
    apply (Pr_RCCA_RCCA2 &m).
    apply (Trans _
      (1%r / 2%r + Pr[RCCA3.main() @ &m : RCCA3.abort] +
      Pr[RCCA2.main() @ &m : exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m])).
    by apply addleM => //; [apply (Pr_RCCA2_RCCA3 &m) | smt].
    by smt.
  qed.

  (** RCCA3 -> RCCA4 **)

  (*
   * This game uses two maps m and d to implement the simulation for
   * the RCCA adversary A. If the simulation fails and the previous
   * game aborts, then either the pms used to compute the challenge ciphertext
   * can be obtained from map m using the plaintext-checking oracle, or else
   * a randomization of the challenge ciphertext can be obtained by a direct
   * lookup in d.
   *)
  local module RCCA4 = {
    var m : ((version * hash) * (pms * label), ms) map
    var d : (label, (ms * version * hash * ciphertext)) map

    module O1 = {
      proc extract(p:version * hash, s:pms * label) : ms = {
        var k : ms;
        var pms : pms;
        var t : label;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) {
          if (in_dom t d /\
              let (ms, pv, h, c) = oget d.[t] in
                p = (pv, h) /\ decrypt pv V.sk c = Some pms) {
            k = let (ms, pv, h, c) = oget d.[t] in ms;
          }
          else k = $key;
          m.[(p, (pms, t))] = k;
        }
        else k = oget m.[(p, (pms, t))];
        return k;
      }
    }

    module O2 = {
      proc dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var k : ms;
        var maybe_k : ms option = None;
        if (!mem t V.labels /\ mem p P) {
          V.labels = add t V.labels;
          (pv, h) = p;
          if (!(V.guess /\ p = pp /\ t = V.t /\ V.c = c)) {
            if (decrypt pv V.sk c <> None /\
                in_dom ((pv, h), (oget (decrypt pv V.sk c), t)) m) {
              k = oget m.[((pv, h), (oget (decrypt pv V.sk c), t))];
            }
            else k = $key;
            d.[t] = (k, pv, h, c);
            maybe_k = if (V.guess => !mem k V.keys \/ t <> V.t)
                      then Some k else None;
          }
        }
        return maybe_k;
      }
    }

    module A = A(O1, O2)

    proc main() : bool = {
      var b, b' : bool;
      var k0, k1 : ms;
      PMS_KEM.init();
      (V.pk, V.sk) = PMS_KEM.keygen();
      V.init();
      m = FMap.empty;
      d = FMap.empty;
      (V.pms, V.c) = PMS_KEM.enc(fst pp, V.pk, ());
      V.t = A.choose(V.pk);
      k0 = $key;
      k1 = $key;
      V.guess = true;
      V.keys = add k0 (add k1 V.keys);
      b' = A.guess(V.c, k0);
      return true;
    }
  }.

  local equiv RCCA3_RCCA4_extract :
    RCCA3.O1.extract ~ RCCA4.O1.extract :
    ={p, s} /\
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt (fst pp) V.sk V.c = Some V.pms){2} /\
    (RCCA3.abort{1} =>
     (exists t, in_dom (pp, (V.pms, t)) RCCA4.m) \/
     (V.guess /\ in_dom V.t RCCA4.d /\
      let (k, pv, h, c) = oget RCCA4.d.[V.t] in
       pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms)){2} /\
    (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} <=>
     (in_dom (p, (pms, t)) RCCA4.m{2} \/
      (in_dom t RCCA4.d{2} /\
       let (k, pv, h, c) = oget RCCA4.d{2}.[t] in
        pv = fst p /\ h = snd p /\ decrypt pv V.sk{2} c = Some pms)))) /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} =>
      in_dom (p, (pms, t)) RCCA4.m{2} =>
      RCCA3.m{1}.[(p, (pms, t))] = RCCA4.m{2}.[(p, (pms, t))])) /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} =>
      !in_dom (p, (pms, t)) RCCA4.m{2} =>
        RCCA3.m{1}.[(p, (pms, t))] =
        let (k, pv, h, c) = oget RCCA4.d{2}.[t] in Some k))
    ==>
    ={res} /\
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt (fst pp) V.sk V.c = Some V.pms){2} /\
    (RCCA3.abort{1} =>
     (exists t, in_dom (pp, (V.pms, t)) RCCA4.m) \/
     (V.guess /\ in_dom V.t RCCA4.d /\
      let (k, pv, h, c) = oget RCCA4.d.[V.t] in
       pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms)){2} /\
    (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} <=>
     (in_dom (p, (pms, t)) RCCA4.m{2} \/
      (in_dom t RCCA4.d{2} /\
       let (k, pv, h, c) = oget RCCA4.d{2}.[t] in
        pv = fst p /\ h = snd p /\ decrypt pv V.sk{2} c = Some pms)))) /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} =>
      in_dom (p, (pms, t)) RCCA4.m{2} =>
      RCCA3.m{1}.[(p, (pms, t))] = RCCA4.m{2}.[(p, (pms, t))])) /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} =>
      !in_dom (p, (pms, t)) RCCA4.m{2} =>
        RCCA3.m{1}.[(p, (pms, t))] =
        let (k, pv, h, c) = oget RCCA4.d{2}.[t] in Some k)).
  proof.
    proc.
    sp; if{1}.
      rcondt{2} 1; first by intros &1; skip; intros &2; progress; smt.
      sp; rcondf{2} 1.
        intros &1; skip; intros &2; progress.
        by cut W := H2 p{2} pms{2} t{2}; smt.
      wp; rnd; skip; progress.
        by smt.
        by elim H8=> ?; smt.
        by smt.
        by generalize (H2 p0 pms0 t0); smt.
        by cut W := H3 p0 pms0 t0; smt.
        by cut W := H2 p0 pms0 t0; cut X := H4 p0 pms0 t0; smt.
     if{2}.
       sp; rcondt{2} 1; first by intros &1; skip; intros &2; progress; smt.
       wp; skip; progress.
         by smt.
         by elim H7; smt.
         by cut W := H2 p0 pms0 t0; smt.
         by elim H7; smt.
         by smt.
         by smt.
      by wp; skip; progress; smt.
  qed.

  local equiv RCCA3_RCCA4_dec :
    RCCA3.O2.dec ~ RCCA4.O2.dec :
    ={p, t, c} /\
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt (fst pp) V.sk V.c = Some V.pms){2} /\
    (RCCA3.abort{1} =>
     (exists t, in_dom (pp, (V.pms, t)) RCCA4.m) \/
     (V.guess /\ in_dom V.t RCCA4.d /\
      let (k, pv, h, c) = oget RCCA4.d.[V.t] in
       pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms)){2} /\
    (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} <=>
     (in_dom (p, (pms, t)) RCCA4.m{2} \/
      (in_dom t RCCA4.d{2} /\
       let (k, pv, h, c) = oget RCCA4.d{2}.[t] in
        pv = fst p /\ h = snd p /\ decrypt pv V.sk{2} c = Some pms)))) /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} =>
      in_dom (p, (pms, t)) RCCA4.m{2} =>
      RCCA3.m{1}.[(p, (pms, t))] = RCCA4.m{2}.[(p, (pms, t))])) /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} =>
      !in_dom (p, (pms, t)) RCCA4.m{2} =>
        RCCA3.m{1}.[(p, (pms, t))] =
        let (k, pv, h, c) = oget RCCA4.d{2}.[t] in Some k))
    ==>
    ={res} /\
    ={glob V} /\
    (V.guess{1} => ={V.t}) /\
    (decrypt (fst pp) V.sk V.c = Some V.pms){2} /\
    (RCCA3.abort{1} =>
     (exists t, in_dom (pp, (V.pms, t)) RCCA4.m) \/
     (V.guess /\ in_dom V.t RCCA4.d /\
      let (k, pv, h, c) = oget RCCA4.d.[V.t] in
       pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms)){2} /\
    (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} <=>
     (in_dom (p, (pms, t)) RCCA4.m{2} \/
      (in_dom t RCCA4.d{2} /\
       let (k, pv, h, c) = oget RCCA4.d{2}.[t] in
        pv = fst p /\ h = snd p /\ decrypt pv V.sk{2} c = Some pms)))) /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} =>
      in_dom (p, (pms, t)) RCCA4.m{2} =>
      RCCA3.m{1}.[(p, (pms, t))] = RCCA4.m{2}.[(p, (pms, t))])) /\
    (forall p pms t,
     (in_dom (p, (pms, t)) RCCA3.m{1} =>
      !in_dom (p, (pms, t)) RCCA4.m{2} =>
        RCCA3.m{1}.[(p, (pms, t))] =
        let (k, pv, h, c) = oget RCCA4.d{2}.[t] in Some k)).
  proof.
    proc.
    wp; sp; if => //.
    inline{1} RCCA3.O1.extract.
    sp; if => //; first by smt.
      if{1}.
        if{2}.
          by exfalso; smt.
          wp; rnd; skip; progress.
            by smt.
            by smt.
            by smt.
            by elim H12; smt.
            by smt.

          if{2}.
          sp; if{1}; first by exfalso; smt.
          wp; skip; progress.
            by smt.
            by elim H12; smt.
            by smt.

            case (in_dom (p0, (pms0, t0)) RCCA4.m{2}) => //= ?.
            case (t0 = t{2}) => ?.
              subst; split; smt.
              split; first by smt.
              by rewrite FMap.get_set_neq; smt.

            elim H12 => ?; first by smt.
              cut L : (in_dom (p0, (pms0, t0)) RCCA3.m{1}); last by smt.
              rewrite H2.
              case (t0 = t{2}) => ?.
                subst; elim H12 => X Y.
                by generalize Y; rewrite FMap.get_set_eq oget_some; smt.
                right; elim H12 => X Y.
                by generalize X Y; rewrite !FMap.get_set_neq; smt.

            by smt.

         sp; if{1}; last by exfalso; smt.
         wp; rnd; skip; progress.
           by smt.
           elim H13=> ?; first by smt.
           right; split; first by smt.
           split; first by smt.
           cut -> : t{2} = V.t{2} by smt.
           rewrite FMap.get_set_eq oget_some=> /=.
           by generalize H13; elim (decrypt pv{2} V.sk{2} c{2}); smt.
           by smt.

           case (in_dom (p0, (pms0, t0)) RCCA4.m{2}) => //= ?.
           case ((p0, (pms0, t0)) = ((pv, h){2}, (oget (decrypt pv{2} V.sk{2} c{2}), t{2}))) => ?.
              split; first by smt.
              cut -> : (t0 = t){2} by smt.
              rewrite FMap.get_set_eq oget_some=> /=.
              by generalize H15; smt.
              cut L : (in_dom (p0, (pms0, t0)) RCCA3.m{1}) by smt.
              split; first by smt.
              by generalize H15; rewrite FMap.get_set_neq; smt.

            elim H13 => ?; first by smt.

            elim H13 => X Y.
            case ((p0, (pms0, t0)) = ((pv, h){2}, (oget (decrypt pv{2} V.sk{2} c{2}), t{2}))) => ?.
              by smt.

              cut L : (in_dom (p0, (pms0, t0)) RCCA3.m{1}); last by smt.
              rewrite H2.
              case (in_dom (p0, (pms0, t0)) RCCA4.m{2}) => //= ?.
              case (t0 = t{2}) => ?.
                subst; generalize Y; rewrite FMap.get_set_eq oget_some; smt.                   generalize Y; rewrite FMap.get_set_neq; smt.

             by smt.
             cut : decrypt pv{2} V.sk{2} c{2} <> None by smt.
             case (t0 = t{2}) => ?; smt.

      by skip; progress; smt.
  qed.

  local equiv RCCA3_RCCA4 :
    RCCA3.main ~ RCCA4.main :
    true ==>
    RCCA3.abort{1} =>
      (exists t, in_dom (pp, (V.pms, t)) RCCA4.m){2} \/
      (in_dom V.t RCCA4.d /\
       let (k, pv, h, c) = oget RCCA4.d.[V.t] in
         pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms){2}.
  proof.
    proc.
    rnd{1}.
    call (_:
     ={glob V} /\
     (V.guess{1} => ={V.t}) /\
     (decrypt (fst pp) V.sk  V.c = Some V.pms){2} /\
     (RCCA3.abort{1} =>
      (exists t, in_dom (pp, (V.pms, t)) RCCA4.m) \/
      (V.guess /\ in_dom V.t RCCA4.d /\
       let (k, pv, h, c) = oget RCCA4.d.[V.t] in
        pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms)){2} /\
     (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
     (forall p pms t,
      (in_dom (p, (pms, t)) RCCA3.m{1} <=>
      (in_dom (p, (pms, t)) RCCA4.m{2} \/
       (in_dom t RCCA4.d{2} /\
        let (k, pv, h, c) = oget RCCA4.d{2}.[t] in
         pv = fst p /\ h = snd p /\ decrypt pv V.sk{2} c = Some pms)))) /\
     (forall p pms t,
      (in_dom (p, (pms, t)) RCCA3.m{1} =>
       in_dom (p, (pms, t)) RCCA4.m{2} =>
       RCCA3.m{1}.[(p, (pms, t))] = RCCA4.m{2}.[(p, (pms, t))])) /\
     (forall p pms t,
      (in_dom (p, (pms, t)) RCCA3.m{1} =>
       !in_dom (p, (pms, t)) RCCA4.m{2} =>
         RCCA3.m{1}.[(p, (pms, t))] =
         let (k, pv, h, c) = oget RCCA4.d{2}.[t] in Some k))).
      by apply RCCA3_RCCA4_dec.
      by apply RCCA3_RCCA4_extract.
    wp; rnd; rnd; wp.
    call (_:
     ={glob V} /\
     (V.guess{1} => ={V.t}) /\
     (decrypt (fst pp) V.sk V.c = Some V.pms){2} /\
     (RCCA3.abort{1} =>
      (exists t, in_dom (pp, (V.pms, t)) RCCA4.m) \/
      (V.guess /\ in_dom V.t RCCA4.d /\
       let (k, pv, h, c) = oget RCCA4.d.[V.t] in
        pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms)){2} /\
     (forall t, in_dom t RCCA4.d => mem t V.labels){2} /\
     (forall p pms t,
      (in_dom (p, (pms, t)) RCCA3.m{1} <=>
      (in_dom (p, (pms, t)) RCCA4.m{2} \/
       (in_dom t RCCA4.d{2} /\
        let (k, pv, h, c) = oget RCCA4.d{2}.[t] in
         pv = fst p /\ h = snd p /\ decrypt pv V.sk{2} c = Some pms)))) /\
     (forall p pms t,
      (in_dom (p, (pms, t)) RCCA3.m{1} =>
       in_dom (p, (pms, t)) RCCA4.m{2} =>
       RCCA3.m{1}.[(p, (pms, t))] = RCCA4.m{2}.[(p, (pms, t))])) /\
     (forall p pms t,
      (in_dom (p, (pms, t)) RCCA3.m{1} =>
       !in_dom (p, (pms, t)) RCCA4.m{2} =>
         RCCA3.m{1}.[(p, (pms, t))] =
         let (k, pv, h, c) = oget RCCA4.d{2}.[t] in Some k))).
      by apply RCCA3_RCCA4_dec.
      by apply RCCA3_RCCA4_extract.
    seq 2 2 : (={V.pk, V.sk} /\ keypair(V.pk, V.sk){1}).
      call keygen_spec_rel; call (_:true); skip; progress.
        by apply stateless_pms_kem.
        by smt.
      exists * V.pk{1}, V.sk{1}; elim *; intros pk sk.
      call (enc_spec_rel sk pk (fst pp)).
      inline V.init; wp; skip; progress; generalize H1; smt.
  qed.

  local lemma Pr_RCCA3_RCCA4 &m :
    Pr[RCCA3.main() @ &m : RCCA3.abort] <=
    Pr[RCCA4.main() @ &m : exists t, in_dom (pp, (V.pms, t)) RCCA4.m] +
    Pr[RCCA4.main() @ &m : let (k, pv, h, c) = oget RCCA4.d.[V.t] in
       pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms].
  proof.
    apply (Trans _
      Pr[RCCA4.main() @ &m :
       (exists t, in_dom (pp, (V.pms, t)) RCCA4.m) \/
       let (k, pv, h, c) = oget RCCA4.d.[V.t] in
         pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms]).
      by byequiv RCCA3_RCCA4; smt.
      rewrite Pr [mu_or].
      cut X : forall (x y z), 0%r <= z => x <= y => x - z <= y by smt.
    by apply X; [smt | apply Refl].
  qed.

  (** RCCA4 -> OW_PCA **)
  import Inner_KEM.

  (*
   * This module implements auxiliary procedures used in the reduction
   * to OW_PCA and NR_PCA, and the extract and decryption oracles (the
   * same are used in both reductions).
   *)
  local module Find(PCO:PCA.Oracle) = {
    var m : ((version * hash) * (pms * label), ms) map
    var d : (label, (ms * version * hash * ciphertext)) map
    var pk : pkey

    (* Private procedures *)
    proc find(pv:version, c:ciphertext, h:hash, t:label) : pms option = {
      var p' : version * hash;
      var s : pms * label;
      var pms : pms;
      var t' : label;
      var found : bool;
      var q : ((version * hash) * (pms * label)) set;
      var maybe_pms : pms option = None;
      q = dom(m);
      while (q <> FSet.empty /\ maybe_pms = None) {
        (p',  s) = pick q;
        q = rm (p', s) q;
        (pms, t') = s;
        found = PCO.check(pv, pms, (), c);
        if (found /\ pv = fst p' /\ h = snd p' /\ t = t') maybe_pms = Some pms;
      }
      return maybe_pms;
    }

    proc find_any(pv:version, c:ciphertext) : pms option = {
      var p' : version * hash;
      var s : pms * label;
      var pms : pms;
      var t' : label;
      var found : bool;
      var q : ((version * hash) * (pms * label)) set;
      var maybe_pms : pms option = None;
      q = dom(m);
      while (q <> FSet.empty /\ maybe_pms = None) {
        (p',  s) = pick q;
        q = rm (p', s) q;
        (pms, t') = s;
        found = PCO.check(pv, pms, (), c);
        if (found) maybe_pms = Some pms;
      }
      return maybe_pms;
    }

    module O1 = {
      proc extract(p:version * hash, s:pms * label) : ms = {
        var k : ms;
        var pms : pms;
        var t : label;
        var pv : version;
        var h : hash;
        var c : ciphertext;
        var found : bool;
        (pms, t) = s;
        if (!in_dom (p, (pms, t)) m) {
          (k, pv, h, c) = oget d.[t];
          found = PCO.check(pv, pms, (), c);
          if (in_dom t d /\ p = (pv, h) /\ found) {
            k = let (ms, pv, h, c) = oget d.[t] in ms;
          }
          else k = $key;
          m.[(p, (pms, t))] = k;
        }
        else k = oget m.[(p, (pms, t))];
        return k;
      }
    }

    module O2 = {
      proc dec(p:version * hash, t:label, c:ciphertext) : ms option = {
        var pv : version;
        var h : hash;
        var k : ms;
        var maybe_pms : pms option;
        var maybe_k : ms option = None;
        if (!mem t V.labels /\ mem p P) {
          V.labels = add t V.labels;
          (pv, h) = p;
          if (!(V.guess /\ p = pp /\ t = V.t /\ V.c = c)) {
            maybe_pms = find(pv, c, h, t);
            if (maybe_pms <> None) k = oget m.[((pv, h), (oget maybe_pms, t))];
            else k = $key;
            d.[t] = (k, pv, h, c);
            maybe_k = if (V.guess => !mem k V.keys \/ t <> V.t)
                      then Some k else None;
          }
        }
        return maybe_k;
      }
    }
  }.

  (* Adversary used in the reduction to OW_PCA *)
  local module B(PCO:PCA.Oracle) = {
    module F = Find(PCO)
    module A = A(Find(PCO).O1, Find(PCO).O2)

    proc choose(pk:pkey) : unit = { Find.pk = pk; }

    proc guess(c:ciphertext) : pms = {
      var maybe_pms : pms option;
      var k0, k1 : ms;
      var b' : bool;
      V.init();
      V.c = c;
      Find.m = FMap.empty;
      Find.d = FMap.empty;
      V.t = A.choose(Find.pk);
      k0 = $key;
      k1 = $key;
      V.keys = add k0 (add k1 V.keys);
      V.guess = true;
      b' = A.guess(c, k0);
      maybe_pms = F.find_any(fst pp, c);
      return oget maybe_pms;
    }
  }.

  local module O = {
    proc check(p:version, k:pms, t:unit, c:ciphertext) : bool = {
      var maybe_k : pms option;
      maybe_k = decrypt p PCA.V.sk c;
      return (maybe_k = Some k);
    }
  }.

  local module OW_PCA0 = {
    module B = B(O)

    proc main() : bool = {
      var pk : pkey;
      var t : version;
      var k, k' : pms;
      var c : ciphertext;
      PMS_KEM.init();
      (pk, PCA.V.sk) = PMS_KEM.keygen();
      (k, c) = PMS_KEM.enc(fst pp, pk, ());
      B.choose(pk);
      k' = B.guess(c);
      return (k = k');
    }
  }.

  local equiv OW_PCA0_OW_PCA_check :
    O.check ~ PCA.OW_PCA(PMS_KEM, B).O.check :
    ={p, k, t, c} /\ ={glob PCA.V} ==>
    ={res} /\ ={glob PCA.V}.
  proof.
    proc.
    wp; exists * p{2}, PCA.V.sk{2}, c{2}; elim *; intros pv sk c.
    by call{2} (dec_spec sk pv c).
  qed.

  local equiv OW_PCA0_OW_PCA :
    OW_PCA0.main ~ PCA.OW_PCA(PMS_KEM, B).main : true ==> ={res}.
  proof.
    proc.
    swap{1} 3 1.
    inline PCA.OW_PCA(PMS_KEM, B).A.guess OW_PCA0.B.guess.
    sim (={glob PCA.V}) true : (={k,k',glob Find,glob PCA.V});
      first by apply OW_PCA0_OW_PCA_check.
    seq 3 3 : (={pk, glob PCA.V, Find.pk} /\ keypair(pk, PCA.V.sk){2}).
    inline PCA.OW_PCA(PMS_KEM, B).A.choose OW_PCA0.B.choose.
    wp; call keygen_spec_rel; call (_:true) => //.
    skip; progress.
      by apply stateless_pms_kem.
      by smt.
    exists * PCA.V.sk{1}, pk{1}; elim *; intros sk pk.
    call (enc_spec_rel sk pk (fst pp)).
    wp; skip; progress.
    cut X : forall x, tt = x by smt; apply X.
 qed.

  local lemma check_spec _p _k _c :
    phoare
    [ O.check :
      p = _p /\ k = _k /\ c = _c ==>
      res <=> decrypt _p PCA.V.sk _c = Some _k ] = 1%r.
  proof.
    by proc; wp; skip; smt.
  qed.

  local lemma find_any_spec _pv _c :
    phoare
    [ Find(O).find_any :
      pv = _pv /\ c = _c ==>
      let maybe = decrypt _pv PCA.V.sk _c in
       res =
       if (exists h t, in_dom (h, (oget maybe, t)) Find.m) then maybe
       else None ] = 1%r.
  proof.
    proc; sp.
    while
     ((forall x, mem x q => in_dom x Find.m) /\
      let maybe = decrypt pv PCA.V.sk c in
        (maybe_pms <> None =>
         maybe_pms = maybe /\ maybe <> None /\
         exists h t, in_dom (h, (oget maybe, t)) Find.m) /\
        forall x,
          in_dom x Find.m => !mem x q => maybe_pms = None =>
           maybe <> Some (fst (snd x)))
     (card q).
       intros z; sp; wp.
       exists * pms, pv, c; elim *; intros pms pv c q.
       call (check_spec pv pms c); skip; progress; smt.

    wp; skip; intros &1; progress => //.
      by smt.
      by smt.
      case ((decrypt pv PCA.V.sk c){1} = None) => ?.
        by smt.
        case (maybe_pms0 = None) => ?; last by smt.
        cut : forall h pms t,
          in_dom (h, (pms, t)) Find.m{1} =>
          decrypt pv{1} PCA.V.sk{1} c{1} <> Some pms by smt => ?.
        cut : !exists h t,
          in_dom (h, (oget (decrypt pv{1} PCA.V.sk{1} c{1}), t)) Find.m{1} /\
          decrypt pv{1} PCA.V.sk{1} c{1} <> None by smt.
        by smt.
  qed.

  local lemma find_spec _pv _c _h _t :
    phoare
    [ Find(O).find :
      pv = _pv /\ c = _c /\ h = _h /\ t = _t ==>
      let maybe = decrypt _pv PCA.V.sk _c in
       res =
       if (in_dom ((_pv, _h), (oget maybe, _t)) Find.m) then maybe
       else None ] = 1%r.
  proof.
    proc; sp.
    while
     ((forall x, mem x q => in_dom x Find.m) /\
      let maybe = decrypt pv PCA.V.sk c in
        (maybe_pms <> None =>
         maybe_pms = maybe /\ maybe <> None /\
         in_dom ((pv, h), (oget maybe, t)) Find.m) /\
        forall pv_ h_ pms_ t_,
          in_dom ((pv_, h_), (pms_, t_)) Find.m =>
          !mem ((pv_, h_), (pms_, t_)) q =>
          maybe_pms = None =>
          ((pv_, h_), (maybe, t_)) <> ((pv, h), (Some pms_, t)))
     (card q).
    intros z; sp; wp.
      exists * pms, pv, c; elim *; intros pms pv c q.
      by call (check_spec pv pms c); skip; progress; smt.
    wp; skip; intros &1; progress => //.
      by smt.
      by smt.
      case ((decrypt pv PCA.V.sk c){1} = None) => ?.
        by smt.
        cut : (decrypt pv PCA.V.sk c =
               Some (oget (decrypt pv PCA.V.sk c))){1} by smt.
        by smt.
  qed.

  local equiv RCCA4_Find_extract_guess :
    RCCA4.O1.extract ~ Find(O).O1.extract :
    ={p, s} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\
    RCCA4.m{1} = Find.m{2} /\
    RCCA4.d{1} = Find.d{2} /\
    decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1}
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\
    RCCA4.m{1} = Find.m{2} /\
    RCCA4.d{1} = Find.d{2} /\
    decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1}.
  proof.
    proc.
    sp; if => //.
      seq 0 2 :
       (={pms, t, p, s, V.keys, V.labels, V.guess, V.t, V.c} /\
        V.pk{1} = Find.pk{2} /\
        V.sk{1} = PCA.V.sk{2} /\
        RCCA4.m{1} = Find.m{2} /\
        RCCA4.d{1} = Find.d{2} /\
        decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1} /\
        ((in_dom t RCCA4.d /\
          let (ms, pv, h, c) = oget RCCA4.d.[t] in
            p = (pv, h) /\ decrypt pv V.sk c = Some pms){1} <=>
         (in_dom t Find.d /\ p = (pv, h) /\ found){2})).
        sp; exists * pms{2}, pv{2}, c{2}; elim *; intros pms pv c.
        by call{2} (check_spec pv pms c); skip; progress; smt.
        by if => //; wp; try rnd; skip; progress.
      by wp.
  qed.

  local equiv RCCA4_Find_dec_guess :
    RCCA4.O2.dec ~ Find(O).O2.dec :
    ={p, t, c} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\
    RCCA4.m{1} = Find.m{2} /\
    RCCA4.d{1} = Find.d{2} /\
    decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1}
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t, V.c} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\
    RCCA4.m{1} = Find.m{2} /\
    RCCA4.d{1} = Find.d{2} /\
    decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1}.
  proof.
    proc.
    sp; if => //.
    sp; if => //.
    seq 0 1 :
     (maybe_k{1} = None /\
      ={maybe_k, pv, h, p, t, c, V.labels, V.keys, V.guess, V.t, V.c} /\
      V.pk{1} = Find.pk{2} /\
      V.sk{1} = PCA.V.sk{2} /\
      RCCA4.m{1} = Find.m{2} /\
      RCCA4.d{1} = Find.d{2} /\
      decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1} /\
      !(V.guess /\ (pv,h) = pp /\ t = V.t /\ V.c = c){1} /\
      ((decrypt pv V.sk c <> None /\
       in_dom ((pv, h), (oget (decrypt pv V.sk c), t)) RCCA4.m){1} <=>
       maybe_pms{2} <> None) /\
      (maybe_pms <> None =>
       maybe_pms = Some (oget (decrypt pv PCA.V.sk c))){2}).
      sp; exists * pv{2}, c{2}, h{2}, t{2}; elim *; intros pv c h t q ?.
      call{2} (find_spec pv c h t); skip; progress.
        by smt.
        by smt.
        by smt.
        by generalize H3; elim (decrypt pv{2} PCA.V.sk{2} c{2}); smt.

      if => //.
        by wp; skip; smt.
        by wp; rnd.
  qed.

  local equiv RCCA4_Find_extract_choose :
    RCCA4.O1.extract ~ Find(O).O1.extract :
    ={p, s} /\ ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\
    RCCA4.m{1} = Find.m{2} /\
    RCCA4.d{1} = Find.d{2} /\
    decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1}
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\
    RCCA4.m{1} = Find.m{2} /\
    RCCA4.d{1} = Find.d{2} /\
    decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1}.
  proof.
    proc.
    sp; if => //.
      seq 0 2 :
       (={pms, t, p, s, V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
        V.sk{1} = PCA.V.sk{2} /\
        V.pk{1} = Find.pk{2} /\
        RCCA4.m{1} = Find.m{2} /\
        RCCA4.d{1} = Find.d{2} /\
        decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1} /\
        ((in_dom t RCCA4.d /\
          let (ms, pv, h, c) = oget RCCA4.d.[t] in
            p = (pv, h) /\ decrypt pv V.sk c = Some pms){1} <=>
         (in_dom t Find.d /\ p = (pv, h) /\ found){2})).
        sp; exists * pms{2}, pv{2}, c{2}; elim *; intros pms pv c.
        by call{2} (check_spec pv pms c); skip; progress; smt.
        by if => //; wp; try rnd; skip; progress.
      by wp.
  qed.

  local equiv RCCA4_Find_dec_choose :
    RCCA4.O2.dec ~ Find(O).O2.dec :
    ={p, t, c} /\ ={V.keys, V.labels, V.guess, V.t} /\
    !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\
    RCCA4.m{1} = Find.m{2} /\
    RCCA4.d{1} = Find.d{2} /\
    decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1}
    ==>
    ={res} /\ ={V.keys, V.labels, V.guess, V.t} /\
    !V.guess{1} /\
    V.pk{1} = Find.pk{2} /\
    V.sk{1} = PCA.V.sk{2} /\
    RCCA4.m{1} = Find.m{2} /\
    RCCA4.d{1} = Find.d{2} /\
    decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1}.
  proof.
    proc.
    sp; if => //.
    sp; if => //; first by smt.
    seq 0 1 :
     (maybe_k{1} = None /\
      ={maybe_k, pv, h, p, t, c, V.labels, V.keys, V.guess, V.t} /\
      !V.guess{1} /\
      V.pk{1} = Find.pk{2} /\
      V.sk{1} = PCA.V.sk{2} /\
      RCCA4.m{1} = Find.m{2} /\
      RCCA4.d{1} = Find.d{2} /\
      decrypt (fst pp) V.sk{1} V.c{1} = Some V.pms{1} /\
      !(V.guess /\ p = pp /\ t = V.t /\ V.c = c){1} /\
      ((decrypt pv V.sk c <> None /\
        in_dom ((pv, h), (oget (decrypt pv V.sk c), t)) RCCA4.m){1} <=>
       maybe_pms{2} <> None) /\
      (maybe_pms <> None =>
       maybe_pms = Some (oget (decrypt pv PCA.V.sk c))){2}).
      sp; exists * pv{2}, c{2}, h{2}, t{2}; elim *; intros pv c h t ? ?.
      call{2} (find_spec pv c h t); skip; progress.
        by smt.
        by smt.
        by smt.
        by generalize H4; elim (decrypt pv{2} PCA.V.sk{2} c{2}); smt.

      if => //.
        by wp; skip; smt.
        by wp; rnd.
  qed.

  local equiv RCCA4_OW_PCA0 :
    RCCA4.main ~ OW_PCA0.main :
    true ==> (exists t, in_dom (pp, (V.pms, t)) RCCA4.m){1} => res{2}.
  proof.
    proc.
    inline OW_PCA0.B.choose OW_PCA0.B.guess.
    swap{2} 7 -4; swap{2} [9..10] -5; swap{2} [7..8] -1; wp.
    seq 6 8 :
      (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
       RCCA4.m{1} = Find.m{2} /\ RCCA4.d{1} = Find.d{2} /\
       V.pk{1} = pk{2} /\ V.sk{1} = PCA.V.sk{2} /\
       pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
       V.pms{1} = k{2} /\ V.c{1} = c{2} /\
       (decrypt (fst pp) V.sk V.c = Some V.pms){1}).
    seq 5 5 : (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
       RCCA4.m{1} = Find.m{2} /\ RCCA4.d{1} = Find.d{2} /\
       V.pk{1} = pk{2} /\ V.sk{1} = PCA.V.sk{2} /\ keypair(V.pk, V.sk){1}).
    inline V.init; wp; call keygen_spec_rel; call (_:true).
    by skip; progress; try apply stateless_pms_kem; smt.
    sp; exists * V.sk{1}, V.pk{1}; elim *; intros sk pk.
    call (enc_spec_rel sk pk (fst pp)); wp; skip; progress.
      by generalize H2; smt.
    seq 6 8 : (={V.keys, V.labels, V.guess, V.t, V.c} /\
     V.pk{1} = Find.pk{2} /\ V.sk{1} = PCA.V.sk{2} /\
     pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
     V.pms{1} = k{2} /\ V.c{2} = c0{2} /\
     RCCA4.m{1} = Find.m{2} /\
     RCCA4.d{1} = Find.d{2} /\
     (decrypt (fst pp) V.sk V.c = Some V.pms){1}).
    call (_: ={V.keys, V.labels, V.guess, V.t, V.c} /\
     V.pk{1} = Find.pk{2} /\
     V.sk{1} = PCA.V.sk{2} /\
     RCCA4.m{1} = Find.m{2} /\
     RCCA4.d{1} = Find.d{2} /\
     (decrypt (fst pp) V.sk V.c = Some V.pms){1}).
      by apply RCCA4_Find_dec_guess.
      by apply RCCA4_Find_extract_guess.
     wp; rnd; rnd; wp.
    call (_: ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
     V.pk{1} = Find.pk{2} /\
     V.sk{1} = PCA.V.sk{2} /\
     RCCA4.m{1} = Find.m{2} /\
     RCCA4.d{1} = Find.d{2} /\
     (decrypt (fst pp) V.sk V.c = Some V.pms){1}).
      by apply RCCA4_Find_dec_choose.
      by apply RCCA4_Find_extract_choose.
    by wp.
    wp; exists * c0{2}; elim *; intros c.
    call{2} (find_any_spec (fst pp) c).
    by wp; skip; progress; smt.
  qed.

  local lemma Pr_RCCA4_OW_PCA &m :
    Pr[RCCA4.main() @ &m : exists t, in_dom (pp, (V.pms, t)) RCCA4.m] <=
    Pr[PCA.OW_PCA(PMS_KEM, B).main() @ &m : res].
  proof.
    apply (Trans _ Pr[OW_PCA0.main() @ &m : res]).
    by byequiv RCCA4_OW_PCA0.
    by byequiv OW_PCA0_OW_PCA.
  qed.

  (** RCCA4 -> NR *)

  (* Adversary used in the reduction to NR_PCA *)
  local module C(PCO:PCA.Oracle) = {
    module F = Find(PCO)
    module A = A(Find(PCO).O1, Find(PCO).O2)

    proc choose(pk:pkey) : unit = { Find.pk = pk; }

    proc guess(c:ciphertext) : ciphertext = {
      var pms : pms;
      var k0, k1 : ms;
      var b' : bool;
      V.init();
      V.c = c;
      Find.m = FMap.empty;
      Find.d = FMap.empty;
      V.t = A.choose(Find.pk);
      k0 = $key;
      k1 = $key;
      V.keys = add k0 (add k1 V.keys);
      V.guess = true;
      b' = A.guess(c, k0);
      return let (k, pv, h, c) = oget Find.d.[V.t] in c;
    }
  }.

  local module NR_PCA0 = {
    module C = C(O)

    proc main() : bool = {
      var pk : pkey;
      var p : version;
      var k : pms;
      var maybe_k : pms option;
      var c, c' : ciphertext;
      PMS_KEM.init();
      (pk, PCA.V.sk) = PMS_KEM.keygen();
      (k, c) = PMS_KEM.enc(fst pp, pk, ());
      C.choose(pk);
      c' = C.guess(c);
      maybe_k = PMS_KEM.dec(fst pp, PCA.V.sk, (), c');
      return (c <> c' /\ maybe_k = Some k);
    }
  }.

  local equiv NR_PCA0_NR_PCA :
    NR_PCA0.main ~ PCA.NR_PCA(PMS_KEM, C).main : true ==> ={res}.
  proof.
    proc.
    swap{1} 3 1.
    inline PCA.NR_PCA(PMS_KEM, C).A.guess NR_PCA0.C.guess.
    call (_: ={glob Find, glob PCA.V}); wp.
    sim true (={glob PCA.V}) : (={k,c,glob Find,glob PCA.V}).
    by apply OW_PCA0_OW_PCA_check.
    progress.
      by cut X : forall x, tt = x by smt; apply X.
      by apply stateless_pms_kem.
    seq 3 3 : (={pk,Find.pk,glob PCA.V} /\
      keypair(pk, PCA.V.sk){2} /\ pk{1} = Find.pk{1}).
    inline PCA.NR_PCA(PMS_KEM, C).A.choose NR_PCA0.C.choose; wp.
    call keygen_spec_rel; call (_:true).
    skip; progress; try apply stateless_pms_kem; smt.
    exists * PCA.V.sk{1}, pk{1}; elim *; intros sk pk.
    call (enc_spec_rel sk pk (fst pp)); skip; progress.
    cut X : forall x, tt = x by smt; apply X.
  qed.

  local equiv RCCA4_NR_PCA0 :
    RCCA4.main ~ NR_PCA0.main :
    true ==>
    (let (k, pv, h, c) = oget RCCA4.d.[V.t] in
       pv = fst pp /\ h = snd pp /\
       c <> V.c /\ decrypt pv V.sk c = Some V.pms){1} => res{2}.
  proof.
    proc.
    inline NR_PCA0.C.choose NR_PCA0.C.guess.
    swap{2} 7 -4; swap{2} [9..10] -5; swap{2} [7..8] -1; wp.
    seq 6 8 :
      (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
       RCCA4.m{1} = Find.m{2} /\ RCCA4.d{1} = Find.d{2} /\
       V.pk{1} = pk{2} /\ V.sk{1} = PCA.V.sk{2} /\
       pk0{2} = pk{2} /\ pk{2} = Find.pk{2} /\
       V.pms{1} = k{2} /\ V.c{1} = c{2} /\
       (decrypt (fst pp) V.sk V.c = Some V.pms){1}).
     seq 5 5 : (={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
       RCCA4.m{1} = Find.m{2} /\ RCCA4.d{1} = Find.d{2} /\
       V.pk{1} = pk{2} /\ V.sk{1} = PCA.V.sk{2} /\ keypair(V.pk, V.sk){1}).
     inline V.init; wp; call keygen_spec_rel; call (_:true).
     skip; progress; try apply stateless_pms_kem; smt.
     sp; exists * V.sk{1}, V.pk{1}; elim *; intros sk pk.
     call (enc_spec_rel sk pk (fst pp)); wp; skip; progress.
       by generalize H2; smt.
    seq 6 8 : (={V.keys, V.labels, V.guess, V.t, V.c} /\
     V.pk{1} = Find.pk{2} /\
     V.sk{1} = PCA.V.sk{2} /\ V.c{2} = c0{2} /\ c{2} = c0{2} /\ pk0{2} = pk{2} /\
     V.pms{1} = k{2} /\
     RCCA4.m{1} = Find.m{2} /\
     RCCA4.d{1} = Find.d{2} /\
     (decrypt (fst pp) V.sk V.c = Some V.pms){1}).
    call (_: ={V.keys, V.labels, V.guess, V.t, V.c} /\
     V.pk{1} = Find.pk{2} /\
     V.sk{1} = PCA.V.sk{2} /\
     RCCA4.m{1} = Find.m{2} /\
     RCCA4.d{1} = Find.d{2} /\
     (decrypt (fst pp) V.sk V.c = Some V.pms){1}).
      by apply RCCA4_Find_dec_guess.
      by apply RCCA4_Find_extract_guess.
     wp; rnd; rnd; wp.
    call (_: ={V.keys, V.labels, V.guess, V.t} /\ !V.guess{1} /\
     V.pk{1} = Find.pk{2} /\
     V.sk{1} = PCA.V.sk{2} /\
     RCCA4.m{1} = Find.m{2} /\
     RCCA4.d{1} = Find.d{2} /\
     (decrypt (fst pp) V.sk V.c = Some V.pms){1}).
      by apply RCCA4_Find_dec_choose.
      by apply RCCA4_Find_extract_choose.
    by wp.

    sp; wp; exists * PCA.V.sk{2}, c'{2}; elim *; intros sk c.
    call{2} (dec_spec sk (fst pp) c).
    by skip; smt.
  qed.

  local lemma Pr_RCCA4_NR_PCA &m :
    Pr[RCCA4.main() @ &m : let (k, pv, h, c) = oget RCCA4.d.[V.t] in
       pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms] <=
    Pr[PCA.NR_PCA(PMS_KEM, C).main() @ &m : res].
  proof.
    apply (Trans _ Pr[NR_PCA0.main() @ &m : res]).
    by byequiv RCCA4_NR_PCA0.
    by byequiv NR_PCA0_NR_PCA.
  qed.

  (** Conclusion **)
  module RCCA = Outer_KEM.RCCA.RCCA.

  lemma Conclusion &m :
    exists (B <: PCA.OW_Adversary {PCA.V}) (C <: PCA.NR_Adversary {PCA.V}),
      Pr[RCCA(KEM(RO_KEF, PMS_KEM), A(RO_KEF)).main() @ &m : res] - 1%r / 2%r <=
      qKEF%r / (card (toFSet univ<:pms>))%r +
      Pr[PCA.OW_PCA(PMS_KEM, B).main() @ &m : res] +
      Pr[PCA.NR_PCA(PMS_KEM, C).main() @ &m : res].
  proof.
    exists B, C.
    cut X : forall (x y z:real), x <= y + z => x - y <= z by smt.
    apply X.
    apply (Trans _ (1%r / 2%r +
      (Pr[RCCA2.main() @ &m : exists pv h t, in_dom ((pv, h), (oget RCCA2.fake.[(pv, t)], t)) RCCA2.m] +
      Pr[RCCA3.main() @ &m : RCCA3.abort]))).
    cut W := Pr_RCCA_RCCA3 &m; smt.
    apply addleM => //.
    cut -> : forall (x y z:real), x + y + z = x + (y + z) by smt.
    apply addleM => //.
    apply (Pr_RCCA2 &m).
    apply (Trans _
      (Pr[RCCA4.main() @ &m : exists t, in_dom (pp, (V.pms, t)) RCCA4.m] +
       Pr[RCCA4.main() @ &m : let (k, pv, h, c) = oget RCCA4.d.[V.t] in
          pv = fst pp /\ h = snd pp /\ c <> V.c /\ decrypt pv V.sk c = Some V.pms])).
    by apply (Pr_RCCA3_RCCA4 &m).
    apply addleM.
      by apply (Pr_RCCA4_OW_PCA &m).
      by apply (Pr_RCCA4_NR_PCA &m).
  qed.

end section.

print axiom Conclusion.
print module type Adversary.
