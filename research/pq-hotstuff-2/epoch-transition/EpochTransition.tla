---------------------------- MODULE EpochTransition ----------------------------
(***************************************************************************)
(* Research model of the PQ-HotStuff-2 epoch-transition rules proposed in  *)
(* docs/pq-hotstuff-001-spec.md sections 3.6 and 3.7 (PR #130, head        *)
(* 72c24df31b4e67a573374bb8102f69dde6996c01).                               *)
(*                                                                         *)
(* This models the PROPOSED rules. It is a bounded model; passing it is    *)
(* evidence within the bounds, not a proof of unbounded safety.             *)
(*                                                                         *)
(* Abstractions (all documented in REPORT.md):                             *)
(*  - Cryptography is perfect; Byzantine validators are implicit: they can *)
(*    contribute a vote or timeout to ANY certificate at ANY time and are  *)
(*    never required to obey a rule. Honest validators are explicit.       *)
(*  - Power is 1 per validator; quorum is floor(2T/3)+1.                   *)
(*  - A block is identified by its content (nested tuple), so equal blocks *)
(*    are equal and ancestry is structural.                                *)
(*  - Payload content is abstracted to a kind: N (normal), EC (epoch       *)
(*    change, carrying a candidate successor set), S (canonically empty    *)
(*    suffix block).                                                       *)
(*  - Only one transition 0 -> 1 is modelled (a second epoch change in     *)
(*    epoch 1 is not generated); competing epoch-change blocks are.        *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    V0, SetA, SetB,       \* epoch-0 set and the two candidate successor sets
    Byz,                  \* Byzantine validators (implicit)
    R,                    \* maximum round
    EagerOn,              \* reduction: validators outside LagSet always learn everything before acting (they never lag)
    LagSet,               \* validators allowed to lag when EagerOn
    PreludeDeep,          \* prelude plus: the honest epoch-0 members have also sent their round-2 timeouts (hqc round 1)
    PreludeOn,            \* start from a reachable state in which the honest epoch-0 members have already voted for P and Z
    SkeletonOn,           \* scenario-directed mode: the blocks of the conflicting-commit scenario are pre-proposed; proposing is off
    MaxBP,                \* maximum blocks a Byzantine leader may propose per round
    MaxProps,             \* exploration bound: maximum number of proposed blocks
    MaxTos,               \* exploration bound: maximum number of honest timeouts sent
    SealOn,               \* EC-6 seal (mutation: FALSE)
    SealOnLearn,          \* alternative interpretation: seal when the completing QC is LEARNED, not at the vote
    BoundaryCheck,        \* verifiers reject certificates inconsistent with a known boundary row (mutation: FALSE)
    EmptySuffix,          \* EC-3 suffix blocks must be canonically empty (mutation: FALSE)
    FloorPersist,         \* persisted floors survive an epoch change (mutation: FALSE = merged store behaviour K1)
    AtomicPersist,        \* persist before send (mutation: FALSE = send, then persist, crash can lose it)
    StageVotes,           \* TRUE: persist and send are separate steps (needed when CrashOn); FALSE: one atomic step (state-space reduction when no crashes)
    CrashOn,              \* crash/restart events enabled
    ByzActive,            \* Byzantine validators contribute votes/timeouts (FALSE = silent, worst case for liveness)
    ByzProposeOn,         \* Byzantine leaders may propose
    Sync,                 \* liveness mode: timeouts only at global quiescence, no crashes
    SnapSync              \* state-space reduction: validators share a global network view (snapshot synchrony)

ASSUME R \in 2..8
ASSUME MaxBP \in 1..3

GEN  == <<0>>
NONE == <<>>
Keys == {"S0", "A", "B"}
SetOf(k) == IF k = "S0" THEN V0 ELSE IF k = "A" THEN SetA ELSE SetB
Honest == ((V0 \cup SetA) \cup SetB) \ Byz
Quorum(S) == (2 * Cardinality(S)) \div 3 + 1
ByzCnt(S) == IF ByzActive THEN Cardinality(S \cap Byz) ELSE 0
Max2(a, b) == IF a >= b THEN a ELSE b
Leader(k, r) == LET S == SetOf(k) IN
    IF S = {} THEN -1 ELSE CHOOSE x \in S : Cardinality({y \in S : y < x}) = r % Cardinality(S)

\* ---- block accessors (genesis GEN has only a round) ----
Rnd(b) == b[1]
Par(b) == b[2]
Kd(b)  == b[3]
Ns(b)  == b[4]
Prp(b) == b[5]
Tc(b)  == b[6]


\* ---- scenario skeleton (SkeletonOn): the chain  GEN <- P(EC) <- Z <- X(epoch 1) <- C  and the
\* competing epoch-0 fork  P <- W (round 3, justified by TC(2)) <- W2 (round 4).  A conflicting commit
\* needs QC(X) (commits Z) and QC(W2) (commits W).  Votes, timeouts, learning, crashes stay free.
SkP  == <<1, GEN, "EC", "A", Leader("S0", 1), NONE>>
SkZ  == <<2, SkP, "S", "-", Leader("S0", 2), NONE>>
SkX  == <<3, SkZ, "N", "-", Leader("A", 3), NONE>>
SkC  == <<4, SkX, "N", "-", Leader("A", 4), NONE>>
SkTc == <<"S0", 0, 2, 1, SkP>>
SkW  == <<3, SkP, "S", "-", Leader("S0", 3), SkTc>>
SkW2 == <<4, SkW, "S", "-", Leader("S0", 4), NONE>>
Skel == {SkP, SkZ, SkX, SkC, SkW, SkW2}

VARIABLES
    votes,     \* set of <<voter, block>> honest votes that have left the node
    tos,       \* set of <<voter, epoch, round, hqcRound>> honest timeouts that have left the node
    props,     \* set of proposed blocks
    hvr, hqr,  \* persisted floors: highest voted/timed-out round, highest QC round voted on
    seal,      \* persisted seal round for epoch 0 (-1 = none)
    pend,      \* persisted pending vote (persisted, not yet sent) or NONE
    upend,     \* mutation only: vote already sent but not yet persisted (volatile)
    rows,      \* persisted boundary rows: set of <<z, P>>
    recep,     \* persisted epoch of the last record (used by the floor-reset mutation)
    lastprop,  \* persisted last proposed round
    view,      \* volatile knowledge: set of <<"B",b>>, <<"Q",b>>, <<"T",tc>>
    comm,      \* persisted committed blocks
    info       \* memo of the chain information of every proposed block

vars == <<votes, tos, props, hvr, hqr, seal, pend, upend, rows, recep, lastprop, view, comm, info>>

\* ---------------------------------------------------------------------------
\* Chain information, computed structurally from content
\* ---------------------------------------------------------------------------
GENINFO == [ok |-> TRUE, ep |-> 0, key |-> "S0", pend |-> NONE, ecp |-> 0, zb |-> -1, cp |-> NONE, zp |-> FALSE, anc |-> {GEN}]

\* One step of the chain information from the parent's information (ia).  zp = "this block is the
\* second block of a consecutive pair (Y, b) with Y = P or a suffix block of P", i.e. its certificate
\* completes the commit of the pending epoch-change block P.
InfoStep(b, ia) ==
     LET a   == Par(b)
         cmp == ia.zp
         okK == IF cmp THEN Kd(b) = "N"
                ELSE IF ia.pend # NONE
                     THEN (IF EmptySuffix THEN Kd(b) = "S" ELSE Kd(b) \in {"S", "N", "EC"})
                     ELSE (Kd(b) = "N" \/ (Kd(b) = "EC" /\ ia.ep = 0))
         okN == IF Kd(b) = "EC"
                THEN Ns(b) \in {"A", "B"} /\ SetOf(Ns(b)) # {}
                ELSE Ns(b) = "-"
         okv == ia.ok /\ Rnd(b) > Rnd(a) /\ okK /\ okN
         pv  == IF cmp THEN NONE
                ELSE IF ia.pend # NONE THEN ia.pend
                ELSE IF Kd(b) = "EC" THEN b ELSE NONE
     IN [ok   |-> okv,
         ep   |-> IF cmp THEN ia.ep + 1 ELSE ia.ep,
         key  |-> IF cmp THEN Ns(ia.pend) ELSE ia.key,
         pend |-> pv,
         ecp  |-> IF cmp THEN 0 ELSE ia.ecp + (IF Kd(b) = "EC" THEN 1 ELSE 0),
         zb   |-> IF cmp THEN Rnd(a) ELSE ia.zb,
         cp   |-> IF cmp THEN ia.pend ELSE ia.cp,
         zp   |-> okv /\ pv # NONE /\ b # pv /\ ia.pend = pv /\ Rnd(b) = Rnd(a) + 1,
         anc  |-> {b} \cup ia.anc]

\* memoised: info[b] is stored for every proposed block; a candidate (not yet proposed) costs one InfoStep
RECURSIVE Info(_)
Info(b) == IF b = GEN THEN GENINFO
           ELSE IF b \in DOMAIN info THEN info[b]
           ELSE InfoStep(b, Info(Par(b)))

ZP(a) == a # GEN /\ Info(a).zp

\* constant-level full recursion (no memo); used by the self-tests and by Inv_InfoMemoConsistent
RECURSIVE InfoFull(_)
InfoFull(b) == IF b = GEN THEN GENINFO ELSE InfoStep(b, InfoFull(Par(b)))
ZPF(a) == a # GEN /\ InfoFull(a).zp

AncSelf(b) == Info(b).anc

SetOfBlk(b) == SetOf(Info(b).key)
PropOK(b) == Info(b).ok /\ Prp(b) = Leader(Info(b).key, Rnd(b))

\* ---------------------------------------------------------------------------
\* Certificates (global existence; Byzantine validators always help)
\* ---------------------------------------------------------------------------
QCExists(b) ==
    \/ b = GEN
    \/ /\ b \in props
       /\ Info(b).ok
       /\ LET S == SetOfBlk(b) IN
            Cardinality({u \in S \cap Honest : <<u, b>> \in votes}) + ByzCnt(S) >= Quorum(S)

QCSetOf == {b \in props : QCExists(b)}

TCForm(k, E, r, nb, Q) ==
    LET S   == SetOf(k)
        hon == {u \in S \cap Honest : \E m \in 0..R : /\ <<u, E, r, m>> \in tos
                                                       /\ m <= Rnd(nb)}
        hasMax == \/ \E u \in S \cap Honest : <<u, E, r, Rnd(nb)>> \in tos
                  \/ ByzCnt(S) > 0
    IN /\ S # {}
       /\ Cardinality(hon) + ByzCnt(S) >= Quorum(S)
       /\ hasMax
       /\ (nb = GEN \/ nb \in Q)

TCCand == {<<k, E, r, Rnd(nb), nb>> : k \in Keys, E \in 0..1, r \in 1..R, nb \in props \cup {GEN}}
TCSetOf(Q) == {t \in TCCand : TCForm(t[1], t[2], t[3], t[5], Q)}

\* a TC is acceptable in block b: right round, right epoch and set for that round in b's chain
TcOk(b, T) ==
    LET t  == Tc(b)
        zb == Info(b).zb
    IN /\ t # NONE
       /\ t \in T
       /\ t[3] = Rnd(b) - 1
       /\ t[4] <= Rnd(Par(b))
       /\ t[2] = (IF zb >= 0 /\ t[3] > zb THEN 1 ELSE 0)
       /\ t[1] = (IF t[2] = 1 THEN Info(b).key ELSE "S0")

\* ---------------------------------------------------------------------------
\* What a validator accepts, given its persisted boundary rows
\* ---------------------------------------------------------------------------
LabelOK(v, b) ==
    \/ ~BoundaryCheck
    \/ \A rw \in rows[v] :
         /\ (Info(b).ep = 0 => Rnd(b) <= rw[1])
         /\ (Info(b).ep = 1 => (Info(b).zb = rw[1] /\ Info(b).cp = rw[2]))

QCValidFor(v, b, Q) == b = GEN \/ (b \in Q /\ LabelOK(v, b))

ClosureValid(v, b, Q) ==
    \A x \in AncSelf(b) \ {GEN} : x \in props /\ Info(x).ok /\ QCValidFor(v, Par(x), Q)

ClosureItems(b) ==
    {<<"B", x>> : x \in AncSelf(b)} \cup {<<"Q", Par(x)>> : x \in AncSelf(b) \ {GEN}}

QsOf(V)  == {i[2] : i \in {j \in V : j[1] = "Q"}}
TCsOf(V) == {i[2] : i \in {j \in V : j[1] = "T"}}

DerivedRows(V) == {<<Rnd(x), Info(x).pend>> : x \in {y \in QsOf(V) : ZP(y)}}
DerivedComm(V) == UNION {AncSelf(Par(c)) : c \in {x \in QsOf(V) : x # GEN /\ Rnd(x) = Rnd(Par(x)) + 1}}

TcLabelOK(v, t) ==
    IF rows[v] = {} THEN t[2] = 0 /\ t[1] = "S0"
    ELSE \A rw \in rows[v] :
           /\ t[2] = (IF t[3] > rw[1] THEN 1 ELSE 0)
           /\ t[1] = (IF t[2] = 1 THEN Ns(rw[2]) ELSE "S0")

\* ---------------------------------------------------------------------------
\* Persisted-floor views (the floor-reset mutation resets them on an epoch increase)
\* ---------------------------------------------------------------------------
EffHvr(v, e)  == IF ~FloorPersist /\ e > recep[v] THEN 0 ELSE hvr[v]
EffHqr(v, e)  == IF ~FloorPersist /\ e > recep[v] THEN 0 ELSE hqr[v]
EffSeal(v, e) == IF ~FloorPersist /\ e > recep[v] THEN -1 ELSE seal[v]

SealBlocks(v, e, b) ==  \* the seal forbids signing epoch-0 objects above the sealed round
    SealOn /\ e = 0 /\ EffSeal(v, 0) >= 0 /\ Rnd(b) > EffSeal(v, 0)

BoundaryBlocks(v, b) ==
    BoundaryCheck /\ ~LabelOK(v, b)

\* ---------------------------------------------------------------------------
\* Actions
\* ---------------------------------------------------------------------------
LearnBlockOK(v, b, Q) ==
    /\ b \in props
    /\ <<"B", b>> \notin view[v]
    /\ ClosureValid(v, b, Q)
    /\ (Tc(b) = NONE \/ <<"T", Tc(b)>> \in view[v])

LearnBlock(v, b, Q) ==
    /\ LearnBlockOK(v, b, Q)
    /\ LET nv == view[v] \cup ClosureItems(b) IN
         /\ view' = [view EXCEPT ![v] = nv]
         /\ rows' = [rows EXCEPT ![v] = rows[v] \cup DerivedRows(nv)]
         /\ comm' = [comm EXCEPT ![v] = comm[v] \cup DerivedComm(nv)]
         /\ seal' = [seal EXCEPT ![v] =
                IF SealOnLearn /\ \E z \in QsOf(nv) : ZP(z) /\ Info(z).ep = 0
                THEN Max2(seal[v], 0 + CHOOSE m \in {Rnd(z) : z \in {y \in QsOf(nv) : ZP(y) /\ Info(y).ep = 0}} :
                              \A n \in {Rnd(z) : z \in {y \in QsOf(nv) : ZP(y) /\ Info(y).ep = 0}} : n <= m)
                ELSE seal[v]]
    /\ UNCHANGED <<votes, tos, props, hvr, hqr, pend, upend, recep, lastprop, info>>

LearnQCOK(v, b, Q) ==
    /\ b # GEN
    /\ <<"B", b>> \in view[v]
    /\ <<"Q", b>> \notin view[v]
    /\ QCValidFor(v, b, Q)

LearnQC(v, b, Q) ==
    /\ LearnQCOK(v, b, Q)
    /\ LET nv == view[v] \cup {<<"Q", b>>} IN
         /\ view' = [view EXCEPT ![v] = nv]
         /\ rows' = [rows EXCEPT ![v] = rows[v] \cup DerivedRows(nv)]
         /\ comm' = [comm EXCEPT ![v] = comm[v] \cup DerivedComm(nv)]
         /\ seal' = [seal EXCEPT ![v] =
                IF SealOnLearn /\ ZP(b) /\ Info(b).ep = 0 THEN Max2(seal[v], Rnd(b)) ELSE seal[v]]
    /\ UNCHANGED <<votes, tos, props, hvr, hqr, pend, upend, recep, lastprop, info>>

LearnTCOK(v, t, T, Q) ==
    /\ t \in T
    /\ <<"T", t>> \notin view[v]
    /\ ClosureValid(v, t[5], Q)
    /\ QCValidFor(v, t[5], Q)
    /\ (BoundaryCheck => TcLabelOK(v, t))

LearnTC(v, t, T, Q) ==
    /\ LearnTCOK(v, t, T, Q)
    /\ LET nv == view[v] \cup {<<"T", t>>} \cup ClosureItems(t[5]) \cup (IF t[5] = GEN THEN {} ELSE {<<"Q", t[5]>>}) IN
         /\ view' = [view EXCEPT ![v] = nv]
         /\ rows' = [rows EXCEPT ![v] = rows[v] \cup DerivedRows(nv)]
         /\ comm' = [comm EXCEPT ![v] = comm[v] \cup DerivedComm(nv)]
    /\ UNCHANGED <<votes, tos, props, hvr, hqr, seal, pend, upend, recep, lastprop, info>>

\* ---- voting ----
VoteOK(v, b, T) ==
    /\ b \in props
    /\ pend[v] = NONE
    /\ upend[v] = NONE
    /\ <<"B", b>> \in view[v]
    /\ PropOK(b)
    /\ v \in SetOfBlk(b)
    /\ Rnd(b) > EffHvr(v, Info(b).ep)
    /\ Rnd(b) > Rnd(Par(b))
    /\ (Tc(b) = NONE) <=> (Rnd(b) = Rnd(Par(b)) + 1)
    /\ (Tc(b) # NONE => (TcOk(b, T) /\ <<"T", Tc(b)>> \in view[v]))
    /\ ~BoundaryBlocks(v, b)
    /\ ~SealBlocks(v, Info(b).ep, b)
    /\ <<"V", v, Rnd(b)>> \notin {<<"V", x[1], Rnd(x[2])>> : x \in votes}   \* never two votes in one round

NewFloors(v, b) ==
    /\ hvr'  = [hvr  EXCEPT ![v] = Rnd(b)]
    /\ hqr'  = [hqr  EXCEPT ![v] = Max2(EffHqr(v, Info(b).ep), Rnd(Par(b)))]
    /\ seal' = [seal EXCEPT ![v] =
                  IF SealOn /\ ~SealOnLearn /\ ZP(b) /\ Info(b).ep = 0 THEN Rnd(b)
                  ELSE EffSeal(v, Info(b).ep)]
    /\ recep' = [recep EXCEPT ![v] = Max2(recep[v], Info(b).ep)]

\* persist-then-send (AtomicPersist): stage 1 persists the vote record, stage 2 sends it
Vote(v, b, T) ==
    /\ VoteOK(v, b, T)
    /\ AtomicPersist
    /\ NewFloors(v, b)
    /\ pend' = [pend EXCEPT ![v] = IF StageVotes THEN b ELSE NONE]
    /\ votes' = IF StageVotes THEN votes ELSE votes \cup {<<v, b>>}
    /\ UNCHANGED <<tos, props, upend, rows, lastprop, view, comm, info>>

SendPending(v) ==
    /\ pend[v] # NONE
    /\ votes' = votes \cup {<<v, pend[v]>>}
    /\ pend' = [pend EXCEPT ![v] = NONE]
    /\ UNCHANGED <<tos, props, hvr, hqr, seal, upend, rows, recep, lastprop, view, comm, info>>

\* mutation: send first, persist later (a crash in between loses the record)
VoteSendFirst(v, b, T) ==
    /\ VoteOK(v, b, T)
    /\ ~AtomicPersist
    /\ votes' = votes \cup {<<v, b>>}
    /\ upend' = [upend EXCEPT ![v] = b]
    /\ UNCHANGED <<tos, props, hvr, hqr, seal, pend, rows, recep, lastprop, view, comm, info>>

PersistLate(v) ==
    /\ upend[v] # NONE
    /\ LET b == upend[v] IN
         /\ NewFloors(v, b)
         /\ upend' = [upend EXCEPT ![v] = NONE]
    /\ UNCHANGED <<votes, tos, props, pend, rows, lastprop, view, comm, info>>

\* ---- proposing ----
KindNs == {<<"N", "-">>, <<"S", "-">>} \cup {<<"EC", s>> : s \in {x \in {"A", "B"} : SetOf(x) # {}}}

HighRound(v) == LET rs == {Rnd(x) : x \in QsOf(view[v]) \cup {GEN}} IN CHOOSE m \in rs : \A n \in rs : n <= m

\* the set key (hence the leader schedule) of a child of a block with information ia
KeyAfter(ia) == IF ia.zp THEN Ns(ia.pend) ELSE ia.key

HonestCands(v, T) ==
    LET hr == HighRound(v)
        ps == {x \in QsOf(view[v]) \cup {GEN} : Rnd(x) = hr}
        cs == UNION {UNION {UNION {{<<r, p, kn[1], kn[2], v, t>> :
                      t \in (IF r = hr + 1 THEN {NONE} ELSE TCsOf(view[v]))} :
                      kn \in KindNs} :
                      r \in {q \in (hr + 1)..R : q > hvr[v] /\ q > lastprop[v] /\ Leader(KeyAfter(Info(p)), q) = v}} :
                      p \in ps}
    IN {b \in cs :
          LET ib == Info(b) IN
          /\ ib.ok
          /\ b \notin props
          /\ (Tc(b) # NONE => TcOk(b, T))
          /\ ~BoundaryBlocks(v, b)
          /\ ~SealBlocks(v, ib.ep, b)}

HonestPropose(v, b, T) ==
    /\ ~SkeletonOn
    /\ b \in HonestCands(v, T)
    /\ props' = props \cup {b}
    /\ info' = info @@ (b :> Info(b))
    /\ lastprop' = [lastprop EXCEPT ![v] = Rnd(b)]
    /\ view' = (IF SnapSync
                THEN [u \in Honest |-> view[u] \cup {<<"B", b>>}]
                ELSE [view EXCEPT ![v] = view[v] \cup {<<"B", b>>}])
    /\ UNCHANGED <<votes, tos, hvr, hqr, seal, pend, upend, rows, recep, comm>>

ByzCands(T, Q) ==
    UNION {UNION {UNION {{<<r, p, kn[1], kn[2], Leader(KeyAfter(Info(p)), r), t>> :
                      t \in (IF r = Rnd(p) + 1 THEN {NONE} ELSE T \cup {NONE})} :
                      kn \in KindNs} :
                      r \in {q \in (Rnd(p) + 1)..R : Leader(KeyAfter(Info(p)), q) \in Byz}} :
                      p \in (Q \cup {GEN})}

ByzPropose(b, T, Q) ==
    /\ ByzProposeOn /\ ~SkeletonOn
    /\ b \in ByzCands(T, Q)
    /\ Prp(b) \in Byz
    /\ Info(b).ok
    /\ Rnd(b) > Rnd(Par(b))
    /\ (Tc(b) # NONE => TcOk(b, T))
    /\ b \notin props
    /\ Cardinality({x \in props : Prp(x) = Prp(b) /\ Rnd(x) = Rnd(b)}) < MaxBP
    /\ props' = props \cup {b}
    /\ info' = info @@ (b :> Info(b))
    /\ UNCHANGED <<votes, tos, hvr, hqr, seal, pend, upend, rows, recep, lastprop, view, comm>>

\* ---------------------------------------------------------------------------
\* Quiescence (liveness mode): no deliverable message and no enabled honest step other than timeouts
\* ---------------------------------------------------------------------------
Quiescent(T, Q) ==
    ~( \/ \E v \in Honest, b \in props : LearnBlockOK(v, b, Q) \/ LearnQCOK(v, b, Q) \/ VoteOK(v, b, T)
       \/ \E v \in Honest : pend[v] # NONE \/ upend[v] # NONE \/ HonestCands(v, T) # {}
       \/ \E v \in Honest, t \in T : LearnTCOK(v, t, T, Q) )

\* ---- timeouts ----
RowOf(v) == CHOOSE rw \in rows[v] : TRUE

TimeoutParams(v, r) ==
    LET qs == QsOf(view[v]) \cup {GEN}
        rs == {Rnd(x) : x \in qs}
        mv == CHOOSE m \in rs : \A n \in rs : n <= m
        E  == IF rows[v] # {} /\ r > RowOf(v)[1] THEN 1 ELSE 0
        k  == IF E = 1 THEN Ns(RowOf(v)[2]) ELSE "S0"
    IN [mv |-> mv, E |-> E, k |-> k]

TimeoutOK(v, r) ==
    LET p == TimeoutParams(v, r) IN
    /\ r \in 1..R
    /\ v \in SetOf(p.k)
    /\ p.mv >= EffHqr(v, p.E)
    /\ r > Max2(EffHvr(v, p.E) - 1, p.mv)
    /\ (r = p.mv + 1 \/ \E t \in TCsOf(view[v]) : t[3] = r - 1 /\ t[4] <= p.mv)
    /\ ~(SealOn /\ p.E = 0 /\ EffSeal(v, 0) >= 0 /\ r > EffSeal(v, 0))
    /\ \A x \in tos : ~(x[1] = v /\ x[3] = r)
    /\ (BoundaryCheck => (rows[v] # {} \/ p.E = 0))

Timeout(v, r, T, Q) ==
    /\ TimeoutOK(v, r)
    /\ (Sync => Quiescent(T, Q))
    /\ LET p == TimeoutParams(v, r) IN
         /\ tos' = tos \cup {<<v, p.E, r, p.mv>>}
         /\ hvr' = [hvr EXCEPT ![v] = Max2(EffHvr(v, p.E), r)]
         /\ hqr' = [hqr EXCEPT ![v] = EffHqr(v, p.E)]
         /\ seal' = [seal EXCEPT ![v] = EffSeal(v, p.E)]
         /\ recep' = [recep EXCEPT ![v] = Max2(recep[v], p.E)]
    /\ UNCHANGED <<votes, props, pend, upend, rows, lastprop, view, comm, info>>

\* ---- crash / restart: volatile knowledge and an unpersisted vote are lost ----
\* In SnapSync mode the global network view is not erased; only the unpersisted vote is lost.
Crash(v) ==
    /\ CrashOn
    /\ (IF SnapSync THEN upend[v] # NONE ELSE view[v] # {} \/ upend[v] # NONE)
    /\ view' = (IF SnapSync THEN view ELSE [view EXCEPT ![v] = {}])
    /\ upend' = [upend EXCEPT ![v] = NONE]
    /\ UNCHANGED <<votes, tos, props, hvr, hqr, seal, pend, rows, recep, lastprop, comm, info>>

Goal == \E c \in props : /\ QCExists(c)
                         /\ Info(c).ep = 1
                         /\ Rnd(c) = Rnd(Par(c)) + 1
                         /\ Info(Par(c)).ep = 1

BoundHit == (\E x \in props : Rnd(x) >= R) \/ (\E x \in tos : x[3] >= R)

Stutter == (Goal \/ BoundHit) /\ UNCHANGED vars

PreludeView == {<<"B", x>> : x \in InfoFull(SkZ).anc} \cup {<<"Q", Par(x)>> : x \in InfoFull(SkZ).anc \ {GEN}}
HV0 == V0 \ Byz   \* honest epoch-0 members (the prelude voters)
PreludeSeal == IF SealOn /\ ~SealOnLearn THEN Rnd(SkZ) ELSE -1

Init ==
    /\ votes = (IF PreludeOn THEN {<<u, x>> : u \in HV0, x \in {SkP, SkZ}} ELSE {})
    /\ tos = (IF PreludeOn /\ PreludeDeep THEN {<<u, 0, Rnd(SkZ), Rnd(SkP)>> : u \in HV0} ELSE {})
    /\ props = (IF SkeletonOn THEN Skel ELSE {})
    /\ hvr = [v \in Honest |-> IF PreludeOn /\ v \in HV0 THEN Rnd(SkZ) ELSE 0]
    /\ hqr = [v \in Honest |-> IF PreludeOn /\ v \in HV0 THEN Rnd(SkP) ELSE 0]
    /\ seal = [v \in Honest |-> IF PreludeOn /\ v \in HV0 THEN PreludeSeal ELSE -1]
    /\ pend = [v \in Honest |-> NONE] /\ upend = [v \in Honest |-> NONE]
    /\ rows = [v \in Honest |-> {}]
    /\ recep = [v \in Honest |-> 0]
    /\ lastprop = [v \in Honest |-> 0]
    /\ view = [v \in Honest |-> IF PreludeOn /\ v \in HV0 THEN PreludeView ELSE {}]
    /\ comm = [v \in Honest |-> IF PreludeOn /\ v \in HV0 THEN {GEN} ELSE {}]
    /\ info = (IF SkeletonOn THEN [x \in Skel \cup {GEN} |-> InfoFull(x)] ELSE (GEN :> GENINFO))

CanLearn(u, T, Q) ==
    \/ \E b \in props : LearnBlockOK(u, b, Q) \/ LearnQCOK(u, b, Q)
    \/ \E t \in T : LearnTCOK(u, t, T, Q)

\* ---------------------------------------------------------------------------
\* SnapSync: global snapshot-synchrony abstraction (SnapSync = TRUE)
\* All validators share a single network view; learning is a global network event.
\* Eliminates delivery-order interleavings; reduces state space by ~10-100x.
\* Preserves: outgoing-set cutoff (rows updated for all validators), Byzantine
\* suppression of QC publication (SnapLearnQC is still a non-deterministic step),
\* and crash semantics (crash clears only unpersisted vote, not global view).
\* ---------------------------------------------------------------------------
SV == CHOOSE v \in Honest : TRUE  \* canonical validator for global-view ops

GlobalView == view[SV]  \* all validators see the same view when SnapSync

SnapLearnBlockOK(b, Q) ==
    /\ b \in props
    /\ <<"B", b>> \notin GlobalView
    /\ ClosureValid(SV, b, Q)
    /\ (Tc(b) = NONE \/ <<"T", Tc(b)>> \in GlobalView)

SnapLearnBlock(b, Q) ==
    /\ SnapLearnBlockOK(b, Q)
    /\ LET nv == GlobalView \cup ClosureItems(b) IN
         /\ view' = [v \in Honest |-> nv]
         /\ rows' = [v \in Honest |-> rows[v] \cup DerivedRows(nv)]
         /\ comm' = [v \in Honest |-> comm[v] \cup DerivedComm(nv)]
         /\ seal' = [v \in Honest |->
                IF SealOnLearn /\ \E z \in QsOf(nv) : ZP(z) /\ Info(z).ep = 0
                THEN Max2(seal[v], 0 + CHOOSE m \in {Rnd(z) : z \in {y \in QsOf(nv) : ZP(y) /\ Info(y).ep = 0}} :
                              \A n \in {Rnd(z) : z \in {y \in QsOf(nv) : ZP(y) /\ Info(y).ep = 0}} : n <= m)
                ELSE seal[v]]
    /\ UNCHANGED <<votes, tos, props, hvr, hqr, pend, upend, recep, lastprop, info>>

SnapLearnQCOK(b, Q) ==
    /\ b # GEN
    /\ <<"B", b>> \in GlobalView
    /\ <<"Q", b>> \notin GlobalView
    /\ QCValidFor(SV, b, Q)

SnapLearnQC(b, Q) ==
    /\ SnapLearnQCOK(b, Q)
    /\ LET nv == GlobalView \cup {<<"Q", b>>} IN
         /\ view' = [v \in Honest |-> nv]
         /\ rows' = [v \in Honest |-> rows[v] \cup DerivedRows(nv)]
         /\ comm' = [v \in Honest |-> comm[v] \cup DerivedComm(nv)]
         /\ seal' = [v \in Honest |->
                IF SealOnLearn /\ ZP(b) /\ Info(b).ep = 0 THEN Max2(seal[v], Rnd(b)) ELSE seal[v]]
    /\ UNCHANGED <<votes, tos, props, hvr, hqr, pend, upend, recep, lastprop, info>>

SnapLearnTCOK(t, T, Q) ==
    /\ t \in T
    /\ <<"T", t>> \notin GlobalView
    /\ ClosureValid(SV, t[5], Q)
    /\ QCValidFor(SV, t[5], Q)
    /\ (BoundaryCheck => TcLabelOK(SV, t))

SnapLearnTC(t, T, Q) ==
    /\ SnapLearnTCOK(t, T, Q)
    /\ LET nv == GlobalView \cup {<<"T", t>>} \cup ClosureItems(t[5]) \cup (IF t[5] = GEN THEN {} ELSE {<<"Q", t[5]>>}) IN
         /\ view' = [v \in Honest |-> nv]
         /\ rows' = [v \in Honest |-> rows[v] \cup DerivedRows(nv)]
         /\ comm' = [v \in Honest |-> comm[v] \cup DerivedComm(nv)]
    /\ UNCHANGED <<votes, tos, props, hvr, hqr, seal, pend, upend, recep, lastprop, info>>

Next ==
    LET Q == QCSetOf
        T == TCSetOf(Q)
        Settled ==
            IF SnapSync THEN
                ~( \/ \E b \in props : SnapLearnBlockOK(b, Q) \/ SnapLearnQCOK(b, Q)
                   \/ \E t \in T : SnapLearnTCOK(t, T, Q) )
            ELSE
                (~EagerOn) \/ (\A u \in Honest \ LagSet : ~CanLearn(u, T, Q))
    IN
    \/ (IF SnapSync
        THEN \E b \in props : SnapLearnBlock(b, Q) \/ SnapLearnQC(b, Q)
        ELSE \E v \in Honest : \E b \in props : LearnBlock(v, b, Q) \/ LearnQC(v, b, Q))
    \/ (IF SnapSync
        THEN \E t \in T : SnapLearnTC(t, T, Q)
        ELSE \E v \in Honest : \E t \in T : LearnTC(v, t, T, Q))
    \/ Settled /\ \E v \in Honest : \E b \in props : Vote(v, b, T) \/ VoteSendFirst(v, b, T)
    \/ Settled /\ \E v \in Honest : SendPending(v) \/ PersistLate(v) \/ Crash(v)
    \/ Settled /\ \E v \in Honest : \E r \in 1..R : Timeout(v, r, T, Q)
    \/ Settled /\ \E v \in Honest : \E b \in HonestCands(v, T) : HonestPropose(v, b, T)
    \/ Settled /\ \E b \in ByzCands(T, Q) : ByzPropose(b, T, Q)
    \/ Stutter

SizeBound == Cardinality(props) <= MaxProps /\ Cardinality(tos) <= MaxTos

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------------
\* Safety properties
\* ---------------------------------------------------------------------------
AllComm == UNION {comm[v] : v \in Honest}

\* S1: no two conflicting blocks are committed
Inv_NoConflictingCommit ==
    \A x, y \in AllComm : x \in AncSelf(y) \/ y \in AncSelf(x)

\* S2: no two conflicting epoch transitions become authoritative
Inv_NoConflictingTransition ==
    Cardinality(UNION {rows[v] : v \in Honest}) <= 1

\* S3: certificates known to a validator are backed by the quorum of THEIR OWN epoch's set
\*     (recomputed independently from the raw votes)
Inv_CertificatesUseOwnSet ==
    \A v \in Honest : \A b \in QsOf(view[v]) \ {GEN} :
        LET S == SetOf(Info(b).key) IN
          Cardinality({u \in S : u \in Byz \/ <<u, b>> \in votes}) >= Quorum(S)

\* S4: a validator that knows the boundary never holds an old-epoch certificate beyond it
Inv_NoOldEpochBeyondBoundary ==
    \A v \in Honest : \A rw \in rows[v] : \A b \in QsOf(view[v]) \ {GEN} :
        ~(Info(b).ep = 0 /\ Rnd(b) > rw[1])

\* S5: a vote never leaves without its durable record (floors and seal)
Inv_VoteDurable ==
    \A x \in votes :
        /\ hvr[x[1]] >= Rnd(x[2])
        /\ hqr[x[1]] >= Rnd(Par(x[2]))
        /\ ((SealOn /\ ~SealOnLearn /\ ZP(x[2]) /\ Info(x[2]).ep = 0) => seal[x[1]] >= Rnd(x[2]))

\* S6 (action property): persisted floors never decrease
FloorsMonotone ==
    \A v \in Honest : /\ hvr'[v] >= hvr[v] /\ hqr'[v] >= hqr[v] /\ seal'[v] >= seal[v]
                      /\ rows[v] \subseteq rows'[v] /\ comm[v] \subseteq comm'[v]

\* S7: an honest validator never votes twice in a round
Inv_NoHonestDoubleVote ==
    \A x, y \in votes : (x[1] = y[1] /\ Rnd(x[2]) = Rnd(y[2])) => x = y

\* S8: at most one epoch-change block may be pending on a certified chain
Inv_SingleTransitionPerChain ==
    \A b \in props : QCExists(b) => Info(b).ecp <= 1

\* the memo equals the full structural recomputation
Inv_InfoMemoConsistent == \A b \in props : info[b] = InfoFull(b)

\* reachability witnesses (violations of these are the evidence that the behaviour is reachable)
Inv_NotCompleted == ~Goal
Inv_NoBoundaryKnown == \A v \in Honest : rows[v] = {}
Inv_NoEpochOneBlock == \A b \in props : Info(b).ep = 0
Inv_NoSealed == \A v \in Honest : seal[v] < 0

Prop_Floors == [][FloorsMonotone]_vars
=============================================================================
