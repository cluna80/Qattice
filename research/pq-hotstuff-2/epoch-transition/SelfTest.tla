------------------------------ MODULE SelfTest ------------------------------
(* Model self-tests: static assertions on the helper operators of EpochTransition,  *)
(* evaluated by TLC as ASSUME statements before any state exploration.            *)
EXTENDS EpochTransition

A1  == <<1, GEN, "N",  "-", 0, NONE>>
P   == <<2, A1,  "EC", "A", 1, NONE>>
S3  == <<3, P,   "S",  "-", 2, NONE>>
X4  == <<4, S3,  "N",  "-", 4, NONE>>
S4  == <<4, S3,  "S",  "-", 3, NONE>>         \* a suffix block that is NOT the first block of epoch 1
S5g == <<5, S3,  "S",  "-", 0, NONE>>

\* ---- quorum arithmetic ----
ASSUME Quorum({0,1,2,3}) = 3
ASSUME Quorum({0,1,2}) = 3
ASSUME Quorum({0,1,2,3,4,5,6}) = 5
ASSUME Quorum({0}) = 1

\* ---- structure: a pending epoch-change block, its suffix and the completing certificate ----
ASSUME InfoFull(A1).ok /\ InfoFull(A1).ep = 0 /\ InfoFull(A1).pend = NONE
ASSUME InfoFull(P).ok /\ InfoFull(P).pend = P /\ InfoFull(P).ecp = 1
ASSUME InfoFull(S3).ok /\ InfoFull(S3).pend = P /\ InfoFull(S3).ep = 0
ASSUME ZPF(S3)                       \* S3 is the second block of the consecutive pair (P, S3)
ASSUME ~ZPF(P) /\ ~ZPF(A1)
ASSUME InfoFull(X4).ok /\ InfoFull(X4).ep = 1 /\ InfoFull(X4).zb = 3 /\ InfoFull(X4).cp = P /\ InfoFull(X4).key = "A" /\ InfoFull(X4).pend = NONE
ASSUME ~InfoFull(S4).ok                 \* after the completing pair a suffix kind is not allowed (the block is epoch 1, kind N only)

\* ---- EC-3: suffix blocks must be canonically empty ----
ASSUME EmptySuffix => ~InfoFull(<<3, P, "N", "-", 2, NONE>>).ok
ASSUME EmptySuffix => ~InfoFull(<<3, P, "EC", "A", 2, NONE>>).ok
ASSUME (~EmptySuffix) => InfoFull(<<3, P, "N", "-", 2, NONE>>).ok
ASSUME InfoFull(<<3, P, "S", "-", 2, NONE>>).ok

\* ---- a suffix kind with nothing pending, an EC with a bad set, a non-increasing round ----
ASSUME ~InfoFull(<<2, A1, "S", "-", 1, NONE>>).ok
ASSUME ~InfoFull(<<2, A1, "EC", "-", 1, NONE>>).ok
ASSUME ~InfoFull(<<1, A1, "N", "-", 1, NONE>>).ok
\* the pair must be consecutive: a gap of one round is not a completing pair
ASSUME ~ZPF(<<4, P, "S", "-", 1, NONE>>)
ASSUME ZPF(<<3, P, "S", "-", 1, NONE>>)
\* P at round 2, a suffix block at round 4 (gap), then round 5: the pair (round 4, round 5) completes the commit
ASSUME ~ZPF(<<4, P, "S", "-", 1, NONE>>)
ASSUME ZPF(<<5, <<4, P, "S", "-", 1, NONE>>, "S", "-", 1, NONE>>)
\* once a completing pair exists, a further suffix kind is invalid (the next block is epoch 1, kind N)
ASSUME ~InfoFull(<<4, <<3, P, "S", "-", 1, NONE>>, "S", "-", 1, NONE>>).ok

\* ---- ancestry ----
ASSUME InfoFull(X4).anc = {X4, S3, P, A1, GEN}

\* ---- leader: round-robin over the sorted set ----
ASSUME Leader("S0", 0) = Leader("S0", 4)
ASSUME Leader("S0", 1) # Leader("S0", 2)

\* ---- block content is identity: a one-field change gives a different block ----
ASSUME P # <<2, A1, "EC", "B", 1, NONE>>

SelfNext == FALSE /\ UNCHANGED vars
=============================================================================
