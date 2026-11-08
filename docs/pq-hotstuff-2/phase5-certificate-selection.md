# Power-aware certificate selection (PROPOSAL; separate from the snapshot specification; no validity rule changes)

**Certificate validity is unchanged**: `check_header` still requires signer power at least the quorum and permits any larger signer set, `verify_tc` still requires the nested QC's round to equal the maximum reported `high_qc_round`. Nothing here is a protocol rule,
nothing is implemented, and transport limits keep assuming the maximum permitted certificate (`k = n`). This only describes what an aggregator MAY choose to put in a certificate it builds, to reduce bytes and verification work when voting power is unequal.

## Why it only helps with unequal power
With equal power the quorum already needs `floor(2n/3) + 1` signers, so the smallest valid certificate has that many signatures and a "minimal" selection changes nothing (n = 1000: 667 signers, QC 2,211,370 bytes). With unequal power, the smallest valid signer set
is the smallest prefix of validators ordered by power whose total reaches the quorum threshold `floor(2T/3) + 1`. Illustration with ASSUMED power distributions (not measured; Qattice's real distribution is unknown), n = 1000:
| Distribution (assumed) | smallest valid signer count | QC bytes at that count | equal-power quorum QC (667) |
|---|---|---|---|
| equal power | 667 | 2,211,370 | 2,211,370 |
| power proportional to 1/rank | 83 | 275,410 | 2,211,370 |
| top 100 hold 70% of power, the rest equal | 96 | 318,505 | 2,211,370 |
Verification cost falls in proportion (one ML-DSA-65 verification per signature, about 0.14 ms each on the measured machine).

## Selection policy (aggregator-local, deterministic given its inputs, not consensus-critical)
1. **QC:** from the valid votes for one `(round, block, parent, parent_round)`, choose the smallest set whose power reaches the quorum threshold, taking higher power first and breaking ties by lower validator index. Any set reaching the threshold is valid to verifiers, so aggregators with different policies interoperate.
2. **TC (preserving the high-QC requirement):** the nested `high_qc` must be the QC whose round equals the maximum `high_qc_round` among the INCLUDED timeouts, and the proposal built on the TC must have a QC at or above that maximum (`QcBelowTcMax` otherwise). So the aggregator (a) takes the highest `high_qc_round` among ALL valid timeouts it holds, (b) includes at least one timeout reporting that round, (c) attaches that round's QC as the nested certificate, (d) then fills to the power threshold by the QC rule. Omitting a higher reported round would let a proposal build on a lower QC; honest voters' locks (`hqr`) would still refuse it, but it costs a round, so (a) to (c) are mandatory for the policy.
3. Both stay inside the existing maximum: never more than `n` signatures.

## Trade-offs and what is NOT decided
* Smaller certificates make low-power validators' participation invisible in certificates. If rewards, liveness accounting or slashing evidence ever rely on certificate signer lists, a minimal set under-credits them; that dependency is a separate decision and must be settled first.
* Interaction with the Qattice personhood-weighted voting design (how power is assigned, how it changes) is not assessed here.
* It does not remove the need for the maximum-certificate envelope: another aggregator may include more signers, and verifiers must accept it.
* It does not change `MessageLimits::derive`, the startup validation, or any test; adopting it would add aggregator tests (smallest-set property, TC high-QC preservation, verifier acceptance of both minimal and non-minimal sets, a differential test against the current aggregator on equal-power chains) and no validity tests.
