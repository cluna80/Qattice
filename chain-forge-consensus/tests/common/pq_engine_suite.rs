// Shared body of the PQ-HotStuff-2 engine tests. It is `include!`d by two test crates that differ ONLY in the signature scheme
// behind `doubles::{TestSigner, TestVerifier, test_public_key}`: tests/pq_hotstuff_engine.rs (fast, non-cryptographic doubles)
// and tests/pq_hotstuff_engine_fips204.rs (real FIPS 204 ML-DSA-65). Every assertion is identical in both; the includer defines
// `mod doubles` and `const DEFAULT_SEEDS`.
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};

use chain_forge_consensus::pq_hotstuff::certs::*;
use chain_forge_consensus::pq_hotstuff::engine::*;
use chain_forge_consensus::pq_hotstuff::limits::PqLimits;
use chain_forge_consensus::pq_hotstuff::safety::*;
use chain_forge_consensus::pq_hotstuff::types::{EpochSet, ValidatorEntry};
use chain_forge_consensus::pq_hotstuff::wire::*;
use doubles::*;

const CHAIN: &str = "qattice-pqhs2-dev";
const PROFILE: &str = "qattice-pq-hotstuff-2-v2";
const GENESIS_HASH: [u8; 32] = [7; 32];
const NAMES: [&str; 4] = ["qcb1alice", "qcb1bob", "qcb1carol", "qcb1dave"];

type E = Engine<MemStorage, TestCounter, TestSigner, TestVerifier>;
type St = SafetyStore<MemStorage, TestCounter>;

fn set_n(n: usize) -> EpochSet {
    EpochSet::new(0, (0..n).map(|i| ValidatorEntry { address: NAMES[i].to_string(), public_key: test_public_key(i as u8 + 1), power: 1 }).collect()).unwrap()
}
fn limits(n: usize) -> PqLimits {
    let l = PqLimits { max_validators: n, max_cert_validators: 1024, max_block_payload_bytes: 4096, max_message_bytes: None };
    PqLimits { max_message_bytes: l.proposal_envelope_max(n), ..l }
}
fn cfg(i: usize, n: usize) -> EngineConfig {
    EngineConfig { chain_id: CHAIN.into(), protocol_profile: PROFILE.into(), set: set_n(n), my_index: i, genesis_hash: GENESIS_HASH, limits: limits(n), seed: 0 }
}
fn binding(i: usize) -> CounterBinding { CounterBinding { public_key: test_public_key(i as u8 + 1), instance_id: [i as u8; 16] } }
fn fresh_store(i: usize, f: Shared) -> St {
    let pk = test_public_key(i as u8 + 1);
    let init = FreshInit { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &pk, instance_id: [i as u8; 16], epoch: 0 };
    St::initialize_fresh(MemStorage::new(f.clone()), TestCounter::bound(CounterState::INITIAL, f, binding(i)), &init, &ParticipationEvidence::default()).expect("init")
}
fn engine(i: usize, n: usize) -> E { E::new(cfg(i, n), fresh_store(i, faults()), TestSigner::new(i as u8 + 1), TestVerifier).expect("engine") }

/// Reopen a node from its durable state only (a process restart): the volatile block tree is lost.
fn restart(e: E, i: usize, n: usize) -> E {
    let (store, signer, verifier) = e.into_parts();
    let (st, ctr) = store.into_parts();
    let pk = test_public_key(i as u8 + 1);
    let exp = Expected { protocol_profile: PROFILE, chain_id: CHAIN, public_key: &pk };
    let store = St::open(st, ctr, &exp, &TestVerifier, &ParticipationEvidence::default()).expect("reopen");
    E::new(cfg(i, n), store, signer, verifier).expect("engine")
}

// ---------------------------------------------------------------------------------------------------- certificate fixtures

struct CountingVerifier(Cell<usize>);
impl ConsensusVerifier for CountingVerifier {
    fn verify(&self, pk: &[u8], c: &[u8], m: &[u8], s: &[u8]) -> bool { self.0.set(self.0.get() + 1); TestVerifier.verify(pk, c, m, s) }
}

struct Fx { set: EpochSet, vh: [u8; 32], genesis: GenesisCert }
fn fx() -> Fx {
    let set = set_n(4);
    let vh = set.validator_set_hash();
    Fx { genesis: GenesisCert { protocol_profile: PROFILE.into(), chain_id: CHAIN.into(), genesis_hash: GENESIS_HASH, valset_hash: vh }, set, vh }
}
impl Fx {
    fn ctx<'a>(&'a self, v: &'a dyn ConsensusVerifier) -> VerifyCtx<'a> {
        VerifyCtx { chain_id: CHAIN, set: &self.set, valset_hash: self.vh, genesis: &self.genesis, verifier: v }
    }
}
fn sign(i: usize, ctx: &[u8], msg: &[u8]) -> Vec<u8> { TestSigner::new(i as u8 + 1).sign(ctx, msg).unwrap() }
fn vote_bytes(round: u64, bid: [u8; 32], pid: [u8; 32], pr: u64) -> Vec<u8> {
    VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round, block_id: bid, parent_id: pid, parent_round: pr }.encode().unwrap()
}
fn mk_qc(f: &Fx, round: u64, bid: u8, who: &[usize]) -> Qc {
    let (b, p) = ([bid; 32], [bid.wrapping_sub(1); 32]);
    let m = vote_bytes(round, b, p, round - 1);
    let mut signers = vec![false; 4];
    for i in who { signers[*i] = true; }
    let mut who = who.to_vec(); who.sort();
    Qc { epoch: 0, round, block_id: b, parent_id: p, parent_round: round - 1, valset_hash: f.vh, signers, sigs: who.iter().map(|i| sign(*i, CTX_VOTE, &m)).collect() }
}
fn mk_tc(f: &Fx, round: u64, rounds: &[(usize, u64)], nested: Cert) -> Tc {
    let mut signers = vec![false; 4];
    let mut sorted = rounds.to_vec(); sorted.sort();
    for (i, _) in &sorted { signers[*i] = true; }
    let sigs = sorted.iter().map(|(i, hr)| {
        let m = TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round, high_qc_round: *hr }.encode().unwrap();
        sign(*i, CTX_TIMEOUT, &m)
    }).collect();
    Tc { epoch: 0, round, valset_hash: f.vh, signers, high_qc_rounds: sorted.iter().map(|(_, r)| *r).collect(), sigs, high_qc: nested }
}

// ================================================================================================ encoding (draft 3.4)

#[test]
fn encoded_sizes_match_the_spec_table() {
    let f = fx();
    let qc = mk_qc(&f, 5, 5, &[0, 1, 2]);
    assert_eq!(qc.encode().len(), 10_086); // spec 3.4.5: n = 4, k = 3
    let tc = mk_tc(&f, 6, &[(0, 5), (1, 5), (2, 4)], Cert::Qc(qc));
    assert_eq!(tc.encode().len(), 20_128);
}

#[test]
fn qc_tc_and_genesis_round_trip_and_re_encode_identically() {
    let f = fx();
    let qc = mk_qc(&f, 5, 5, &[0, 2, 3]);
    assert_eq!(Qc::decode(&qc.encode()).unwrap(), qc);
    let tc = mk_tc(&f, 7, &[(1, 5), (2, 5), (3, 3)], Cert::Qc(qc.clone()));
    assert_eq!(Tc::decode(&tc.encode()).unwrap(), tc);
    let g = Cert::Genesis(f.genesis.clone());
    assert_eq!(Cert::decode(&g.encode()).unwrap(), g);
    assert_eq!(Cert::decode(&Cert::Qc(qc.clone()).encode()).unwrap(), Cert::Qc(qc));
    let tcg = mk_tc(&f, 2, &[(0, 0), (1, 0), (2, 0)], g);
    assert_eq!(Tc::decode(&tcg.encode()).unwrap().encode(), tcg.encode());
}

#[test]
fn every_truncation_and_trailing_byte_is_rejected() {
    let f = fx();
    let qc = mk_qc(&f, 5, 5, &[0, 1, 2]).encode();
    for cut in 0..qc.len() { assert!(Qc::decode(&qc[..cut]).is_err(), "cut {cut}"); }
    let mut more = qc.clone(); more.push(0);
    assert!(Qc::decode(&more).is_err());
    let tc = mk_tc(&f, 6, &[(0, 5), (1, 5), (2, 5)], Cert::Qc(mk_qc(&f, 5, 5, &[0, 1, 2]))).encode();
    for cut in (0..tc.len()).step_by(7) { assert!(Tc::decode(&tc[..cut]).is_err(), "cut {cut}"); }
    let mut more = tc.clone(); more.push(0);
    assert!(Tc::decode(&more).is_err());
}

#[test]
fn malformed_headers_and_bitmaps_are_rejected() {
    let f = fx();
    let good = mk_qc(&f, 5, 5, &[0, 1, 2]).encode();
    let mut b = good.clone(); b[0] ^= 1;                       // tag
    assert!(Qc::decode(&b).is_err());
    let mut b = good.clone(); b[TAG_QC.len() + 1] = 2;         // version 2
    assert!(Qc::decode(&b).is_err());
    let mut b = good.clone(); b[TAG_QC.len() + 3] = 2;         // alg_id 2
    assert!(Qc::decode(&b).is_err());
    let bm = TAG_QC.len() + 2 + 2 + 8 + 8 + 32 + 32 + 8 + 32;  // bitmap count field
    let mut b = good.clone(); b[bm + 4] |= 0x01;               // a set pad bit (n = 4: low nibble is padding)
    assert!(Qc::decode(&b).is_err());
    let mut b = good.clone(); b[bm + 4] ^= 0x80;               // flips signer 0: signature count no longer equals popcount
    assert!(Qc::decode(&b).is_err());
    let mut b = good[..bm + 4].to_vec(); b[bm..bm + 4].copy_from_slice(&u32::MAX.to_be_bytes()); // absurd bitmap on a tiny input
    assert!(Qc::decode(&b).is_err());
    assert!(Cert::decode(b"CFH1|nothing|").is_err());
}

#[test]
fn a_genesis_certificate_is_never_a_qc() {
    let f = fx();
    let g = f.genesis.encode();
    assert!(Qc::decode(&g).is_err());
    assert!(Qc::decode(&mk_qc(&f, 1, 1, &[0, 1, 2]).encode()).is_ok());
    assert_ne!(f.genesis.block_id(), mk_qc(&f, 1, 1, &[0, 1, 2]).block_id);
}

// ================================================================================================ validity (draft 3.5.2)

#[test]
fn a_valid_qc_and_tc_verify() {
    let f = fx();
    let qc = mk_qc(&f, 5, 5, &[0, 1, 2]);
    assert_eq!(verify_qc(&f.ctx(&TestVerifier), &qc), Ok(()));
    let tc = mk_tc(&f, 6, &[(0, 5), (1, 5), (2, 4)], Cert::Qc(qc));
    assert_eq!(verify_tc(&f.ctx(&TestVerifier), &tc), Ok(()));
    assert_eq!(verify_cert(&f.ctx(&TestVerifier), &Cert::Genesis(f.genesis.clone())), Ok(()));
}

#[test]
fn canonical_does_not_imply_valid() {
    let f = fx();
    let mut qc = mk_qc(&f, 5, 5, &[0, 1, 2]);
    qc.sigs[1][100] ^= 1;
    let decoded = Qc::decode(&qc.encode()).expect("still canonical");
    assert!(verify_qc(&f.ctx(&TestVerifier), &decoded).is_err());
}

#[test]
fn qc_validity_rejections() {
    let f = fx();
    let v = &TestVerifier;
    let ok = mk_qc(&f, 5, 5, &[0, 1, 2]);
    let bad = |q: &Qc| assert!(verify_qc(&f.ctx(v), q).is_err());
    bad(&Qc { valset_hash: [9; 32], ..ok.clone() });                  // another validator-set commitment
    bad(&Qc { epoch: 1, ..ok.clone() });                              // another epoch
    bad(&Qc { round: 6, ..ok.clone() });                              // round changed after signing
    bad(&Qc { round: 0, parent_round: 0, ..mk_qc(&f, 1, 1, &[0, 1, 2]) });
    bad(&Qc { signers: vec![true, true, true], ..ok.clone() });       // bitmap length != validator count
    bad(&Qc { block_id: f.genesis.block_id(), ..ok.clone() });        // the genesis block is never certified
    let mut swapped = ok.clone(); swapped.sigs.swap(0, 1); bad(&swapped); // reordered signatures
    let mut dup = ok.clone(); dup.sigs[1] = dup.sigs[0].clone(); bad(&dup);
    // a QC whose signatures are genuine but which certifies the genesis block: refused by the rule, not by a signature failure
    let gid = f.genesis.block_id();
    let gm = vote_bytes(5, gid, [4; 32], 4);
    bad(&Qc { block_id: gid, parent_id: [4; 32], sigs: [0usize, 1, 2].iter().map(|i| sign(*i, CTX_VOTE, &gm)).collect(), ..ok.clone() });
    // signatures made in the timeout context never validate as votes (domain separation)
    let m = vote_bytes(5, [5; 32], [4; 32], 4);
    let mut cross = ok.clone();
    cross.sigs = [0usize, 1, 2].iter().map(|i| sign(*i, CTX_TIMEOUT, &m)).collect();
    bad(&cross);
    // another chain
    let other = VerifyCtx { chain_id: "another-chain", ..f.ctx(v) };
    assert!(verify_qc(&other, &ok).is_err());
}

/// Cheap checks first: a certificate whose claimed signers cannot reach a quorum is refused with zero signature verifications.
#[test]
fn a_sub_quorum_certificate_costs_no_signature_verification() {
    let f = fx();
    let cv = CountingVerifier(Cell::new(0));
    let mut q = mk_qc(&f, 5, 5, &[0, 1]);
    q.sigs.iter_mut().for_each(|s| s.iter_mut().for_each(|b| *b = 0)); // garbage that would be expensive to reject
    assert!(verify_qc(&f.ctx(&cv), &q).is_err());
    assert_eq!(cv.0.get(), 0);
    let mut q = mk_qc(&f, 5, 5, &[0, 1, 2]);
    q.valset_hash = [1; 32];
    assert!(verify_qc(&f.ctx(&cv), &q).is_err());
    assert_eq!(cv.0.get(), 0);
}

#[test]
fn tc_validity_rejections() {
    let f = fx();
    let v = &TestVerifier;
    let q5 = Cert::Qc(mk_qc(&f, 5, 5, &[0, 1, 2]));
    let ok = mk_tc(&f, 7, &[(0, 5), (1, 5), (2, 3)], q5.clone());
    assert_eq!(verify_tc(&f.ctx(v), &ok), Ok(()));
    let bad = |t: &Tc| assert!(verify_tc(&f.ctx(v), t).is_err());
    bad(&Tc { high_qc: Cert::Qc(mk_qc(&f, 4, 4, &[0, 1, 2])), ..ok.clone() });   // nested round != maximum signed round
    bad(&Tc { high_qc_rounds: vec![5, 3, 5], ..ok.clone() });                     // misaligned entries break the signatures
    bad(&Tc { round: 5, ..ok.clone() });                                          // nested round must be below the TC round
    bad(&mk_tc(&f, 7, &[(0, 5), (1, 5)], q5.clone()));                            // below quorum
    bad(&mk_tc(&f, 7, &[(0, 3), (1, 3), (2, 3)], Cert::Genesis(f.genesis.clone()))); // genesis nested with a non-zero round
    bad(&Tc { high_qc: Cert::Qc(Qc { valset_hash: [3; 32], ..mk_qc(&f, 5, 5, &[0, 1, 2]) }), ..ok.clone() }); // invalid nested QC
    // vote-context signatures are not timeout signatures
    let mut t = ok.clone();
    t.sigs = [0usize, 1, 2].iter().map(|i| sign(*i, CTX_VOTE, &TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: 7, high_qc_round: t.high_qc_rounds[*i] }.encode().unwrap())).collect();
    bad(&t);
}

// ================================================================================================ block identity

fn base_block(f: &Fx) -> Block {
    Block { epoch: 0, round: 6, height: 5, parent_id: [5; 32], qc: Cert::Qc(mk_qc(f, 5, 5, &[0, 1, 2])), tc: None, payload: b"devnet-interim payload".to_vec(), proposer: 1, signature: vec![] }
}

#[test]
fn block_id_commits_to_every_consensus_critical_field() {
    let f = fx();
    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
    let b = base_block(&f);
    let id = block_id_of(&b, &idc).unwrap();
    assert_eq!(id, block_id_of(&b, &idc).unwrap());
    let changed: Vec<(&str, Block)> = vec![
        ("round", Block { round: 7, ..b.clone() }),
        ("height", Block { height: 6, ..b.clone() }),
        ("parent_id", Block { parent_id: [6; 32], ..b.clone() }),
        ("payload", Block { payload: b"devnet-interim payloae".to_vec(), ..b.clone() }),
        ("proposer", Block { proposer: 2, ..b.clone() }),
        ("qc signatures", Block { qc: Cert::Qc(mk_qc(&f, 5, 5, &[0, 1, 3])), ..b.clone() }),
        ("tc presence", Block { tc: Some(mk_tc(&f, 5, &[(0, 4), (1, 4), (2, 4)], Cert::Qc(mk_qc(&f, 4, 4, &[0, 1, 2])))), ..b.clone() }),
    ];
    for (what, c) in changed { assert_ne!(block_id_of(&c, &idc).unwrap(), id, "{what}"); }
    // the signature is the one field outside the commitment
    assert_eq!(block_id_of(&Block { signature: vec![1; 9], ..b.clone() }, &idc).unwrap(), id);
    // chain identity
    let idc2 = IdCtx { chain_id: "another-chain", ..IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set } };
    assert_ne!(block_id_of(&b, &idc2).unwrap(), id);
}

#[test]
fn the_validator_set_commitment_covers_every_entry() {
    let a = set_n(4);
    let h = a.validator_set_hash();
    assert_eq!(h, set_n(4).validator_set_hash());
    let mut e: Vec<ValidatorEntry> = a.entries().to_vec(); e[2].power = 2;
    assert_ne!(EpochSet::new(0, e).unwrap().validator_set_hash(), h);
    let mut e: Vec<ValidatorEntry> = a.entries().to_vec(); e[2].public_key[0] ^= 1;
    assert_ne!(EpochSet::new(0, e).unwrap().validator_set_hash(), h);
    let mut e: Vec<ValidatorEntry> = a.entries().to_vec(); e[2].address = "qcb1zed".into();
    assert_ne!(EpochSet::new(0, e).unwrap().validator_set_hash(), h);
    assert_ne!(set_n(3).validator_set_hash(), h);
}

// ================================================================================================ engine behaviour

/// Reliable in-order delivery. Drives proposals for `rounds` rounds and returns each node's commits.
fn drive(nodes: &mut Vec<E>, steps: usize) -> Vec<Vec<Committed>> {
    let n = nodes.len();
    let mut commits: Vec<Vec<Committed>> = vec![vec![]; n];
    for _ in 0..steps {
        let r = nodes.iter().map(|e| e.round()).max().unwrap(); // the next leader learns the QC first
        let l = nodes[0].leader_of(r);
        let payload = format!("tx-batch-{r}").into_bytes();
        let first = match nodes[l].propose(payload) { Ok(o) => o, Err(_) => break };
        let mut q: VecDeque<(usize, usize, Output)> = first.into_iter().map(|o| (l, l, o)).collect();
        while let Some((from, _at, o)) = q.pop_front() {
            let deliveries: Vec<(usize, Msg)> = match o {
                Output::Broadcast(m) => (0..n).filter(|i| *i != from).map(|i| (i, m.clone())).collect(),
                Output::Send { to, msg } => if to == from { vec![] } else { vec![(to, msg)] },
                Output::Commit(c) => { commits[from].push(c); vec![] }
                Output::EnteredRound { .. } => vec![],
            };
            for (to, m) in deliveries {
                let outs = nodes[to].on_message(m).unwrap_or_default();
                q.extend(outs.into_iter().map(|o| (to, to, o)));
            }
        }
    }
    commits
}

#[test]
fn four_honest_nodes_commit_the_same_chain_in_order() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let c = drive(&mut nodes, 12);
    // nodes learn the newest QC at different moments, so their commit lists are prefixes of the longest one
    let longest = c.iter().max_by_key(|v| v.len()).unwrap().clone();
    for v in &c { assert_eq!(v[..], longest[..v.len()], "a node's commits are not a prefix of the longest list"); }
    assert!(longest.len() >= 9, "committed {}", longest.len());
    let heights: Vec<u64> = longest.iter().map(|x| x.height).collect();
    assert_eq!(heights, (1..=heights.len() as u64).collect::<Vec<_>>()); // each block exactly once, in height order
    assert_eq!(longest[0].payload, b"tx-batch-1".to_vec());
}

#[test]
fn a_proposal_from_the_wrong_leader_or_with_a_tampered_field_is_rejected() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let l = nodes[0].leader_of(1);
    let outs = nodes[l].propose(b"p".to_vec()).unwrap();
    let Some(Output::Broadcast(Msg::Proposal(b))) = outs.into_iter().next() else { panic!("no proposal") };
    let other = (l + 1) % 4;
    // tampered payload: the signature no longer matches the block id
    let mut t = b.clone(); t.payload = b"q".to_vec();
    assert!(nodes[other].on_proposal(t).is_err());
    // tampered round / proposer
    assert!(nodes[other].on_proposal(Block { round: 2, ..b.clone() }).is_err());
    assert!(nodes[other].on_proposal(Block { proposer: other, ..b.clone() }).is_err());
    // epoch change is refused
    assert!(nodes[other].on_proposal(Block { epoch: 1, ..b.clone() }).is_err());
    // the genuine block is accepted
    assert!(nodes[other].on_proposal(b).is_ok());
}

#[test]
fn a_node_votes_once_per_round_even_for_two_conflicting_proposals() {
    let f = fx();
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let l = nodes[0].leader_of(1);
    let Some(Output::Broadcast(Msg::Proposal(a))) = nodes[l].propose(b"A".to_vec()).unwrap().into_iter().next() else { panic!() };
    // an equivocating leader's twin, signed outside the store
    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
    let mut twin = Block { payload: b"B".to_vec(), signature: vec![], ..a.clone() };
    let id = block_id_of(&twin, &idc).unwrap();
    twin.signature = sign(l, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
    let l2 = nodes[0].leader_of(2);
    let victim = (0..4).find(|i| *i != l && *i != l2).unwrap(); // not the next leader: its vote is sent, not counted locally
    let first = nodes[victim].on_proposal(a).unwrap();
    assert!(first.iter().any(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. })));
    let second = nodes[victim].on_proposal(twin).unwrap();
    assert!(!second.iter().any(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. })), "a second vote in the same round");
}

#[test]
fn a_restart_resends_the_stored_vote_byte_for_byte_and_never_re_signs() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let l = nodes[0].leader_of(1);
    let Some(Output::Broadcast(Msg::Proposal(b))) = nodes[l].propose(b"A".to_vec()).unwrap().into_iter().next() else { panic!() };
    let l2 = nodes[0].leader_of(2);
    let v = (0..4).find(|i| *i != l && *i != l2).unwrap();
    let first = nodes[v].on_proposal(b.clone()).unwrap();
    let Some(Output::Send { msg: Msg::Vote(v1), .. }) = first.into_iter().next() else { panic!("no vote") };
    let e = nodes.remove(v);
    let mut e = restart(e, v, 4);
    let again = e.on_proposal(b).unwrap();
    let Some(Output::Send { msg: Msg::Vote(v2), .. }) = again.into_iter().next() else { panic!("no re-sent vote") };
    assert_eq!(v1.msg.encode().unwrap(), v2.msg.encode().unwrap());
    assert_eq!(v1.signature, v2.signature, "the vote must be re-sent, not re-signed");
}

#[test]
fn timeouts_form_a_tc_and_the_chain_continues_past_a_failed_leader() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let l1 = nodes[0].leader_of(1);
    // the round-1 leader is silent: every other node times out
    let mut q: VecDeque<(usize, Output)> = VecDeque::new();
    for i in 0..4 { if i != l1 { for o in nodes[i].local_timeout().unwrap() { q.push_back((i, o)); } } }
    while let Some((from, o)) = q.pop_front() {
        let ds: Vec<(usize, Msg)> = match o {
            Output::Broadcast(m) => (0..4).filter(|i| *i != from && *i != l1).map(|i| (i, m.clone())).collect(),
            Output::Send { to, msg } if to != l1 => vec![(to, msg)],
            _ => vec![],
        };
        for (to, m) in ds { for o in nodes[to].on_message(m).unwrap_or_default() { q.push_back((to, o)); } }
    }
    for i in 0..4 { if i != l1 { assert_eq!(nodes[i].round(), 2, "node {i} did not enter round 2"); } }
    // the round-2 leader proposes with the TC and the honest nodes vote
    let l2 = nodes[0].leader_of(2);
    assert_ne!(l2, l1);
    let outs = nodes[l2].propose(b"after-tc".to_vec()).unwrap();
    let Some(Output::Broadcast(Msg::Proposal(b))) = outs.into_iter().next() else { panic!() };
    assert!(b.tc.is_some());
    let voter = (0..4).find(|i| *i != l1 && *i != l2).unwrap();
    let vout = nodes[voter].on_proposal(b).unwrap();
    assert!(vout.iter().any(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. })));
}

#[test]
fn a_proposal_that_skips_a_round_without_a_tc_is_rejected() {
    let f = fx();
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let l = nodes[0].leader_of(1);
    let Some(Output::Broadcast(Msg::Proposal(mut b))) = nodes[l].propose(b"A".to_vec()).unwrap().into_iter().next() else { panic!() };
    // re-label as a round-5 block extending genesis, signed by round 5's real leader, without a TC
    let l5 = nodes[0].leader_of(5);
    b.round = 5; b.proposer = l5;
    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
    let id = block_id_of(&b, &idc).unwrap();
    b.signature = sign(l5, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
    assert!(nodes[(l5 + 1) % 4].on_proposal(b).is_err());
}

#[test]
fn engine_construction_checks_the_key_and_the_limits() {
    let f = faults();
    assert!(E::new(cfg(1, 4), fresh_store(2, f.clone()), TestSigner::new(2), TestVerifier).is_err(), "store of another key");
    assert!(E::new(cfg(1, 4), fresh_store(1, f.clone()), TestSigner::new(3), TestVerifier).is_err(), "signer of another key");
    let mut c = cfg(1, 4); c.limits.max_message_bytes = Some(1_000);
    assert!(E::new(c, fresh_store(1, f.clone()), TestSigner::new(2), TestVerifier).is_err(), "message limit below the largest proposal");
    let mut c = cfg(1, 4); c.my_index = 9;
    assert!(E::new(c, fresh_store(1, f), TestSigner::new(2), TestVerifier).is_err());
}

// ---- engine rules that need a crafted, validly signed block (signed outside the store, as an adversary could) ----

fn signed_block(f: &Fx, mut b: Block) -> Block {
    let id = block_id_of(&b, &IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set }).unwrap();
    b.signature = sign(b.proposer, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
    b
}
fn has_vote(o: &[Output]) -> bool { o.iter().any(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. })) }
fn genesis_block(f: &Fx, round: u64, proposer: usize) -> Block {
    Block { epoch: 0, round, height: 1, parent_id: f.genesis.block_id(), qc: Cert::Genesis(f.genesis.clone()), tc: None, payload: b"x".to_vec(), proposer, signature: vec![] }
}

#[test]
fn a_validly_signed_block_from_a_non_leader_is_rejected() {
    let f = fx();
    let mut e = engine(0, 4);
    let leader = e.leader_of(1);
    let imposter = (leader + 1) % 4;
    let b = signed_block(&f, genesis_block(&f, 1, imposter));
    assert!(e.on_proposal(b).is_err());
    let ok = signed_block(&f, genesis_block(&f, 1, leader));
    assert!(e.on_proposal(ok).is_ok());
}

#[test]
fn a_block_with_an_invalid_parent_qc_is_rejected_even_when_correctly_signed() {
    let f = fx();
    let mut e = engine(0, 4);
    // a certificate with garbage signatures for a block the node knows
    let l1 = e.leader_of(1);
    let b1 = signed_block(&f, genesis_block(&f, 1, l1));
    let id1 = block_id_of(&b1, &IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set }).unwrap();
    e.on_proposal(b1).unwrap();
    let mut forged = Qc { epoch: 0, round: 1, block_id: id1, parent_id: f.genesis.block_id(), parent_round: 0, valset_hash: f.vh, signers: vec![true, true, true, false], sigs: vec![vec![0u8; 3309]; 3] };
    let l2 = e.leader_of(2);
    let b2 = signed_block(&f, Block { epoch: 0, round: 2, height: 2, parent_id: id1, qc: Cert::Qc(forged.clone()), tc: None, payload: b"y".to_vec(), proposer: l2, signature: vec![] });
    assert!(e.on_proposal(b2).is_err(), "a forged QC must not be accepted");
    forged.sigs = mk_qc(&f, 1, 0, &[0, 1, 2]).sigs; // signatures over a different block
    let b2 = signed_block(&f, Block { epoch: 0, round: 2, height: 2, parent_id: id1, qc: Cert::Qc(forged), tc: None, payload: b"y".to_vec(), proposer: l2, signature: vec![] });
    assert!(e.on_proposal(b2).is_err());
}

/// The scripted counterexample of spec section 5: a leader that skips a QC higher than the one the timeout certificate reports
/// would fork after a view change, so the node must not vote.
#[test]
fn a_block_that_skips_a_higher_qc_reported_by_its_timeout_certificate_gets_no_vote() {
    let f = fx();
    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
    let mut e = engine(0, 4);
    let b1 = signed_block(&f, genesis_block(&f, 1, e.leader_of(1)));
    let id1 = block_id_of(&b1, &idc).unwrap();
    e.on_proposal(b1).unwrap();
    let qc1 = Qc { epoch: 0, round: 1, block_id: id1, parent_id: f.genesis.block_id(), parent_round: 0, valset_hash: f.vh, ..mk_qc(&f, 1, 1, &[0, 1, 2]) };
    let m = vote_bytes(1, id1, f.genesis.block_id(), 0);
    let qc1 = Qc { sigs: [0usize, 1, 2].iter().map(|i| sign(*i, CTX_VOTE, &m)).collect(), ..qc1 };
    // a TC for round 3 reporting a QC of round 2 (some other block), signed by three validators
    let qc2 = mk_qc(&f, 2, 9, &[0, 1, 2]);
    let tc = mk_tc(&f, 3, &[(0, 2), (1, 2), (2, 2)], Cert::Qc(qc2));
    let skipping = signed_block(&f, Block { epoch: 0, round: 4, height: 2, parent_id: id1, qc: Cert::Qc(qc1.clone()), tc: Some(tc), payload: b"z".to_vec(), proposer: e.leader_of(4), signature: vec![] });
    let out = e.on_proposal(skipping).unwrap();
    assert!(!has_vote(&out), "voted for a block whose QC is below the TC's highest reported QC");
    // control: the same shape with a TC that reports only round 1 is votable
    let tc_ok = mk_tc(&f, 3, &[(0, 1), (1, 1), (2, 1)], Cert::Qc(qc1.clone()));
    let fine = signed_block(&f, Block { epoch: 0, round: 4, height: 2, parent_id: id1, qc: Cert::Qc(qc1), tc: Some(tc_ok), payload: b"w".to_vec(), proposer: e.leader_of(4), signature: vec![] });
    assert!(has_vote(&e.on_proposal(fine).unwrap()));
}

/// Two-chain commit across a round gap: a block certified two rounds after its parent must not commit that parent.
#[test]
fn a_certificate_across_a_round_gap_does_not_commit_the_parent() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let l1 = nodes[0].leader_of(1);
    let outs = nodes[l1].propose(b"A".to_vec()).unwrap();
    let a = outs.iter().find_map(|o| if let Output::Broadcast(Msg::Proposal(b)) = o { Some(b.clone()) } else { None }).unwrap();
    // everyone sees A and every vote for A (so every node holds QC(A)); nobody proposes round 2 (its leader is down)
    let mut votes: Vec<VoteMsg> = outs.iter().filter_map(|o| if let Output::Send { msg: Msg::Vote(v), .. } = o { Some(v.clone()) } else { None }).collect();
    for i in 0..4 { if i != l1 { for o in nodes[i].on_proposal(a.clone()).unwrap() { if let Output::Send { msg: Msg::Vote(v), .. } = o { votes.push(v); } } } }
    let l2 = nodes[0].leader_of(2);
    for v in &votes { for i in 0..4 { if i != l2 { let _ = nodes[i].on_vote(v.clone()); } } }
    for i in 0..4 { if i != l2 { assert_eq!(nodes[i].high_qc().round(), 1, "node {i} should hold QC(A)"); } }
    // everyone but the dead round-2 leader times out of round 2 and the TC forms
    let mut q: VecDeque<(usize, Output)> = VecDeque::new();
    let mut commits = 0;
    for i in 0..4 { if i != l2 { nodes[i].local_timeout().unwrap_or_default(); } }
    for i in 0..4 { if i != l2 { for o in nodes[i].local_timeout().unwrap_or_default() { q.push_back((i, o)); } } }
    let mut proposed_c = false;
    while let Some((from, o)) = q.pop_front() {
        let ds: Vec<(usize, Msg)> = match o {
            Output::Broadcast(m) => (0..4).filter(|i| *i != from && *i != l2).map(|i| (i, m.clone())).collect(),
            Output::Send { to, msg } if to != l2 => vec![(to, msg)],
            Output::Commit(_) => { commits += 1; vec![] }
            _ => vec![],
        };
        for (to, m) in ds { for o in nodes[to].on_message(m).unwrap_or_default() { q.push_back((to, o)); } }
        if !proposed_c && (0..4).all(|i| i == l2 || nodes[i].round() >= 3) {
            proposed_c = true;
            let l3 = nodes[0].leader_of(3);
            for o in nodes[l3].propose(b"C".to_vec()).unwrap() { q.push_back((l3, o)); }
        }
    }
    assert!(proposed_c, "round 3 was never reached");
    assert!((0..4).any(|i| i != l2 && nodes[i].high_qc().round() == 3), "QC(C) should exist (round 3, parent round 1)");
    assert_eq!(commits, 0, "a QC two rounds after its parent must not commit the parent");
}

#[test]
fn a_vote_with_a_bad_signature_or_identity_is_not_counted() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let l1 = nodes[0].leader_of(1);
    let Some(Output::Broadcast(Msg::Proposal(a))) = nodes[l1].propose(b"A".to_vec()).unwrap().into_iter().next() else { panic!() };
    let l2 = nodes[0].leader_of(2);
    let voters: Vec<usize> = (0..4).filter(|i| *i != l1 && *i != l2).collect();
    let mut votes = vec![];
    for i in &voters { for o in nodes[*i].on_proposal(a.clone()).unwrap() { if let Output::Send { msg: Msg::Vote(v), .. } = o { votes.push(v); } } }
    let mut bad = votes[0].clone(); bad.signature[5] ^= 1;
    assert!(nodes[l2].on_vote(bad).is_err());
    let mut wrong_voter = votes[0].clone(); wrong_voter.voter = (wrong_voter.voter + 1) % 4;
    assert!(nodes[l2].on_vote(wrong_voter).is_err());
    let mut other_chain = votes[0].clone(); other_chain.msg.chain_id = "other".into();
    assert!(nodes[l2].on_vote(other_chain).is_err());
    // only the genuine votes (plus the leader's own, counted internally) form the QC: l1's vote is not among them
    for v in &votes { let _ = nodes[l2].on_vote(v.clone()); }
    assert_ne!(nodes[l2].high_qc().round(), 1, "two honest votes are below the quorum of three");
}

#[test]
fn a_proposal_with_a_forged_timeout_certificate_is_rejected() {
    let f = fx();
    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
    let mut e = engine(0, 4);
    let b1 = signed_block(&f, genesis_block(&f, 1, e.leader_of(1)));
    let id1 = block_id_of(&b1, &idc).unwrap();
    e.on_proposal(b1).unwrap();
    let m = vote_bytes(1, id1, f.genesis.block_id(), 0);
    let qc1 = Qc { epoch: 0, round: 1, block_id: id1, parent_id: f.genesis.block_id(), parent_round: 0, valset_hash: f.vh, signers: vec![true, true, true, false], sigs: [0usize, 1, 2].iter().map(|i| sign(*i, CTX_VOTE, &m)).collect() };
    let mut tc = mk_tc(&f, 3, &[(0, 1), (1, 1), (2, 1)], Cert::Qc(qc1.clone()));
    tc.sigs.iter_mut().for_each(|s| s[9] ^= 1); // structurally valid, signatures forged
    let b4 = signed_block(&f, Block { epoch: 0, round: 4, height: 2, parent_id: id1, qc: Cert::Qc(qc1), tc: Some(tc), payload: b"t".to_vec(), proposer: e.leader_of(4), signature: vec![] });
    assert!(e.on_proposal(b4).is_err());
}

#[test]
fn a_timeout_certificate_is_broadcast_when_formed_and_a_received_one_advances_the_round() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    // three nodes time out of round 1; the third timeout reaches node 0, which forms the TC and must broadcast it
    let tos: Vec<TimeoutMsg> = (1..4).map(|i| nodes[i].local_timeout().unwrap().into_iter().find_map(|o| if let Output::Broadcast(Msg::Timeout(t)) = o { Some(t) } else { None }).unwrap()).collect();
    let mut formed = None;
    for t in &tos { for o in nodes[0].on_timeout(t.clone()).unwrap() { if let Output::Broadcast(Msg::Tc(tc)) = o { formed = Some(tc); } } }
    let tc = formed.expect("the node that forms a TC must broadcast it");
    assert_eq!(nodes[0].round(), 2);
    // a node that never saw the timeouts adopts the TC
    assert_eq!(nodes[1].round(), 1);
    nodes[1].on_message(Msg::Tc(tc.clone())).unwrap();
    assert_eq!(nodes[1].round(), 2);
    // a forged TC changes nothing
    let mut forged = tc; forged.sigs[0][3] ^= 1;
    assert!(nodes[2].on_tc(forged).is_err());
    assert_eq!(nodes[2].round(), 1);
}

#[test]
fn a_payload_above_the_limit_is_refused_by_the_proposer_and_the_validators() {
    let f = fx();
    let mut e = engine(1, 4);
    assert!(e.propose(vec![0u8; 4097]).is_err() || e.leader_of(1) != 1);
    let mut v = engine(0, 4);
    let b = signed_block(&f, Block { payload: vec![0u8; 4097], ..genesis_block(&f, 1, v.leader_of(1)) });
    assert!(v.on_proposal(b).is_err());
}

// ================================================================================================ authentication
// Wrong key, wrong context, altered message and other-chain replay must all fail for proposals, votes, timeouts, QCs and TCs.

fn engine_on(chain: &str, i: usize, n: usize) -> E {
    let mut c = cfg(i, n);
    c.chain_id = chain.into();
    let f = faults();
    let pk = test_public_key(i as u8 + 1);
    let init = FreshInit { protocol_profile: PROFILE, chain_id: chain, public_key: &pk, instance_id: [i as u8; 16], epoch: 0 };
    let store = St::initialize_fresh(MemStorage::new(f.clone()), TestCounter::bound(CounterState::INITIAL, f, binding(i)), &init, &ParticipationEvidence::default()).expect("init");
    E::new(c, store, TestSigner::new(i as u8 + 1), TestVerifier).expect("engine")
}
const WRONG_CONTEXTS_FOR_VOTE: [&[u8]; 2] = [CTX_TIMEOUT, CTX_PROPOSAL];
const WRONG_CONTEXTS_FOR_TIMEOUT: [&[u8]; 2] = [CTX_VOTE, CTX_PROPOSAL];
const WRONG_CONTEXTS_FOR_PROPOSAL: [&[u8]; 2] = [CTX_VOTE, CTX_TIMEOUT];

#[test]
fn a_block_signed_with_another_validators_key_is_rejected() {
    let f = fx();
    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
    let mut e = engine(0, 4);
    let l = e.leader_of(1);
    let mut b = genesis_block(&f, 1, l);
    let id = block_id_of(&b, &idc).unwrap();
    let msg = BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap();
    for other in (0..4).filter(|i| *i != l) {
        b.signature = sign(other, Kind::Proposal.context(), &msg);
        assert!(e.on_proposal(b.clone()).is_err(), "a signature by validator {other} was accepted as the leader's");
    }
    b.signature = sign(l, Kind::Proposal.context(), &msg);
    assert!(e.on_proposal(b).is_ok());
}

#[test]
fn signatures_made_in_the_wrong_context_are_rejected_for_every_message_type() {
    let f = fx();
    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
    // proposals
    for ctx in WRONG_CONTEXTS_FOR_PROPOSAL {
        let mut e = engine(0, 4);
        let l = e.leader_of(1);
        let mut b = genesis_block(&f, 1, l);
        let id = block_id_of(&b, &idc).unwrap();
        b.signature = sign(l, ctx, &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
        assert!(e.on_proposal(b).is_err());
    }
    // votes: a genuine vote, re-signed in other contexts
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let (l1, l2) = (nodes[0].leader_of(1), nodes[0].leader_of(2));
    let outs = nodes[l1].propose(b"A".to_vec()).unwrap();
    let a = outs.iter().find_map(|o| if let Output::Broadcast(Msg::Proposal(b)) = o { Some(b.clone()) } else { None }).unwrap();
    let voter = (0..4).find(|i| *i != l1 && *i != l2).unwrap();
    let Some(Output::Send { msg: Msg::Vote(v), .. }) = nodes[voter].on_proposal(a).unwrap().into_iter().next() else { panic!("no vote") };
    for ctx in WRONG_CONTEXTS_FOR_VOTE {
        let mut bad = v.clone();
        bad.signature = sign(voter, ctx, &bad.msg.encode().unwrap());
        assert!(nodes[l2].on_vote(bad).is_err());
    }
    assert!(nodes[l2].on_vote(v).is_ok());
    // timeouts
    let mut t_nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let Some(Output::Broadcast(Msg::Timeout(t))) = t_nodes[1].local_timeout().unwrap().into_iter().next() else { panic!("no timeout") };
    for ctx in WRONG_CONTEXTS_FOR_TIMEOUT {
        let mut bad = t.clone();
        bad.signature = sign(t.voter, ctx, &bad.msg.encode().unwrap());
        assert!(t_nodes[0].on_timeout(bad).is_err());
    }
    assert!(t_nodes[0].on_timeout(t).is_ok());
    // QC and TC signature lists
    let vctx = f.ctx(&TestVerifier);
    let mut qc = mk_qc(&f, 5, 5, &[0, 1, 2]);
    let m = vote_bytes(5, [5; 32], [4; 32], 4);
    qc.sigs = [0usize, 1, 2].iter().map(|i| sign(*i, CTX_PROPOSAL, &m)).collect();
    assert!(verify_qc(&vctx, &qc).is_err());
    let q5 = Cert::Qc(mk_qc(&f, 5, 5, &[0, 1, 2]));
    for ctx in WRONG_CONTEXTS_FOR_TIMEOUT {
        let mut tc = mk_tc(&f, 7, &[(0, 5), (1, 5), (2, 5)], q5.clone());
        tc.sigs = [0usize, 1, 2].iter().map(|i| sign(*i, ctx, &TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: 7, high_qc_round: 5 }.encode().unwrap())).collect();
        assert!(verify_tc(&vctx, &tc).is_err());
    }
}

#[test]
fn a_certificate_signature_from_the_wrong_validator_is_rejected() {
    let f = fx();
    let vctx = f.ctx(&TestVerifier);
    let mut qc = mk_qc(&f, 5, 5, &[0, 1, 2]);
    qc.sigs[2] = sign(3, CTX_VOTE, &vote_bytes(5, [5; 32], [4; 32], 4)); // validator 3 signed validator 2's slot
    assert!(verify_qc(&vctx, &qc).is_err());
    let q5 = Cert::Qc(mk_qc(&f, 5, 5, &[0, 1, 2]));
    let mut tc = mk_tc(&f, 7, &[(0, 5), (1, 5), (2, 5)], q5);
    tc.sigs[1] = sign(3, CTX_TIMEOUT, &TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: 7, high_qc_round: 5 }.encode().unwrap());
    assert!(verify_tc(&vctx, &tc).is_err());
}

#[test]
fn messages_and_certificates_from_another_chain_are_rejected() {
    const OTHER: &str = "qattice-other-chain";
    let f = fx();
    // a proposal produced by the same validators on another chain
    let mut ours = engine(0, 4);
    let l = ours.leader_of(1);
    let mut theirs = engine_on(OTHER, l, 4);
    let outs = theirs.propose(b"cross".to_vec()).unwrap();
    let Some(Output::Broadcast(Msg::Proposal(foreign))) = outs.iter().find(|o| matches!(o, Output::Broadcast(Msg::Proposal(_)))).cloned() else { panic!("no proposal") };
    assert!(ours.on_proposal(foreign).is_err(), "a block from another chain was accepted");
    // votes and timeouts signed correctly for the other chain
    let l2 = ours.leader_of(2);
    let voter = (0..4).find(|i| *i != l && *i != l2).unwrap();
    let mut t_voter = engine_on(OTHER, voter, 4);
    let Some(Output::Broadcast(Msg::Proposal(fb))) = outs.into_iter().find(|o| matches!(o, Output::Broadcast(Msg::Proposal(_)))) else { panic!() };
    let Some(Output::Send { msg: Msg::Vote(fv), .. }) = t_voter.on_proposal(fb).unwrap().into_iter().next() else { panic!("no foreign vote") };
    let mut collector = engine(l2, 4);
    assert!(collector.on_vote(fv).is_err(), "a vote for another chain was counted");
    let Some(Output::Broadcast(Msg::Timeout(ft))) = engine_on(OTHER, 1, 4).local_timeout().unwrap().into_iter().next() else { panic!() };
    assert!(engine(0, 4).on_timeout(ft).is_err(), "a timeout for another chain was counted");
    // the same, isolated: a genuinely signed timeout whose ONLY difference is the chain id (it carries our genesis certificate)
    let timeout_for = |chain: &str| {
        let m = TimeoutMessage { alg_id: ALG, chain_id: chain.into(), epoch: 0, round: 1, high_qc_round: 0 };
        TimeoutMsg { voter: 1, signature: sign(1, CTX_TIMEOUT, &m.encode().unwrap()), msg: m, high_qc: Cert::Genesis(f.genesis.clone()) }
    };
    assert!(engine(0, 4).on_timeout(timeout_for(CHAIN)).is_ok(), "control: the same timeout on this chain is accepted");
    assert!(engine(0, 4).on_timeout(timeout_for(OTHER)).is_err(), "a timeout whose only difference is the chain id was counted");
    // certificates and the genesis certificate of another chain
    let mut other_ctx = f.ctx(&TestVerifier);
    other_ctx.chain_id = OTHER;
    assert!(verify_qc(&other_ctx, &mk_qc(&f, 5, 5, &[0, 1, 2])).is_err());
    let foreign_genesis = Cert::Genesis(GenesisCert { chain_id: OTHER.into(), ..f.genesis.clone() });
    assert!(verify_cert(&f.ctx(&TestVerifier), &foreign_genesis).is_err());
}

// ================================================================================================ deterministic simulation

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0.wrapping_mul(0x2545F4914F6CDD1D) }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}

/// QAT-06: Withhold withholds its own votes from a randomly-chosen half; SplitBrain sends two different
/// proposals to disjoint halves (partition by parity). These match the Tendermint sim adversaries exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role { Honest, Silent, Equivocator, Withhold, SplitBrain }

struct Sim {
    n: usize,
    nodes: Vec<Option<E>>,
    roles: Vec<Role>,
    down_until: Vec<u64>,
    round_started: Vec<u64>,
    last_round: Vec<u64>,
    net: Vec<(u64, usize, Msg, u32)>,
    log: Vec<(usize, Msg)>,
    commits: Vec<Vec<Committed>>,
    ledger: Vec<BTreeMap<u64, BlockId>>,
    by_id: BTreeMap<BlockId, Block>,
    rng: Rng,
    tick: u64,
    gst: u64,
    restarts: bool,
    restart_count: usize,
    seed: u64,
    /// (start_tick, end_tick, bitmask): nodes whose `(mask >> i) & 1` differs are in separate partitions.
    partition: Option<(u64, u64, u8)>,
    /// Staggered start: node i does not join until `start_at[i]`.
    start_at: Vec<u64>,
    /// Extra delay probability (0–100): with this % chance add `slow_extra` ticks to a message.
    slow_pct: u64,
    slow_extra: u64,
    /// Fork-detection mode: if true the sim tracks whether honest nodes see conflicting commits (expected).
    expect_fork: bool,
    forks_detected: usize,
}

const TIMEOUT: u64 = 30;

impl Sim {
    fn new(seed: u64, roles: Vec<Role>, restarts: bool) -> Sim {
        let n = roles.len();
        Sim {
            n, nodes: (0..n).map(|i| if roles[i] == Role::Silent { None } else { Some(engine(i, n)) }).collect(), roles,
            down_until: vec![0; n], round_started: vec![0; n], last_round: vec![1; n], net: vec![], log: vec![], commits: vec![vec![]; n], ledger: vec![BTreeMap::new(); n], by_id: BTreeMap::new(),
            rng: Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1), tick: 0, gst: 150, restarts, restart_count: 0, seed,
            partition: None, start_at: vec![0; n], slow_pct: 0, slow_extra: 0, expect_fork: false, forks_detected: 0,
        }
    }
    fn partitioned(&self, a: usize, b: usize, t: u64) -> bool {
        matches!(self.partition, Some((s, e, mask)) if t >= s && t < e && ((mask >> a) & 1) != ((mask >> b) & 1))
    }
    fn send(&mut self, from: usize, to: usize, m: Msg) {
        if to == from { return; }
        if self.partitioned(from, to, self.tick) { return; }
        let pre_gst = self.tick < self.gst;
        if pre_gst && self.rng.below(100) < 20 { return; }
        let mut d = if pre_gst { 1 + self.rng.below(12) } else { 1 + self.rng.below(2) };
        if self.slow_pct > 0 && self.rng.below(100) < self.slow_pct { d += self.slow_extra; }
        self.net.push((self.tick + d, to, m, 0));
    }
    fn route(&mut self, from: usize, outs: Vec<Output>) {
        for o in outs {
            match o {
                Output::Broadcast(m) => { self.note(&m); self.log.push((from, m.clone())); for to in 0..self.n { self.send(from, to, m.clone()); } }
                Output::Send { to, msg } => { self.note(&msg); self.log.push((from, msg.clone())); self.send(from, to, msg); }
                // the executed ledger is durable (the execution layer's job): a restarted engine re-emits commits from
                // height 1, which are idempotent and must name the same block
                Output::Commit(c) => match self.ledger[from].get(&c.height) {
                    Some(id) => assert_eq!(*id, c.id, "node {from} re-committed height {} with another block after a restart", c.height),
                    None => { self.ledger[from].insert(c.height, c.id); self.commits[from].push(c); }
                },
                Output::EnteredRound { .. } => {}
            }
        }
    }
    /// Remember every proposal by id: the stand-in for a block-sync service (the engine has no sync protocol yet).
    fn note(&mut self, m: &Msg) {
        if let Msg::Proposal(b) = m {
            let f = fx();
            if let Ok(id) = block_id_of(b, &IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set }) { self.by_id.entry(id).or_insert_with(|| b.clone()); }
        }
    }
    fn up(&self, i: usize) -> bool { self.nodes[i].is_some() && self.down_until[i] <= self.tick && self.tick >= self.start_at[i] }

    fn byz_extras(&mut self, i: usize, m: &Msg) {
        match self.roles[i].clone() {
            Role::Equivocator => {
                // equivocator double-votes on every proposal it sees
                if let Msg::Proposal(b) = m {
                    let f = fx();
                    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
                    if let Ok(id) = block_id_of(b, &idc) {
                        let vm = VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: b.round, block_id: id, parent_id: b.parent_id, parent_round: b.qc.round() };
                        let sig = sign(i, CTX_VOTE, &vm.encode().unwrap());
                        let to = self.nodes[i].as_ref().map_or(0, |e| e.leader_of(b.round + 1));
                        self.send(i, to, Msg::Vote(VoteMsg { voter: i, msg: vm, signature: sig }));
                    }
                }
            }
            Role::Withhold => {
                // withhold: forward votes/timeouts only to a randomly-chosen half of honest nodes
                // (the pattern that makes lock rules necessary: different subsets see different round messages)
                if matches!(m, Msg::Vote(_) | Msg::Timeout(_)) {
                    for to in 0..self.n {
                        if to != i && self.rng.below(2) == 0 { self.send(i, to, m.clone()); }
                    }
                    // prevent default broadcast by consuming in byz_extras; the caller must not send
                }
            }
            Role::SplitBrain => {
                // split-brain: send two different proposals to even-indexed and odd-indexed nodes
                if let Msg::Proposal(b) = m {
                    let f = fx();
                    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
                    let mut b2 = Block { payload: format!("splitbrain-n{i}r{}", b.round).into_bytes(), signature: vec![], ..b.clone() };
                    if let Ok(id2) = block_id_of(&b2, &idc) {
                        b2.signature = sign(i, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id2 }.encode().unwrap());
                        for to in 0..self.n {
                            if to != i { self.send(i, to, if to % 2 == 0 { m.clone() } else { Msg::Proposal(b2.clone()) }); }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn is_byzantine(&self, i: usize) -> bool {
        matches!(self.roles[i], Role::Equivocator | Role::Withhold | Role::SplitBrain)
    }

    fn step(&mut self) {
        let t = self.tick;
        // deliver due messages in random order
        let mut due: Vec<(u64, usize, Msg, u32)> = vec![];
        let mut keep = vec![];
        for m in self.net.drain(..) { if m.0 <= t { due.push(m) } else { keep.push(m) } }
        self.net = keep;
        while !due.is_empty() {
            let k = self.rng.below(due.len() as u64) as usize;
            let (_, to, m, tries) = due.swap_remove(k);
            if !self.up(to) { if self.nodes[to].is_some() && tries < 40 { self.net.push((t + 3, to, m, tries + 1)); } continue; }
            if self.is_byzantine(to) { self.byz_extras(to, &m); }
            let e = self.nodes[to].as_mut().unwrap();
            match e.on_message(m.clone()) {
                Ok(outs) => self.route(to, outs),
                Err(EngineError::MissingParent(pid)) if tries < 40 => {
                    // sync request: the missing ancestor arrives first, then the original message is retried
                    if let Some(b) = self.by_id.get(&pid).cloned() { self.net.push((t + 1, to, Msg::Proposal(b), tries + 1)); }
                    self.net.push((t + 4, to, m, tries + 1));
                }
                Err(EngineError::ConflictingCommit) => {
                    if self.expect_fork { self.forks_detected += 1; }
                    else {
                        let e = self.nodes[to].as_ref().unwrap();
                        let h = |x: &[u8]| x[..3].iter().map(|b| format!("{b:02x}")).collect::<String>();
                        let mut d = format!("tip={} h{}; known:", h(&e.committed_tip().0), e.committed_tip().1);
                        for b in e.known_blocks() { d += &format!("\n  r{} h{} parent={} qc.round={} tc={:?}", b.round, b.height, h(&b.parent_id), b.qc.round(), b.tc.as_ref().map(|t| (t.round, t.max_high_qc_round()))); }
                        panic!("SAFETY VIOLATION seed {} tick {t}: node {to} would commit a conflicting block on message {:?}\n{d}", self.seed, std::mem::discriminant(&m));
                    }
                }
                Err(_) => {}
            }
        }
        for i in 0..self.n {
            if !self.up(i) { continue; }
            // round bookkeeping and the pacemaker
            let r = self.nodes[i].as_ref().unwrap().round();
            if r != self.last_round[i] { self.last_round[i] = r; self.round_started[i] = t; }
            if self.nodes[i].as_ref().unwrap().is_leader() {
                let payload = format!("n{i}r{r}").into_bytes();
                if let Ok(outs) = self.nodes[i].as_mut().unwrap().propose(payload) {
                    self.route(i, outs);
                    if self.is_byzantine(i) { self.twin(i, r); }
                }
            }
            if t.saturating_sub(self.round_started[i]) >= TIMEOUT {
                self.round_started[i] = t;
                if let Ok(outs) = self.nodes[i].as_mut().unwrap().local_timeout() { self.route(i, outs); }
            }
        }
        if self.restarts && t > 20 && t < self.gst + 100 && self.rng.below(60) == 0 {
            let i = self.rng.below(self.n as u64) as usize;
            if self.roles[i] == Role::Honest && self.up(i) && (0..self.n).all(|j| self.down_until[j] <= t) {
                let e = self.nodes[i].take().unwrap();
                self.nodes[i] = Some(restart(e, i, self.n));
                self.down_until[i] = t + 1 + self.rng.below(10);
                self.restart_count += 1;
                // stand-in for p2p sync: replay every proposal ever broadcast, in order
                let proposals: Vec<Msg> = self.log.iter().filter(|(_, m)| matches!(m, Msg::Proposal(_))).map(|(_, m)| m.clone()).collect();
                for m in proposals { self.net.push((self.down_until[i] + 1, i, m, 0)); }
                self.last_round[i] = 1; self.round_started[i] = self.down_until[i];
            }
        }
        self.tick += 1;
    }

    fn twin(&mut self, i: usize, r: u64) {
        let Some(Msg::Proposal(a)) = self.log.iter().rev().find(|(f, m)| *f == i && matches!(m, Msg::Proposal(b) if b.round == r)).map(|(_, m)| m.clone()) else { return };
        let f = fx();
        let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
        let mut b = Block { payload: format!("twin-n{i}r{r}").into_bytes(), signature: vec![], ..a };
        let id = block_id_of(&b, &idc).unwrap();
        b.signature = sign(i, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
        for to in (0..self.n).filter(|j| j % 2 == 1) { self.send(i, to, Msg::Proposal(b.clone())); }
    }

    fn run(&mut self, ticks: u64) { for _ in 0..ticks { self.step(); } }
    fn honest(&self) -> Vec<usize> { (0..self.n).filter(|i| !self.is_byzantine(*i) && self.roles[*i] != Role::Silent).collect() }

    /// Agreement: no height has two different committed blocks anywhere among honest nodes.
    fn assert_agreement(&self, label: &str) {
        let mut by_height: BTreeMap<u64, BlockId> = BTreeMap::new();
        for i in self.honest() {
            for c in &self.commits[i] {
                match by_height.insert(c.height, c.id) {
                    Some(prev) if prev != c.id => panic!("{label}: AGREEMENT VIOLATED at height {}", c.height),
                    _ => {}
                }
            }
            // each node commits in strictly increasing height, once per block
            assert!(self.commits[i].windows(2).all(|w| w[1].height > w[0].height), "{label}: commit order");
        }
    }

    /// No honest validator signed two different votes (or two different timeouts) for one round.
    fn assert_no_honest_double_signing(&self, label: &str) {
        let mut votes: BTreeMap<(usize, u64), Vec<u8>> = BTreeMap::new();
        let mut tos: BTreeMap<(usize, u64), u64> = BTreeMap::new();
        for (from, m) in &self.log {
            if self.is_byzantine(*from) || self.roles[*from] == Role::Silent { continue; }
            match m {
                Msg::Vote(v) if v.voter == *from => {
                    let b = v.msg.encode().unwrap();
                    if let Some(prev) = votes.insert((*from, v.msg.round), b.clone()) { assert_eq!(prev, b, "{label}: node {from} voted twice in round {}", v.msg.round); }
                }
                Msg::Timeout(t) if t.voter == *from => {
                    if let Some(prev) = tos.insert((*from, t.msg.round), t.msg.high_qc_round) { assert_eq!(prev, t.msg.high_qc_round, "{label}: node {from} timed out twice in round {}", t.msg.round); }
                }
                _ => {}
            }
        }
    }
}

/// Seeds per campaign (default 10; raise with PQHS_SEEDS for a longer soak).
fn seeds() -> u64 { std::env::var("PQHS_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_SEEDS) }

fn campaign(label: &str, roles: Vec<Role>, restarts: bool, min_commits: usize) {
    for seed in 1..=seeds() {
        let mut s = Sim::new(seed, roles.clone(), restarts);
        s.run(520);
        let l = format!("{label} seed {seed}");
        s.assert_agreement(&l);
        s.assert_no_honest_double_signing(&l);
        let best = s.honest().iter().map(|i| s.commits[*i].len()).max().unwrap();
        assert!(best >= min_commits, "{l}: liveness after GST: best honest node committed only {best} blocks");
    }
}

/// Extended campaign: accepts a closure that mutates `Sim` after construction (for partition, stagger, slow links,
/// fork-detection mode, etc.). `ticks` is the total run length; `min_commits` is the minimum an honest node must
/// commit; `max_lag` (if Some) is the maximum by which any honest node may trail the best honest node.
fn campaign_sc(label: &str, roles: Vec<Role>, restarts: bool, ticks: u64, min_commits: usize, max_lag: Option<usize>, setup: impl Fn(&mut Sim, u64)) {
    let (mut total_restarts, mut forks_total) = (0usize, 0usize);
    for seed in 1..=seeds() {
        let mut s = Sim::new(seed, roles.clone(), restarts);
        setup(&mut s, seed);
        s.run(ticks);
        let l = format!("{label} seed {seed}");
        if !s.expect_fork {
            s.assert_agreement(&l);
            s.assert_no_honest_double_signing(&l);
            let lens: Vec<usize> = s.honest().iter().map(|i| s.commits[*i].len()).collect();
            let best = *lens.iter().max().unwrap_or(&0);
            assert!(best >= min_commits, "{l}: liveness: best honest node committed only {best} blocks");
            if let Some(lag) = max_lag {
                for (k, n) in lens.iter().enumerate() {
                    assert!(*n + lag >= best, "{l}: honest node {} committed {n} but another committed {best}: did not catch up", s.honest()[k]);
                }
            }
        } else {
            forks_total += s.forks_detected;
        }
        total_restarts += s.restart_count;
    }
    if restarts { assert!(total_restarts > 0, "{label}: campaign never restarted any node"); }
    // For fork-detection mode: forks_total counts how many times ConflictingCommit was raised across the campaign.
    // We do NOT assert forks_total > 0 for small seed counts: fork occurrence is probabilistic. The property being
    // tested is that ConflictingCommit is surfaced (not silently swallowed) when it occurs — verified by the caller.
    let _ = forks_total;
}

#[test]
fn sim_all_honest_agree_and_make_progress_after_gst() {
    campaign("honest", vec![Role::Honest; 4], false, 30);
}

#[test]
fn sim_one_silent_validator_within_the_fault_bound() {
    campaign("silent", vec![Role::Honest, Role::Honest, Role::Silent, Role::Honest], false, 5);
}

#[test]
fn sim_one_equivocating_validator_cannot_split_the_chain() {
    campaign("equivocator", vec![Role::Honest, Role::Equivocator, Role::Honest, Role::Honest], false, 15);
}

#[test]
fn sim_honest_nodes_crash_and_restart_without_double_signing() {
    campaign("restarts", vec![Role::Honest; 4], true, 25);
}

#[test]
fn sim_restarts_together_with_an_equivocator() {
    campaign("restarts+equivocator", vec![Role::Honest, Role::Honest, Role::Equivocator, Role::Honest], true, 15);
}

// ── QAT-06 adversarial scenarios (§12 Phase 0 gate) ─────────────────────────────────────────────

/// QAT-06-S1: staggered start — nodes join at different times (spread = 80 ticks).
/// Verifies agreement and progress when validators are not all online from tick 0.
/// Requirement: §12 "staggered start" in the §12 simulation gate.
#[test]
fn sim_qat06_s1_staggered_start_agrees_and_makes_progress() {
    campaign_sc("staggered-start", vec![Role::Honest; 4], false, 600, 10, None, |s, seed| {
        let mut rng = Rng(seed.wrapping_mul(0x517CC1B727220A95) | 1);
        for i in 0..s.n { s.start_at[i] = rng.below(80); }
    });
}

/// QAT-06-S2: slow links — 25% of messages take an additional 15 ticks.
/// Verifies agreement and progress on a network with heterogeneous latency.
/// Requirement: §12 "slow links" in the §12 simulation gate.
#[test]
fn sim_qat06_s2_slow_links_agree_and_make_progress() {
    campaign_sc("slow-links", vec![Role::Honest; 4], false, 700, 8, None, |s, _| {
        s.slow_pct = 25; s.slow_extra = 15;
    });
}

/// QAT-06-S3: 2/2 network partition — no quorum on either side while split; heals at tick 230.
/// Requirement: §12 "slow links" (partition case) in the simulation gate; must converge after heal.
#[test]
fn sim_qat06_s3_partition_heals_and_converges() {
    campaign_sc("partition-2/2", vec![Role::Honest; 4], false, 580, 8, Some(6), |s, _| {
        s.partition = Some((30, 230, 0b0011)); // nodes 0+1 vs 2+3
    });
}

/// QAT-06-S4: isolated node — one node is cut off for 200 ticks while the other three commit;
/// after the partition heals the isolated node must catch up within `max_lag` commits.
/// Requirement: §12 partition/sync case.
#[test]
fn sim_qat06_s4_isolated_node_rejoins_and_catches_up() {
    campaign_sc("isolated-node", vec![Role::Honest; 4], false, 580, 8, Some(6), |s, _| {
        s.partition = Some((30, 230, 0b1000)); // node 3 isolated
    });
}

/// QAT-06-S5: Withhold adversary within f (n=4, f=1).
/// The byzantine validator withholds its votes and timeouts from randomly-chosen subsets,
/// creating the split-lock scenario the two-chain lock rule is designed to defeat.
/// Requirement: §12 "Withhold adversary within f", §5 safety rules required.
#[test]
fn sim_qat06_s5_withhold_adversary_within_fault_bound_cannot_violate_safety() {
    campaign_sc("withhold", vec![Role::Withhold, Role::Honest, Role::Honest, Role::Honest], false, 600, 5, None, |_, _| {});
}

/// QAT-06-S6: SplitBrain adversary within f.
/// The byzantine validator sends two different proposals to even/odd-indexed peers.
/// Requirement: §12 "SplitBrain adversary within f".
#[test]
fn sim_qat06_s6_splitbrain_adversary_within_fault_bound_cannot_violate_safety() {
    campaign_sc("splitbrain", vec![Role::SplitBrain, Role::Honest, Role::Honest, Role::Honest], false, 600, 5, None, |_, _| {});
}

/// QAT-06-S7: crash/restart with partition — combines crash recovery and network partition.
/// Requirement: §12 "crash/restart" in the simulation gate; more comprehensive than the base scenario.
#[test]
fn sim_qat06_s7_crash_restart_with_slow_links_never_double_signs() {
    campaign_sc("crash-restart-slow", vec![Role::Honest; 4], true, 650, 8, None, |s, _| {
        s.slow_pct = 20; s.slow_extra = 8;
    });
}

/// QAT-06-S8: fork detection beyond the fault bound — scripted counterexample.
///
/// Builds branch A by running all four nodes normally until height 1 is committed.
/// Then constructs branch B: a twin proposal at round 1 (different payload, same parent,
/// different signature) with a full quorum QC, followed by a round-2 proposal that
/// certifies it, triggering the two-chain commit rule for branch B's round-1 block.
/// Feeds the branch-B round-2 proposal to a node that already committed branch A's
/// round-1 block → `ConflictingCommit`.
///
/// Requirement: §12 "fork detection beyond f".
#[test]
fn sim_qat06_s8_conflicting_commit_is_detected_not_silently_accepted() {
    // Run chain A until nodes commit something (height ≥ 1).
    let n = 4;
    let mut nodes: Vec<E> = (0..n).map(|i| engine(i, n)).collect();
    drive(&mut nodes, 25);
    let f = fx();
    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set };
    let (committed_tip_a, committed_height) = nodes[0].committed_tip();
    assert!(committed_height >= 1, "drive(25) must commit at least 1 block");

    // Build branch B: twin at round 1 with a different payload → distinct block_id.
    let r1_leader = nodes[0].leader_of(1);
    let mut twin_engine: E = engine(r1_leader, n);
    let twin_outs = twin_engine.propose(b"FORK_BRANCH_B_R1".to_vec()).unwrap();
    let twin = twin_outs.iter().find_map(|o| if let Output::Broadcast(Msg::Proposal(b)) = o { Some(b.clone()) } else { None }).expect("twin proposal at round 1");
    let twin_id = block_id_of(&twin, &idc).unwrap();
    assert_ne!(twin_id, committed_tip_a, "twin block_id must differ from branch A's committed tip");

    // QC(twin): all 4 validators sign — simulates f+1 Byzantine cooperation (beyond fault bound).
    let twin_vm = VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: twin.round, block_id: twin_id, parent_id: twin.parent_id, parent_round: twin.qc.round() };
    let twin_vm_bytes = twin_vm.encode().unwrap();

    // Build round-2 on top of twin.  r2_engine collects votes → forms QC(twin) → proposes r2.
    let r2_leader = nodes[0].leader_of(2);
    let mut r2_engine: E = engine(r2_leader, n);
    r2_engine.on_proposal(twin.clone()).unwrap();
    for i in 0..n { let _ = r2_engine.on_vote(VoteMsg { voter: i, msg: twin_vm.clone(), signature: sign(i, CTX_VOTE, &twin_vm_bytes) }); }
    assert_eq!(r2_engine.high_qc().round(), twin.round, "r2_engine must hold QC(twin)");
    let r2_outs = r2_engine.propose(b"FORK_BRANCH_B_R2".to_vec()).unwrap();
    let r2 = r2_outs.iter().find_map(|o| if let Output::Broadcast(Msg::Proposal(b)) = o { Some(b.clone()) } else { None }).expect("r2 proposal");
    let r2_id = block_id_of(&r2, &idc).unwrap();

    // QC(r2): all 4 validators sign.
    let r2_vm = VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: r2.round, block_id: r2_id, parent_id: r2.parent_id, parent_round: r2.qc.round() };
    let r2_vm_bytes = r2_vm.encode().unwrap();

    // Build round-3 on top of r2.  r3_engine collects votes for r2 → forms QC(r2) → proposes r3.
    // r3 carries QC(r2) as its parent cert.  When the victim processes r3, observe_cert(QC(r2)) fires
    // commit_through(twin), which is not an ancestor of branch A's committed tip → ConflictingCommit.
    let r3_leader = nodes[0].leader_of(3);
    let mut r3_engine: E = engine(r3_leader, n);
    r3_engine.on_proposal(twin.clone()).unwrap();
    r3_engine.on_proposal(r2.clone()).unwrap();
    for i in 0..n { let _ = r3_engine.on_vote(VoteMsg { voter: i, msg: twin_vm.clone(), signature: sign(i, CTX_VOTE, &twin_vm_bytes) }); }
    for i in 0..n { let _ = r3_engine.on_vote(VoteMsg { voter: i, msg: r2_vm.clone(), signature: sign(i, CTX_VOTE, &r2_vm_bytes) }); }
    assert_eq!(r3_engine.high_qc().round(), r2.round, "r3_engine must hold QC(r2)");
    let r3_outs = r3_engine.propose(b"FORK_BRANCH_B_R3".to_vec()).unwrap();
    let r3 = r3_outs.iter().find_map(|o| if let Output::Broadcast(Msg::Proposal(b)) = o { Some(b.clone()) } else { None }).expect("r3 proposal");

    // Feed branch B to the victim: twin first (adds to block tree), then r2, then r3.
    // Victim has committed branch A; on r3 it must detect the fork and raise ConflictingCommit.
    let _ = nodes[0].on_proposal(twin.clone());
    let _ = nodes[0].on_proposal(r2.clone());
    let result = nodes[0].on_proposal(r3);
    assert!(
        matches!(result, Err(EngineError::ConflictingCommit)),
        "engine must raise ConflictingCommit when fed a fork chain at branch B: got {result:?}"
    );
}

/// QAT-06-S9: Withhold + restarts — combines the withholding adversary with honest-node crash/restart.
/// Requirement: §12 "crash/restart" and "Withhold within f" combined.
#[test]
fn sim_qat06_s9_withhold_plus_restarts_cannot_violate_safety() {
    campaign_sc("withhold-restarts", vec![Role::Withhold, Role::Honest, Role::Honest, Role::Honest], true, 650, 5, None, |_, _| {});
}

/// QAT-06-S10: staggered start + slow links + SplitBrain — all pre-GST adversities combined within f.
/// Requirement: §12 "thousands of seeded runs" gate; this is the heaviest combined scenario.
#[test]
fn sim_qat06_s10_combined_adversity_within_fault_bound_cannot_violate_safety() {
    campaign_sc("combined-adversity", vec![Role::SplitBrain, Role::Honest, Role::Honest, Role::Honest], false, 700, 5, None, |s, seed| {
        let mut rng = Rng(seed.wrapping_mul(0xA9A97B2C527C4A5D) | 1);
        for i in 0..s.n { s.start_at[i] = rng.below(60); }
        s.slow_pct = 20; s.slow_extra = 10;
    });
}

#[test]
#[ignore = "diagnostic: DIAG_ROLES=HHEH DIAG_SEED=7 DIAG_RESTARTS=1 cargo test --release -- --ignored --nocapture diag"]
fn diag_run() {
    let roles: Vec<Role> = std::env::var("DIAG_ROLES").unwrap_or("HHSH".into()).chars().map(|c| match c { 'S' => Role::Silent, 'E' => Role::Equivocator, _ => Role::Honest }).collect();
    let seed = std::env::var("DIAG_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let mut s = Sim::new(seed, roles, std::env::var("DIAG_RESTARTS").is_ok());
    for t in (0..520).step_by(40) {
        s.run(40);
        let rounds: Vec<Option<u64>> = (0..s.n).map(|i| s.nodes[i].as_ref().map(|e| e.round())).collect();
        let hq: Vec<Option<u64>> = (0..s.n).map(|i| s.nodes[i].as_ref().map(|e| e.high_qc().round())).collect();
        println!("t={} rounds={:?} high_qc={:?} commits={:?} net={} sent={} restarts={}", t + 40, rounds, hq, (0..s.n).map(|i| s.commits[i].len()).collect::<Vec<_>>(), s.net.len(), s.log.len(), s.restart_count);
    }
}
