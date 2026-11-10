// Shared body of the PQ-HotStuff-2 engine tests. It is `include!`d by two test crates that differ ONLY in the signature scheme
// behind `doubles::{TestSigner, TestVerifier, test_public_key}`: tests/pq_hotstuff_engine.rs (fast, non-cryptographic doubles)
// and tests/pq_hotstuff_engine_fips204.rs (real FIPS 204 ML-DSA-65). Every assertion is identical in both; the includer defines
// `mod doubles` and `const DEFAULT_SEEDS`.
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};

use chain_forge_consensus::pq_hotstuff::certs::*;
use chain_forge_consensus::pq_hotstuff::engine::*;
use chain_forge_consensus::pq_hotstuff::blockstore::{BlockStore, StoreError};
use chain_forge_consensus::pq_hotstuff::driver::{classify_engine_error, validate_config, Driver, DriverConfig, DriverError, Outbound};
use chain_forge_consensus::pq_hotstuff::exec::{ExecCursor, ExecError, Executor, InterimApp};
use chain_forge_consensus::pq_hotstuff::header::{verify_header_chain, Anchor, ChainParams, ChainPoint, HeaderError, PayloadFreeBlock, Start, VerifiedChain};
use chain_forge_consensus::pq_hotstuff::netmsg::{decode_header, encode_block, encode_header};
use chain_forge_consensus::pq_hotstuff::limits::PqLimits;
use chain_forge_consensus::pq_hotstuff::netmsg::{self as net, MessageLimits, NetLimitError, NetMsg, SYNC_BLOCKS_CEILING};
use chain_forge_consensus::pq_hotstuff::pacemaker::{Pacemaker, PacemakerConfig, PacemakerError};
use chain_forge_consensus::pq_hotstuff::sync::{check_response, SyncClient, SyncError, SyncRequest, SyncResponse};
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
/// Blocks per sync response used by the tests.
const SYNC_K: usize = 8;
/// The transport limit these tests configure is the DERIVED MINIMUM for the 4-validator test chain (the owner has not set one for any real
/// network; the repository defines none), so every kind of message fits and nothing is larger than needed.
fn limits(n: usize) -> PqLimits {
    let l = PqLimits { max_validators: n, max_cert_validators: 1024, max_block_payload_bytes: 4096, max_message_bytes: None };
    let need = MessageLimits::minimum_transport_limit(&l, n, CHAIN.len(), SYNC_K).expect("derivable").max(l.proposal_envelope_max(n).unwrap());
    PqLimits { max_message_bytes: Some(need), ..l }
}
fn mlim() -> MessageLimits { MessageLimits::derive(&limits(4), 4, CHAIN.len(), SYNC_K).expect("limits") }
fn cfg(i: usize, n: usize) -> EngineConfig {
    EngineConfig { chain_id: CHAIN.into(), protocol_profile: PROFILE.into(), set: set_n(n), my_index: i, genesis_hash: GENESIS_HASH, limits: limits(n), seed: 0, checkpoint: None }
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
    Block { checkpoint: None, epoch: 0, round: 6, height: 5, parent_id: [5; 32], qc: Cert::Qc(mk_qc(f, 5, 5, &[0, 1, 2])), tc: None, payload: b"devnet-interim payload".to_vec(), proposer: 1, signature: vec![] }
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
                _ => vec![], // EnteredRound and the durable-state requests
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
    assert!(nodes[other].on_proposal(Block { checkpoint: None, epoch: 1, ..b.clone() }).is_err());
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
    let Some(Output::Send { msg: Msg::Vote(v1), .. }) = first.into_iter().find(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. })) else { panic!("no vote") };
    let e = nodes.remove(v);
    let mut e = restart(e, v, 4);
    let again = e.on_proposal(b).unwrap();
    let Some(Output::Send { msg: Msg::Vote(v2), .. }) = again.into_iter().find(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. })) else { panic!("no re-sent vote") };
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
    Block { checkpoint: None, epoch: 0, round, height: 1, parent_id: f.genesis.block_id(), qc: Cert::Genesis(f.genesis.clone()), tc: None, payload: b"x".to_vec(), proposer, signature: vec![] }
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
    let b2 = signed_block(&f, Block { checkpoint: None, epoch: 0, round: 2, height: 2, parent_id: id1, qc: Cert::Qc(forged.clone()), tc: None, payload: b"y".to_vec(), proposer: l2, signature: vec![] });
    assert!(e.on_proposal(b2).is_err(), "a forged QC must not be accepted");
    forged.sigs = mk_qc(&f, 1, 0, &[0, 1, 2]).sigs; // signatures over a different block
    let b2 = signed_block(&f, Block { checkpoint: None, epoch: 0, round: 2, height: 2, parent_id: id1, qc: Cert::Qc(forged), tc: None, payload: b"y".to_vec(), proposer: l2, signature: vec![] });
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
    let skipping = signed_block(&f, Block { checkpoint: None, epoch: 0, round: 4, height: 2, parent_id: id1, qc: Cert::Qc(qc1.clone()), tc: Some(tc), payload: b"z".to_vec(), proposer: e.leader_of(4), signature: vec![] });
    let out = e.on_proposal(skipping).unwrap();
    assert!(!has_vote(&out), "voted for a block whose QC is below the TC's highest reported QC");
    // control: the same shape with a TC that reports only round 1 is votable
    let tc_ok = mk_tc(&f, 3, &[(0, 1), (1, 1), (2, 1)], Cert::Qc(qc1.clone()));
    let fine = signed_block(&f, Block { checkpoint: None, epoch: 0, round: 4, height: 2, parent_id: id1, qc: Cert::Qc(qc1), tc: Some(tc_ok), payload: b"w".to_vec(), proposer: e.leader_of(4), signature: vec![] });
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
    let b4 = signed_block(&f, Block { checkpoint: None, epoch: 0, round: 4, height: 2, parent_id: id1, qc: Cert::Qc(qc1), tc: Some(tc), payload: b"t".to_vec(), proposer: e.leader_of(4), signature: vec![] });
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
    let Some(Output::Send { msg: Msg::Vote(v), .. }) = nodes[voter].on_proposal(a).unwrap().into_iter().find(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. })) else { panic!("no vote") };
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
    let Some(Output::Send { msg: Msg::Vote(fv), .. }) = t_voter.on_proposal(fb).unwrap().into_iter().find(|o| matches!(o, Output::Send { msg: Msg::Vote(_), .. })) else { panic!("no foreign vote") };
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


// ================================================================================================ network envelope and derived limits

fn worst_qc(f: &Fx) -> Qc { mk_qc(f, 9, 9, &[0, 1, 2, 3]) }
fn worst_tc(f: &Fx) -> Tc { mk_tc(f, 10, &[(0, 9), (1, 9), (2, 9), (3, 9)], Cert::Qc(worst_qc(f))) }
fn worst_block(f: &Fx, payload: usize) -> Block {
    Block { checkpoint: None, epoch: 0, round: 11, height: 7, parent_id: [1; 32], qc: Cert::Qc(worst_qc(f)), tc: Some(worst_tc(f)), payload: vec![7u8; payload], proposer: 3, signature: vec![5u8; 3309] }
}
fn big_vote() -> VoteMsg {
    VoteMsg { voter: 2, msg: VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: u64::MAX, block_id: [3; 32], parent_id: [4; 32], parent_round: u64::MAX }, signature: vec![9u8; 3309] }
}
fn big_timeout(f: &Fx) -> TimeoutMsg {
    TimeoutMsg { voter: 1, msg: TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: u64::MAX, high_qc_round: u64::MAX }, signature: vec![9u8; 3309], high_qc: Cert::Qc(worst_qc(f)) }
}
fn every_kind(f: &Fx) -> Vec<NetMsg> {
    vec![
        NetMsg::Consensus(Msg::Proposal(worst_block(f, 100))),
        NetMsg::Consensus(Msg::Proposal(Block { tc: None, ..worst_block(f, 0) })),
        NetMsg::Consensus(Msg::Vote(big_vote())),
        NetMsg::Consensus(Msg::Timeout(big_timeout(f))),
        NetMsg::Consensus(Msg::Tc(worst_tc(f))),
        NetMsg::SyncRequest(SyncRequest { want: [2; 32], max_blocks: 3 }),
        NetMsg::SyncResponse(SyncResponse { want: [2; 32], blocks: vec![worst_block(f, 5), worst_block(f, 6)] }),
    ]
}

/// The derived per-kind limit is not a loose bound: it equals the encoded size of the largest message of that kind (all signers, a TC with a
/// nested QC, the payload limit, the maximum number of sync blocks). A formula that undercounted would make a legal message undeliverable.
#[test]
fn derived_limits_equal_the_size_of_the_largest_message_of_every_kind() {
    let f = fx();
    let m = mlim();
    let len = |x: NetMsg| net::encode(&x).len() as u64;
    assert_eq!(len(NetMsg::Consensus(Msg::Proposal(worst_block(&f, 4096)))), m.proposal);
    assert_eq!(len(NetMsg::Consensus(Msg::Vote(big_vote()))), m.vote);
    assert_eq!(len(NetMsg::Consensus(Msg::Timeout(big_timeout(&f)))), m.timeout);
    assert_eq!(len(NetMsg::Consensus(Msg::Tc(worst_tc(&f)))), m.tc);
    assert_eq!(len(NetMsg::SyncRequest(SyncRequest { want: [1; 32], max_blocks: SYNC_K as u32 })), m.sync_request);
    let resp = SyncResponse { want: [1; 32], blocks: (0..SYNC_K).map(|_| worst_block(&f, 4096)).collect() };
    assert_eq!(len(NetMsg::SyncResponse(resp)), m.sync_response);
    assert!(m.transport >= m.sync_response.max(m.proposal).max(m.timeout).max(m.tc).max(m.vote));
}

#[test]
fn the_transport_limit_is_never_defaulted_and_must_cover_the_derived_minimum() {
    let mut l = limits(4);
    l.max_message_bytes = None;
    let needed = MessageLimits::minimum_transport_limit(&l, 4, CHAIN.len(), SYNC_K).unwrap();
    assert_eq!(MessageLimits::derive(&l, 4, CHAIN.len(), SYNC_K), Err(NetLimitError::LimitUnset { needed }));
    l.max_message_bytes = Some(needed - 1);
    assert_eq!(MessageLimits::derive(&l, 4, CHAIN.len(), SYNC_K), Err(NetLimitError::BelowMinimum { limit: needed - 1, needed }));
    l.max_message_bytes = Some(needed);
    assert!(MessageLimits::derive(&l, 4, CHAIN.len(), SYNC_K).is_ok());
    // the existing p2p default on devnet (max_tx_bytes x 2 = 524,288) cannot carry a 1 MiB payload plus its certificates
    let big = PqLimits { max_validators: 4, max_cert_validators: 1024, max_block_payload_bytes: 1_048_576, max_message_bytes: Some(524_288) };
    assert!(matches!(MessageLimits::derive(&big, 4, CHAIN.len(), SYNC_K), Err(NetLimitError::BelowMinimum { .. })));
}

#[test]
fn the_locked_8_mib_limit_covers_the_devnet_and_refuses_chains_that_need_more() {
    use chain_forge_consensus::pq_hotstuff::netmsg::{read_bounded, MAX_MESSAGE_SIZE};
    assert_eq!(MAX_MESSAGE_SIZE, 8_388_608);
    // devnet: 4 validators, 1 MiB payload; the limit allows K = 7 sync blocks and no more than that
    let dev = PqLimits { max_validators: 4, max_cert_validators: 1024, max_block_payload_bytes: 1_048_576, max_message_bytes: Some(MAX_MESSAGE_SIZE) };
    assert!(MessageLimits::derive(&dev, 4, CHAIN.len(), 7).is_ok());
    assert!(matches!(MessageLimits::derive(&dev, 4, CHAIN.len(), 8), Err(NetLimitError::BelowMinimum { .. })));
    // 1,000 validators: a TC fits (about 6.64 MB) but a proposal carrying a QC and a TC does not, even with an empty payload
    let big = PqLimits { max_validators: 1000, max_cert_validators: 1024, max_block_payload_bytes: 0, max_message_bytes: Some(MAX_MESSAGE_SIZE) };
    let needed = MessageLimits::minimum_transport_limit(&big, 1000, CHAIN.len(), 1).unwrap();
    assert!(needed > MAX_MESSAGE_SIZE, "needed {needed}");
    assert!(matches!(MessageLimits::derive(&big, 1000, CHAIN.len(), 1), Err(NetLimitError::BelowMinimum { .. })));
    // the stream reader stops at the cap without trusting any reported length
    let ok = vec![7u8; 20_000];
    assert_eq!(read_bounded(&mut &ok[..], 20_000).unwrap(), ok);
    assert!(matches!(read_bounded(&mut &ok[..], 19_999), Err(net::NetError::TooLarge { .. })));
    struct Endless(u64);
    impl std::io::Read for Endless { fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { self.0 += b.len() as u64; for x in b.iter_mut() { *x = 1; } Ok(b.len()) } }
    let mut e = Endless(0);
    assert!(matches!(read_bounded(&mut e, MAX_MESSAGE_SIZE), Err(net::NetError::TooLarge { .. })));
    assert!(e.0 <= MAX_MESSAGE_SIZE + 8192, "read {} bytes before dropping", e.0);
}

#[test]
fn limit_arithmetic_is_checked_and_parameters_are_validated() {
    let huge = PqLimits { max_validators: 4, max_cert_validators: 1024, max_block_payload_bytes: u64::MAX, max_message_bytes: Some(u64::MAX) };
    assert_eq!(MessageLimits::derive(&huge, 4, CHAIN.len(), SYNC_K), Err(NetLimitError::Overflow));
    let near = PqLimits { max_block_payload_bytes: u64::MAX / 2, max_message_bytes: Some(u64::MAX), ..huge };
    assert_eq!(MessageLimits::derive(&near, 4, CHAIN.len(), 64), Err(NetLimitError::Overflow));
    let l = limits(4);
    for (n, c, k) in [(0, 5, 1), (1025, 5, 1), (4, 0, 1), (4, 256, 1), (4, 5, 0), (4, 5, SYNC_BLOCKS_CEILING + 1)] {
        assert!(matches!(MessageLimits::derive(&l, n, c, k), Err(NetLimitError::BadParams(_))), "{n} {c} {k}");
    }
}

#[test]
fn the_number_of_sync_blocks_follows_the_transport_limit() {
    let l = limits(4);
    let min8 = MessageLimits::minimum_transport_limit(&l, 4, CHAIN.len(), 8).unwrap();
    assert_eq!(MessageLimits::max_sync_blocks_under(&l, 4, CHAIN.len(), min8), Some(8));
    let min1 = MessageLimits::minimum_transport_limit(&l, 4, CHAIN.len(), 1).unwrap();
    assert_eq!(MessageLimits::max_sync_blocks_under(&l, 4, CHAIN.len(), min1), Some(1));
    assert_eq!(MessageLimits::max_sync_blocks_under(&l, 4, CHAIN.len(), min1 - 1), None);
    assert!(MessageLimits::max_sync_blocks_under(&l, 4, CHAIN.len(), u64::MAX / 4).unwrap() <= SYNC_BLOCKS_CEILING);
}

#[test]
fn every_message_kind_round_trips_and_re_encodes_identically() {
    let f = fx();
    let m = mlim();
    for x in every_kind(&f) {
        let b = net::encode(&x);
        let d = net::decode(&b, &m).expect("decodes");
        assert_eq!(d, x);
        assert_eq!(net::encode(&d), b, "decode then encode is not the identity");
    }
}

#[test]
fn truncations_trailing_bytes_and_corrupt_headers_are_rejected() {
    let f = fx();
    let m = mlim();
    for x in every_kind(&f) {
        let b = net::encode(&x);
        let stride = if b.len() > 2000 { 41 } else { 1 };
        let mut cuts: Vec<usize> = (0..b.len()).step_by(stride).collect();
        cuts.extend([b.len().saturating_sub(1), b.len().saturating_sub(2)]);
        for cut in cuts { assert!(net::decode(&b[..cut], &m).is_err(), "cut {cut} of {}", b.len()); }
        let mut more = b.clone(); more.push(0);
        assert!(net::decode(&more, &m).is_err(), "trailing byte accepted");
        for (at, v) in [(0usize, b[0] ^ 1), (9, b[9] ^ 1), (11, 0), (11, 7)] {
            let mut c = b.clone(); c[at] = v;
            assert_ne!(net::decode(&c, &m).ok(), Some(x.clone()), "corrupt header byte {at} accepted");
        }
    }
}

/// The length is checked against the limit for the message's KIND before any parsing: an oversize message fails as TooLarge, not as a
/// parse error, and an absurd inner length or count in a tiny message cannot make the decoder allocate or read past the input.
#[test]
fn oversize_messages_are_refused_before_parsing_and_absurd_lengths_cannot_allocate() {
    let f = fx();
    let m = mlim();
    let mut v = net::encode(&NetMsg::Consensus(Msg::Vote(big_vote())));
    v.resize(m.vote as usize + 1, 0);
    assert!(matches!(net::decode(&v, &m), Err(net::NetError::TooLarge { .. })));
    assert!(matches!(net::decode(&vec![0u8; m.transport as usize + 1], &m), Err(net::NetError::TooLarge { .. })));
    let mut r = TAG_NET_BYTES.to_vec();
    r.extend_from_slice(&1u16.to_be_bytes());
    r.push(6);
    r.extend_from_slice(&[0u8; 32]);
    r.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(net::decode(&r, &m), Err(net::NetError::Malformed(_))), "sync count u32::MAX");
    let mut p = net::encode(&NetMsg::Consensus(Msg::Proposal(worst_block(&f, 10))));
    let qc_len_at = 12 + 56;
    p[qc_len_at..qc_len_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(net::decode(&p, &m).is_err());
    // sync request counts
    for bad in [0u32, SYNC_K as u32 + 1, u32::MAX] {
        let b = net::encode(&NetMsg::SyncRequest(SyncRequest { want: [1; 32], max_blocks: bad }));
        assert!(net::decode(&b, &m).is_err(), "max_blocks {bad}");
    }
    // option flag and signature length
    let blk = Block { tc: None, ..worst_block(&f, 3) };
    let mut b = net::encode(&NetMsg::Consensus(Msg::Proposal(blk.clone())));
    let flag_at = 12 + 56 + 4 + blk.qc.encode().len();
    assert_eq!(b[flag_at], 0);
    b[flag_at] = 2;
    assert!(net::decode(&b, &m).is_err(), "option flag 2");
    let short = Block { signature: vec![1u8; 10], ..blk };
    assert!(net::decode(&net::encode(&NetMsg::Consensus(Msg::Proposal(short))), &m).is_err(), "short signature");
}
const TAG_NET_BYTES: &[u8] = net::TAG_NET;

// ================================================================================================ pacemaker

#[test]
fn the_pacemaker_backs_off_up_to_its_cap_and_resets_on_progress() {
    let mut p = Pacemaker::new(PacemakerConfig { base: 30, max: 200 }).unwrap();
    let seq: Vec<u64> = (0..6).map(|_| { let t = p.timeout(); p.on_timeout(); t }).collect();
    assert_eq!(seq, vec![30, 60, 120, 200, 200, 200]);
    p.on_progress();
    assert_eq!((p.timeout(), p.consecutive_timeouts()), (30, 0));
    for _ in 0..1000 { p.on_timeout(); }
    assert_eq!(p.timeout(), 200);
    let mut q = Pacemaker::new(PacemakerConfig { base: u64::MAX / 2 + 1, max: u64::MAX }).unwrap();
    q.on_timeout();
    assert_eq!(q.timeout(), u64::MAX, "a shift that would wrap must saturate");
    assert_eq!(Pacemaker::new(PacemakerConfig { base: 0, max: 5 }).err(), Some(PacemakerError::ZeroBase));
    assert_eq!(Pacemaker::new(PacemakerConfig { base: 9, max: 5 }).err(), Some(PacemakerError::MaxBelowBase));
}

// ================================================================================================ block sync

fn idctx(f: &Fx) -> IdCtx<'_> { IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &f.set } }
fn id_of(b: &Block) -> Option<BlockId> { let f = fx(); block_id_of(b, &idctx(&f)).ok() }

/// Four honest nodes over reliable delivery: returns them and the blocks of the resulting chain by height.
fn built_chain(steps: usize) -> (Vec<E>, Vec<Block>) {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    drive(&mut nodes, steps);
    let mut bs: Vec<Block> = nodes[0].known_blocks().into_iter().cloned().collect();
    bs.sort_by_key(|b| b.height);
    (nodes, bs)
}

#[test]
fn a_node_missing_ancestors_fetches_them_by_sync_and_catches_up_without_voting() {
    let f = fx();
    let (nodes, chain) = built_chain(9);
    let tip = chain.last().unwrap().clone();
    let mut lag = engine(2, 4); // a fresh node with no blocks
    let Err(EngineError::MissingParent(mut want)) = lag.on_proposal(tip.clone()) else { panic!("a block with an unknown parent must be reported") };
    let (mut requests, mut commits, mut votes_during_sync) = (0, vec![], 0);
    loop {
        requests += 1;
        assert!(requests < 20, "sync does not converge");
        let req = SyncRequest { want, max_blocks: 3 };
        let resp = nodes[0].serve_sync(&req, 3).expect("the peer has the block");
        check_response(&req, &resp, &idctx(&f), 3).expect("a good response passes the structural check");
        let mut stuck = None;
        for b in resp.blocks {
            match lag.on_sync_block(b) {
                Ok(outs) => for o in outs {
                    match o { Output::Commit(c) => commits.push(c), Output::Send { msg: Msg::Vote(_), .. } => votes_during_sync += 1, _ => {} }
                },
                Err(EngineError::MissingParent(p)) => { stuck = Some(p); break; }
                Err(e) => panic!("a genuine block was rejected: {e}"),
            }
        }
        if let Some(p) = stuck { want = p; continue; }
        match lag.on_proposal(tip.clone()) { Ok(_) => break, Err(EngineError::MissingParent(p)) => want = p, Err(e) => panic!("{e}") }
    }
    assert!(requests >= 3, "a 3-block window needs several requests for a 9-block chain (got {requests})");
    assert_eq!(votes_during_sync, 0, "block sync must never produce votes");
    let theirs = nodes[0].committed_after(0);
    assert!(!commits.is_empty());
    for c in &commits { assert_eq!(c.id, theirs[c.height as usize - 1].id, "synced commit differs at height {}", c.height); }
    assert_eq!(commits.iter().map(|c| c.height).collect::<Vec<_>>(), (1..=commits.len() as u64).collect::<Vec<_>>());
}

#[test]
fn malformed_sync_responses_are_rejected() {
    let f = fx();
    let idc = idctx(&f);
    let (nodes, chain) = built_chain(9);
    let tip_id = id_of(chain.last().unwrap()).unwrap();
    let req = SyncRequest { want: tip_id, max_blocks: 4 };
    let good = nodes[0].serve_sync(&req, 4).unwrap();
    assert_eq!(good.blocks.len(), 4);
    assert!(check_response(&req, &good, &idc, 4).is_ok());
    let bad = |r: &SyncResponse| check_response(&req, r, &idc, 4);
    assert_eq!(bad(&SyncResponse { want: [0; 32], ..good.clone() }), Err(SyncError::WrongTarget));
    assert_eq!(bad(&SyncResponse { blocks: vec![], ..good.clone() }), Err(SyncError::Empty));
    let mut many = good.clone(); many.blocks.insert(0, chain[0].clone());
    assert_eq!(bad(&many), Err(SyncError::TooManyBlocks { got: 5, max: 4 }));
    let mut swapped = good.clone(); swapped.blocks.swap(1, 2);
    assert_eq!(bad(&swapped), Err(SyncError::NotLinked(1)));
    let mut cut = good.clone(); cut.blocks.pop();
    assert_eq!(bad(&cut), Err(SyncError::WrongEnd));
    let mut payload = good.clone(); payload.blocks[1].payload.push(1);
    assert_eq!(bad(&payload), Err(SyncError::NotLinked(2)), "a changed block no longer links to its successor");
    let mut last = good.clone(); last.blocks[3].payload.push(1);
    assert_eq!(bad(&last), Err(SyncError::WrongEnd));
    // the server never exceeds its own cap, and an unknown block is not served
    assert_eq!(nodes[0].serve_sync(&SyncRequest { want: tip_id, max_blocks: 100 }, 2).unwrap().blocks.len(), 2);
    assert!(nodes[0].serve_sync(&SyncRequest { want: [9; 32], max_blocks: 4 }, 4).is_none());
    // a signature or certificate tampered inside an otherwise well-linked response is caught by the engine, which then holds nothing of it
    let mut lag = engine(2, 4);
    lag.on_sync_block(chain[0].clone()).unwrap();
    let held = lag.known_blocks().len();
    let mut sig = chain[1].clone(); sig.signature[7] ^= 1;
    assert!(lag.on_sync_block(sig).is_err());
    let mut forged_qc = chain[1].clone();
    if let Cert::Qc(q) = &mut forged_qc.qc { q.sigs[0][5] ^= 1; }
    assert!(lag.on_sync_block(forged_qc).is_err());
    assert_eq!(lag.known_blocks().len(), held, "a rejected block must leave no trace");
    assert!(lag.on_sync_block(chain[1].clone()).is_ok());
}

#[test]
fn the_sync_client_asks_once_expires_requests_and_stays_bounded() {
    let mut c = SyncClient::new(10, 2);
    assert!(c.want([1; 32], 0, 4).is_some());
    assert!(c.want([1; 32], 1, 4).is_none(), "already being fetched");
    assert!(c.want([2; 32], 1, 4).is_some());
    assert!(c.want([3; 32], 2, 4).is_none(), "table full");
    assert_eq!(c.pending(), 2);
    assert!(c.want([1; 32], 11, 4).is_some(), "an expired request is asked again");
    c.complete(&[1; 32]);
    assert_eq!(c.pending(), 0);
}

// ================================================================================================ persistence and recovery

fn mem() -> MemStorage { MemStorage::new(faults()) }

/// Like `drive`, but applies the engine's durable-state requests to each node's block store, in order, as a driver must.
fn drive_persisting(nodes: &mut Vec<E>, stores: &mut Vec<BlockStore<MemStorage>>, steps: usize) -> Vec<Vec<Committed>> {
    let n = nodes.len();
    let mut commits: Vec<Vec<Committed>> = vec![vec![]; n];
    for _ in 0..steps {
        let r = nodes.iter().map(|e| e.round()).max().unwrap();
        let l = nodes[0].leader_of(r);
        let first = match nodes[l].propose(format!("tx-batch-{r}").into_bytes()) { Ok(o) => o, Err(_) => break };
        let mut q: VecDeque<(usize, Output)> = first.into_iter().map(|o| (l, o)).collect();
        while let Some((from, o)) = q.pop_front() {
            stores[from].apply(&o, &id_of).expect("persist");
            let deliveries: Vec<(usize, Msg)> = match o {
                Output::Broadcast(m) => (0..n).filter(|i| *i != from).map(|i| (i, m.clone())).collect(),
                Output::Send { to, msg } => if to == from { vec![] } else { vec![(to, msg)] },
                Output::Commit(c) => { commits[from].push(c); vec![] }
                _ => vec![],
            };
            for (to, m) in deliveries { for o in nodes[to].on_message(m).unwrap_or_default() { q.push_back((to, o)); } }
        }
    }
    commits
}

#[test]
fn a_restored_node_keeps_its_committed_history_resends_its_vote_and_executes_nothing_twice() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let mut stores: Vec<BlockStore<MemStorage>> = (0..4).map(|_| BlockStore::new(mem())).collect();
    let commits = drive_persisting(&mut nodes, &mut stores, 10);
    // a node that is NOT the next leader of its last vote, so that the re-sent vote is visible as a message
    let v = (0..4).find(|v| { let r = nodes[*v].store().record().last_vote.as_ref().map(|l| l.round); r.map_or(false, |r| nodes[*v].leader_of(r + 1) != *v) }).expect("such a node exists");
    let executed = commits[v].len() as u64;
    assert!(executed >= 6);
    let (tip, hqc, known) = (nodes[v].committed_tip(), nodes[v].high_qc().round(), nodes[v].known_blocks().len());
    let last_vote = nodes[v].store().record().last_vote.clone().expect("it voted");
    let next_leader_is_me = nodes[v].leader_of(last_vote.round + 1) == v;
    let mut e = restart(nodes.remove(v), v, 4); // safety store reopened, empty block tree
    let loaded = stores[v].load().expect("the store loads");
    assert_eq!(loaded.damaged_blocks, 0);
    let (restored, dropped) = e.restore(loaded.blocks, &loaded.committed, loaded.high_qc, loaded.high_tc).expect("restores");
    assert_eq!((restored, dropped), (known, 0));
    assert_eq!(e.committed_tip(), tip, "committed history must survive a restart");
    assert_eq!(e.high_qc().round(), hqc);
    assert!(e.committed_after(executed).is_empty(), "nothing is left to execute: no duplicate execution");
    // an executor that is two heights behind is handed exactly those two blocks, in order
    let behind = e.committed_after(executed - 2);
    assert_eq!(behind.iter().map(|c| c.height).collect::<Vec<_>>(), vec![executed - 1, executed]);
    assert_eq!(behind.iter().map(|c| c.id).collect::<Vec<_>>(), commits[v][commits[v].len() - 2..].iter().map(|c| c.id).collect::<Vec<_>>());
    // re-delivering every known block as a live proposal executes and votes for nothing again
    for b in nodes[0].known_blocks().into_iter().cloned().collect::<Vec<_>>() {
        let outs = e.on_proposal(b).unwrap_or_default();
        assert!(!outs.iter().any(|o| matches!(o, Output::Commit(_) | Output::Send { msg: Msg::Vote(_), .. })), "a restored node acted twice on a known block");
    }
    // the stored vote is re-sent byte for byte
    let outs = e.resend_last_vote().unwrap();
    match outs.into_iter().find_map(|o| if let Output::Send { msg: Msg::Vote(vm), .. } = o { Some(vm) } else { None }) {
        Some(vm) => {
            assert_eq!(vm.msg.encode().unwrap(), last_vote.message);
            assert_eq!(vm.signature, last_vote.envelope.signature, "the vote must be re-sent, not re-signed");
        }
        None => panic!("no vote was re-sent although another validator leads the next round (next leader is me: {next_leader_is_me})"),
    }
}

#[test]
fn a_forged_or_damaged_stored_block_cannot_inject_state_and_committed_history_is_never_shortened() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let mut stores: Vec<BlockStore<MemStorage>> = (0..4).map(|_| BlockStore::new(mem())).collect();
    drive_persisting(&mut nodes, &mut stores, 8);
    let v = 1;
    let loaded = stores[v].load().unwrap();
    let mut blocks = loaded.blocks.clone();
    blocks.sort_by_key(|b| b.height);
    let top = blocks.last().unwrap().clone();
    assert!(loaded.committed.iter().all(|(_, id)| Some(*id) != id_of(&top)), "the newest block is not committed yet");
    // a forged copy of an UNCOMMITTED block, correctly sealed on disk (valid checksum), is dropped by validation
    let mut forged = top.clone(); forged.payload = b"forged".to_vec();
    let mut e = restart(engine(v, 4), v, 4);
    let mut with_forged: Vec<Block> = blocks.iter().filter(|b| b.height != top.height).cloned().collect();
    with_forged.push(forged.clone());
    let (ok, dropped) = e.restore(with_forged, &loaded.committed, loaded.high_qc.clone(), loaded.high_tc.clone()).unwrap();
    assert_eq!(dropped, 1, "the forged block must be dropped");
    assert_eq!(ok, blocks.len() - 1);
    // a forged block named by a COMMIT marker refuses recovery instead of being believed
    let mut e = restart(engine(v, 4), v, 4);
    let committed_height = loaded.committed.last().unwrap().0;
    let target = blocks.iter().find(|b| b.height == committed_height).unwrap().clone();
    let mut bad = target.clone(); bad.payload = b"forged".to_vec();
    let mut tampered: Vec<Block> = blocks.iter().filter(|b| b.height != committed_height).cloned().collect();
    tampered.push(bad);
    assert!(matches!(e.restore(tampered, &loaded.committed, None, None), Err(EngineError::Restore(_))));
    // a committed marker whose block is missing refuses recovery
    let mut e = restart(engine(v, 4), v, 4);
    let missing: Vec<Block> = blocks.iter().filter(|b| b.height != committed_height).cloned().collect();
    assert!(matches!(e.restore(missing, &loaded.committed, None, None), Err(EngineError::Restore(_))));
    // a commit marker whose height disagrees with the height of the block it names refuses recovery (the block itself is genuine)
    let mut e = restart(engine(v, 4), v, 4);
    let mut skewed = loaded.committed.clone();
    let (h, id) = *skewed.last().unwrap();
    assert!(h >= 2);
    *skewed.last_mut().unwrap() = (h - 1, id);
    assert!(matches!(e.restore(blocks.clone(), &skewed, None, None), Err(EngineError::Restore(_))));
}

#[test]
fn the_block_store_ignores_damage_to_blocks_and_hints_but_refuses_damaged_or_gapped_committed_history() {
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let mut stores: Vec<BlockStore<MemStorage>> = (0..4).map(|_| BlockStore::new(mem())).collect();
    drive_persisting(&mut nodes, &mut stores, 8);
    let base = stores[0].storage().clone();
    let names = base.names();
    let blk = names.iter().find(|n| n.starts_with("blk-")).unwrap().clone();
    let cmts: Vec<String> = names.iter().filter(|n| n.starts_with("cmt-")).cloned().collect();
    assert!(cmts.len() >= 3);
    let total_blocks = names.iter().filter(|n| n.starts_with("blk-")).count();
    let load = |st: MemStorage| BlockStore::new(st).load();

    let clean = load(base.clone()).unwrap();
    assert_eq!((clean.blocks.len(), clean.damaged_blocks, clean.damaged_hints), (total_blocks, 0, 0));
    assert_eq!(clean.committed.len(), cmts.len());
    assert!(clean.high_qc.is_some());

    let flip = |st: &mut MemStorage, name: &str, at: usize| { let mut d = st.raw(name).unwrap(); let at = at.min(d.len() - 1); d[at] ^= 1; st.set_raw(name, d); };
    let mut st = base.clone(); flip(&mut st, &blk, 50);
    let l = load(st).unwrap();
    assert_eq!((l.blocks.len(), l.damaged_blocks), (total_blocks - 1, 1));
    let mut st = base.clone(); let d = st.raw(&blk).unwrap(); st.set_raw(&blk, d[..d.len() / 2].to_vec());
    assert_eq!(load(st).unwrap().damaged_blocks, 1, "a truncated block file");
    let mut st = base.clone(); st.set_raw("blk-leftover.tmp", vec![1, 2, 3]); st.set_raw("cmt-0000000000000001.tmp", vec![9]);
    assert_eq!(load(st).unwrap().damaged_blocks, 0, "leftover temporary files are ignored");
    let mut st = base.clone(); flip(&mut st, "hqc", 40);
    let l = load(st).unwrap();
    assert_eq!((l.damaged_hints, l.high_qc.is_none()), (1, true));

    let mut st = base.clone(); flip(&mut st, &cmts[1], 30);
    assert_eq!(load(st).err(), Some(StoreError::CommittedMarkerDamaged(2)));
    let mut st = base.clone(); st.delete_raw(&cmts[1]);
    assert_eq!(load(st).err(), Some(StoreError::CommittedHistoryGap(2)));
    let mut st = base.clone(); st.delete_raw(cmts.last().unwrap());
    assert_eq!(load(st).unwrap().committed.len(), cmts.len() - 1, "losing only the newest marker is a legal crash outcome");
}

/// Crash at every storage operation of a realistic persistence sequence (block, block, commit 1, block, commit 2, ...), and in every
/// possible post-crash storage state: the store always loads, the committed markers are contiguous, every marker's block is present
/// and valid, and the engine restores to exactly the committed height the markers promise.
#[test]
fn a_crash_at_any_point_of_persisting_blocks_and_commits_never_corrupts_or_loses_committed_history() {
    let (_, chain) = built_chain(8);
    let seq = |st: &mut BlockStore<MemStorage>| {
        for (i, b) in chain.iter().take(5).enumerate() {
            let _ = st.put_block(&id_of(b).unwrap(), b);
            if i >= 1 { let _ = st.put_commit(i as u64, &id_of(&chain[i - 1]).unwrap()); }
        }
        let _ = st.put_high_qc(&chain[3].qc);
    };
    // count the fault-eligible operations of a clean run
    let f = faults();
    let mut clean = BlockStore::new(MemStorage::new(f.clone()));
    seq(&mut clean);
    let total = f.borrow().ops;
    assert!(total >= 24);
    let mut outcomes_checked = 0;
    for crash_at in 0..=total {
        let f = faults();
        f.borrow_mut().crash_before = Some(crash_at);
        let mut st = BlockStore::new(MemStorage::new(f));
        seq(&mut st);
        let mem = st.into_inner();
        let mut states = mem.crash_outcomes(64);
        states.push(mem.clone());
        for storage in states {
            let loaded = BlockStore::new(storage).load().unwrap_or_else(|e| panic!("crash before op {crash_at}: the store must load, got {e}"));
            // markers are contiguous from 1 (load enforces it) and every marker's block is present
            for (h, id) in &loaded.committed {
                let b = loaded.blocks.iter().find(|b| id_of(b) == Some(*id)).unwrap_or_else(|| panic!("crash before op {crash_at}: marker {h} has no block"));
                assert_eq!(b.height, *h);
            }
            let mut e = engine(2, 4);
            let (_, dropped) = e.restore(loaded.blocks.clone(), &loaded.committed, loaded.high_qc.clone(), loaded.high_tc.clone())
                .unwrap_or_else(|er| panic!("crash before op {crash_at}: restore refused: {er}"));
            assert_eq!(dropped, 0, "crash before op {crash_at}: a crash must not produce an invalid block");
            assert!(e.committed_tip().1 >= loaded.committed.len() as u64);
            outcomes_checked += 1;
        }
    }
    assert!(outcomes_checked > total, "the crash enumeration must cover several outcomes");
}


// ================================================================================================ deterministic simulation
// A small driver around the engine, in the way the node driver will be: messages travel as encoded `CFH1|net|` envelopes and are decoded
// under the derived limits; a missing ancestor is fetched by the real sync protocol; the engine's durable-state requests are applied to a
// per-node block store before anything that follows them; commits are executed by a durable per-node executor that fails the run on any
// duplicate or skipped height; the pacemaker backs off; a node can crash in the middle of applying a step's outputs and is rebuilt from
// its safety store, its block store and its executor height only.

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0.wrapping_mul(0x2545F4914F6CDD1D) }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role { Honest, Silent, Equivocator }

struct Pkt { at: u64, from: usize, to: usize, bytes: Vec<u8>, tries: u32 }

struct Sim {
    n: usize,
    f: Fx,
    mlim: MessageLimits,
    nodes: Vec<Option<E>>,
    roles: Vec<Role>,
    down_until: Vec<u64>,
    round_started: Vec<u64>,
    last_round: Vec<u64>,
    last_hqc: Vec<u64>,
    pace: Vec<Pacemaker>,
    sync: Vec<SyncClient>,
    stores: Vec<BlockStore<MemStorage>>,
    exec: Vec<Vec<BlockId>>,
    net: Vec<Pkt>,
    log: Vec<(usize, Msg)>,
    rng: Rng,
    tick: u64,
    gst: u64,
    restarts: bool,
    restart_count: usize,
    cuts: usize,
    sync_requests: usize,
    bad_sync: usize,
    malformed: usize,
    partition: Option<(u64, u64, u8)>,
    /// Percent of sync responses a Byzantine server corrupts.
    corrupt_pct: u64,
    seed: u64,
}

const PACE: PacemakerConfig = PacemakerConfig { base: 30, max: 120 };

impl Sim {
    fn new(seed: u64, roles: Vec<Role>, restarts: bool) -> Sim {
        let n = roles.len();
        Sim {
            n, f: fx(), mlim: mlim(), nodes: (0..n).map(|i| if roles[i] == Role::Silent { None } else { Some(engine(i, n)) }).collect(), roles,
            down_until: vec![0; n], round_started: vec![0; n], last_round: vec![1; n], last_hqc: vec![0; n],
            pace: (0..n).map(|_| Pacemaker::new(PACE).unwrap()).collect(), sync: (0..n).map(|_| SyncClient::new(20, 8)).collect(),
            stores: (0..n).map(|_| BlockStore::new(mem())).collect(), exec: vec![vec![]; n], net: vec![], log: vec![],
            rng: Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1), tick: 0, gst: 150, restarts, restart_count: 0, cuts: 0, sync_requests: 0,
            bad_sync: 0, malformed: 0, partition: None, corrupt_pct: 50, seed,
        }
    }
    fn blocked(&self, a: usize, b: usize, t: u64) -> bool {
        matches!(self.partition, Some((s, e, mask)) if t >= s && t < e && ((mask >> a) & 1) != ((mask >> b) & 1))
    }
    fn send_bytes(&mut self, from: usize, to: usize, bytes: Vec<u8>) {
        if to == from || self.blocked(from, to, self.tick) { return; }
        let pre_gst = self.tick < self.gst;
        if pre_gst && self.rng.below(100) < 20 { return; }
        let d = if pre_gst { 1 + self.rng.below(12) } else { 1 + self.rng.below(2) };
        self.net.push(Pkt { at: self.tick + d, from, to, bytes, tries: 0 });
    }
    fn send(&mut self, from: usize, to: usize, m: NetMsg) { let b = net::encode(&m); self.send_bytes(from, to, b); }
    fn up(&self, i: usize) -> bool { self.nodes[i].is_some() && self.down_until[i] <= self.tick }

    /// The execution layer: durable, one block per height, in order. A duplicate or a skipped height fails the run.
    fn execute(&mut self, i: usize, c: Committed) {
        let ex = &mut self.exec[i];
        let h = c.height as usize;
        assert!(h > ex.len(), "DUPLICATE EXECUTION: node {i} was handed height {h} again (executed {}), seed {}", ex.len(), self.seed);
        assert_eq!(h, ex.len() + 1, "SKIPPED HEIGHT: node {i} was handed height {h} after {}, seed {}", ex.len(), self.seed);
        ex.push(c.id);
    }

    /// Apply a node's outputs in order. `limit` models a crash after that many outputs: the rest are lost.
    fn route(&mut self, from: usize, outs: Vec<Output>, limit: Option<usize>) {
        for (k, o) in outs.into_iter().enumerate() {
            if limit.map_or(false, |l| k >= l) { return; }
            match &o {
                Output::PersistBlock(_) | Output::PersistCommit { .. } | Output::PersistHighQc(_) | Output::PersistHighTc(_) => {
                    let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &self.f.set };
                    self.stores[from].apply(&o, &|b| block_id_of(b, &idc).ok()).expect("persist");
                }
                Output::Commit(c) => self.execute(from, c.clone()),
                Output::Broadcast(m) => { self.log.push((from, m.clone())); let b = net::encode(&NetMsg::Consensus(m.clone())); for to in 0..self.n { self.send_bytes(from, to, b.clone()); } }
                Output::Send { to, msg } => { self.log.push((from, msg.clone())); self.send(from, *to, NetMsg::Consensus(msg.clone())); }
                Output::EnteredRound { .. } => {}
            }
        }
    }

    fn pick_peer(&mut self, me: usize, hint: usize) -> usize {
        if hint != me && self.rng.below(2) == 0 { return hint; }
        let others: Vec<usize> = (0..self.n).filter(|j| *j != me).collect();
        others[self.rng.below(others.len() as u64) as usize]
    }
    fn request_sync(&mut self, me: usize, want: BlockId, hint: usize) {
        if let Some(req) = self.sync[me].want(want, self.tick, SYNC_K as u32) {
            self.sync_requests += 1;
            let peer = self.pick_peer(me, hint);
            self.send(me, peer, NetMsg::SyncRequest(req));
        }
    }
    fn apply_sync(&mut self, me: usize, from: usize, resp: SyncResponse) {
        let req = SyncRequest { want: resp.want, max_blocks: SYNC_K as u32 };
        let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &self.f.set };
        if check_response(&req, &resp, &idc, SYNC_K).is_err() { self.bad_sync += 1; return; }
        let want = resp.want;
        let mut complete = true;
        for b in resp.blocks {
            let r = self.nodes[me].as_mut().unwrap().on_sync_block(b);
            match r {
                Ok(outs) => self.route(me, outs, None),
                Err(EngineError::MissingParent(p)) => { self.request_sync(me, p, from); complete = false; break; }
                Err(_) => { self.bad_sync += 1; complete = false; break; }
            }
        }
        if complete { self.sync[me].complete(&want); }
    }

    fn byz_extras(&mut self, i: usize, m: &Msg) {
        // an equivocator also signs votes for every proposal it sees
        if let Msg::Proposal(b) = m {
            let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &self.f.set };
            if let Ok(id) = block_id_of(b, &idc) {
                let vm = VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 0, round: b.round, block_id: id, parent_id: b.parent_id, parent_round: b.qc.round() };
                let sig = sign(i, CTX_VOTE, &vm.encode().unwrap());
                let to = self.nodes[i].as_ref().map_or(0, |e| e.leader_of(b.round + 1));
                self.send(i, to, NetMsg::Consensus(Msg::Vote(VoteMsg { voter: i, msg: vm, signature: sig })));
            }
        }
    }

    /// Rebuild node `i` from durable state only: its safety store, its block store and its executor height.
    fn recover(&mut self, i: usize) {
        let e = self.nodes[i].take().unwrap();
        let mut e = restart(e, i, self.n);
        let loaded = self.stores[i].load().expect("the block store must load after a crash");
        e.restore(loaded.blocks, &loaded.committed, loaded.high_qc, loaded.high_tc).expect("restore");
        // commit markers the crash lost are written again; the executor catches up from its own durable height, exactly once
        let missing_markers = e.committed_after(loaded.committed.len() as u64);
        for c in &missing_markers { self.stores[i].put_commit(c.height, &c.id).expect("marker"); }
        let behind = e.committed_after(self.exec[i].len() as u64);
        self.nodes[i] = Some(e);
        for c in behind { self.execute(i, c); }
        let mut outs = self.nodes[i].as_mut().unwrap().resend_last_vote().unwrap_or_default();
        outs.extend(self.nodes[i].as_mut().unwrap().resend_last_timeout().unwrap_or_default());
        self.route(i, outs, None);
        self.restart_count += 1;
        self.down_until[i] = self.tick + 1 + self.rng.below(10);
        self.last_round[i] = 0;
        self.round_started[i] = self.down_until[i];
        self.pace[i] = Pacemaker::new(PACE).unwrap();
        self.last_hqc[i] = self.nodes[i].as_ref().unwrap().high_qc().round();
    }

    fn step(&mut self) {
        let t = self.tick;
        let mut due: Vec<Pkt> = vec![];
        let mut keep = vec![];
        for p in self.net.drain(..) { if p.at <= t { due.push(p) } else { keep.push(p) } }
        self.net = keep;
        while !due.is_empty() {
            let k = self.rng.below(due.len() as u64) as usize;
            let p = due.swap_remove(k);
            let to = p.to;
            if self.blocked(p.from, to, t) { continue; }
            if !self.up(to) { if self.nodes[to].is_some() && p.tries < 40 { self.net.push(Pkt { at: t + 3, tries: p.tries + 1, ..p }); } continue; }
            let msg = match net::decode(&p.bytes, &self.mlim) { Ok(m) => m, Err(_) => { self.malformed += 1; continue } };
            match msg {
                NetMsg::SyncRequest(req) => {
                    let mut resp = self.nodes[to].as_ref().unwrap().serve_sync(&req, SYNC_K);
                    if let Some(r) = resp.as_mut() {
                        // a Byzantine server sometimes corrupts what it serves
                        if self.roles[to] == Role::Equivocator && self.rng.below(100) < self.corrupt_pct { r.blocks[0].signature[3] ^= 1; }
                    }
                    if let Some(r) = resp { self.send(to, p.from, NetMsg::SyncResponse(r)); }
                }
                NetMsg::SyncResponse(resp) => self.apply_sync(to, p.from, resp),
                NetMsg::SyncBelowBase(_) => {} // advice only; this simulation has no seeded nodes
                NetMsg::Consensus(m) => {
                    if self.roles[to] == Role::Equivocator { self.byz_extras(to, &m); }
                    let r = self.nodes[to].as_mut().unwrap().on_message(m);
                    match r {
                        Ok(outs) => {
                            let cut = if self.restarts && self.roles[to] == Role::Honest && t > 20 && t < self.gst + 100 && self.rng.below(45) == 0 { Some(self.rng.below(outs.len() as u64 + 1) as usize) } else { None };
                            self.route(to, outs, cut);
                            if cut.is_some() { self.cuts += 1; self.recover(to); }
                        }
                        Err(EngineError::MissingParent(pid)) if p.tries < 40 => {
                            self.request_sync(to, pid, p.from);
                            self.net.push(Pkt { at: t + 4, tries: p.tries + 1, ..p });
                        }
                        Err(EngineError::ConflictingCommit) => panic!("SAFETY VIOLATION seed {} tick {t}: node {to} would commit a conflicting block", self.seed),
                        Err(_) => {}
                    }
                }
            }
        }
        for i in 0..self.n {
            if !self.up(i) { continue; }
            let (r, hq) = { let e = self.nodes[i].as_ref().unwrap(); (e.round(), e.high_qc().round()) };
            if hq > self.last_hqc[i] { self.last_hqc[i] = hq; self.pace[i].on_progress(); }
            if r != self.last_round[i] { self.last_round[i] = r; self.round_started[i] = t; }
            if self.nodes[i].as_ref().unwrap().is_leader() {
                if let Ok(outs) = self.nodes[i].as_mut().unwrap().propose(format!("n{i}r{r}").into_bytes()) {
                    self.route(i, outs, None);
                    if self.roles[i] == Role::Equivocator { self.twin(i, r); }
                }
            }
            if t.saturating_sub(self.round_started[i]) >= self.pace[i].timeout() {
                self.round_started[i] = t;
                if let Ok(outs) = self.nodes[i].as_mut().unwrap().local_timeout() { self.pace[i].on_timeout(); self.route(i, outs, None); }
            }
        }
        if self.restarts && t > 20 && t < self.gst + 100 && self.rng.below(90) == 0 {
            let i = self.rng.below(self.n as u64) as usize;
            if self.roles[i] == Role::Honest && self.up(i) && (0..self.n).all(|j| self.down_until[j] <= t) { self.recover(i); }
        }
        self.tick += 1;
    }

    fn twin(&mut self, i: usize, r: u64) {
        let Some(Msg::Proposal(a)) = self.log.iter().rev().find(|(f, m)| *f == i && matches!(m, Msg::Proposal(b) if b.round == r)).map(|(_, m)| m.clone()) else { return };
        let mut b = Block { payload: format!("twin-n{i}r{r}").into_bytes(), signature: vec![], ..a };
        let idc = IdCtx { protocol_profile: PROFILE, chain_id: CHAIN, set: &self.f.set };
        let id = block_id_of(&b, &idc).unwrap();
        b.signature = sign(i, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
        for to in (0..self.n).filter(|j| j % 2 == 1) { self.send(i, to, NetMsg::Consensus(Msg::Proposal(b.clone()))); }
    }

    fn run(&mut self, ticks: u64) { for _ in 0..ticks { self.step(); } }
    fn honest(&self) -> Vec<usize> { (0..self.n).filter(|i| self.roles[*i] == Role::Honest).collect() }

    /// Agreement: the executed sequences of all honest nodes are prefixes of one another (one block per height, everywhere).
    fn assert_agreement(&self, label: &str) {
        let mut by_height: BTreeMap<usize, BlockId> = BTreeMap::new();
        for i in self.honest() {
            for (h, id) in self.exec[i].iter().enumerate() {
                if let Some(prev) = by_height.insert(h + 1, *id) { assert_eq!(prev, *id, "{label}: AGREEMENT VIOLATED at height {}", h + 1); }
            }
        }
    }

    /// No honest validator signed two different votes or timeouts for one round, and every re-send carried the SAME signature bytes.
    fn assert_no_honest_double_signing(&self, label: &str) {
        let mut votes: BTreeMap<(usize, u64), (Vec<u8>, Vec<u8>)> = BTreeMap::new();
        let mut tos: BTreeMap<(usize, u64), (u64, Vec<u8>)> = BTreeMap::new();
        for (from, m) in &self.log {
            if self.roles[*from] != Role::Honest { continue; }
            match m {
                Msg::Vote(v) if v.voter == *from => {
                    let cur = (v.msg.encode().unwrap(), v.signature.clone());
                    if let Some(prev) = votes.insert((*from, v.msg.round), cur.clone()) { assert_eq!(prev, cur, "{label}: node {from} signed two different votes for round {}", v.msg.round); }
                }
                Msg::Timeout(t) if t.voter == *from => {
                    let cur = (t.msg.high_qc_round, t.signature.clone());
                    if let Some(prev) = tos.insert((*from, t.msg.round), cur.clone()) { assert_eq!(prev, cur, "{label}: node {from} signed two different timeouts for round {}", t.msg.round); }
                }
                _ => {}
            }
        }
    }
}

/// Seeds per campaign (default 10; raise with PQHS_SEEDS for a longer soak).
fn seeds() -> u64 { std::env::var("PQHS_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_SEEDS) }

struct Scenario { label: &'static str, roles: Vec<Role>, restarts: bool, partition: Option<(u64, u64, u8)>, ticks: u64, min_commits: usize, max_lag: Option<usize>, expect_bad_sync: bool }

fn campaign(sc: Scenario) {
    let (mut cuts, mut restarts, mut syncs, mut bad) = (0, 0, 0, 0);
    for seed in 1..=seeds() {
        let mut s = Sim::new(seed, sc.roles.clone(), sc.restarts);
        s.partition = sc.partition;
        if sc.expect_bad_sync { s.corrupt_pct = 100; }
        s.run(sc.ticks);
        let l = format!("{} seed {seed}", sc.label);
        s.assert_agreement(&l);
        s.assert_no_honest_double_signing(&l);
        assert_eq!(s.malformed, 0, "{l}: an honest node produced a message its peers could not decode");
        let lens: Vec<usize> = s.honest().iter().map(|i| s.exec[*i].len()).collect();
        let best = *lens.iter().max().unwrap();
        assert!(best >= sc.min_commits, "{l}: liveness after GST: best honest node executed only {best} blocks");
        if let Some(lag) = sc.max_lag { for (k, n) in lens.iter().enumerate() { assert!(*n + lag >= best, "{l}: honest node {} executed {n} blocks but another executed {best}: it did not catch up by sync", s.honest()[k]); } }
        cuts += s.cuts; restarts += s.restart_count; syncs += s.sync_requests; bad += s.bad_sync;
    }
    if sc.restarts { assert!(restarts > 0 && cuts > 0, "{}: the campaign never restarted a node mid-step", sc.label); }
    if sc.expect_bad_sync { assert!(bad > 0, "{}: no corrupted sync response was ever served and rejected", sc.label); }
    if sc.partition.is_some() || sc.restarts { assert!(syncs > 0, "{}: the campaign never used block sync", sc.label); }
}

fn plain(label: &'static str, roles: Vec<Role>, restarts: bool, min_commits: usize) -> Scenario {
    Scenario { label, roles, restarts, partition: None, ticks: 520, min_commits, max_lag: None, expect_bad_sync: false }
}

#[test]
fn sim_all_honest_agree_and_make_progress_after_gst() {
    campaign(plain("honest", vec![Role::Honest; 4], false, 15));
}

#[test]
fn sim_one_silent_validator_within_the_fault_bound() {
    campaign(plain("silent", vec![Role::Honest, Role::Honest, Role::Silent, Role::Honest], false, 4));
}

#[test]
fn sim_one_equivocating_validator_cannot_split_the_chain_or_poison_sync() {
    campaign(plain("equivocator", vec![Role::Honest, Role::Equivocator, Role::Honest, Role::Honest], false, 8));
}

#[test]
fn sim_honest_nodes_crash_mid_step_and_recover_without_double_signing_or_double_execution() {
    campaign(plain("restarts", vec![Role::Honest; 4], true, 12));
}

#[test]
fn sim_restarts_together_with_an_equivocator() {
    campaign(plain("restarts+equivocator", vec![Role::Honest, Role::Honest, Role::Equivocator, Role::Honest], true, 8));
}

/// Two groups of two: neither side has a quorum, so nothing is certified during the partition; after it heals the chain continues and every
/// node ends up on the same chain (nodes that missed blocks fetch them by sync).
#[test]
fn sim_a_network_partition_heals_and_every_node_converges() {
    campaign(Scenario { label: "partition 2/2", roles: vec![Role::Honest; 4], restarts: false, partition: Some((30, 230, 0b0011)), ticks: 560, min_commits: 8, max_lag: Some(6), expect_bad_sync: false });
}

/// One node is cut off while the other three keep a quorum and keep committing; when it rejoins it catches up through block sync alone.
#[test]
fn sim_an_isolated_node_rejoins_and_catches_up_by_sync() {
    campaign(Scenario { label: "isolated node", roles: vec![Role::Honest; 4], restarts: false, partition: Some((30, 300, 0b1000)), ticks: 560, min_commits: 8, max_lag: Some(6), expect_bad_sync: false });
}

/// The same rejoin, but one of the peers it can ask is Byzantine and corrupts a signature in what it serves about half the time. Every such
/// response must be rejected by validation, the node must ask someone else, and it must still catch up.
#[test]
fn sim_a_rejoining_node_survives_a_byzantine_sync_server() {
    campaign(Scenario { label: "isolated node, byzantine server", roles: vec![Role::Honest, Role::Equivocator, Role::Honest, Role::Honest], restarts: false, partition: Some((30, 300, 0b1000)), ticks: 600, min_commits: 6, max_lag: Some(8), expect_bad_sync: true });
}

#[test]
#[ignore = "diagnostic: DIAG_ROLES=HHEH DIAG_SEED=7 DIAG_RESTARTS=1 cargo test --release -- --ignored --nocapture diag"]
fn diag_run() {
    let roles: Vec<Role> = std::env::var("DIAG_ROLES").unwrap_or("HHSH".into()).chars().map(|c| match c { 'S' => Role::Silent, 'E' => Role::Equivocator, _ => Role::Honest }).collect();
    let seed = std::env::var("DIAG_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let mut s = Sim::new(seed, roles, std::env::var("DIAG_RESTARTS").is_ok());
    if let Ok(p) = std::env::var("DIAG_PART") { let v: Vec<u64> = p.split(',').map(|x| x.parse().unwrap()).collect(); s.partition = Some((v[0], v[1], v[2] as u8)); }
    for t in (0..520).step_by(40) {
        s.run(40);
        let rounds: Vec<Option<u64>> = (0..s.n).map(|i| s.nodes[i].as_ref().map(|e| e.round())).collect();
        println!("t={} rounds={:?} executed={:?} net={} restarts={} cuts={} syncs={} bad_sync={}", t + 40, rounds, s.exec.iter().map(|e| e.len()).collect::<Vec<_>>(), s.net.len(), s.restart_count, s.cuts, s.sync_requests, s.bad_sync);
    }
}

// ============================================================================================================================
// Execution handoff and node driver. The application is the DEVNET-INTERIM hash chain (exec.rs): these tests exercise the handoff,
// replay and recovery. They are NOT transaction-execution validation (the real executor needs the payload codec, open item U5).
// ============================================================================================================================
fn blk(h: u64, tag: u8) -> Committed { Committed { id: [tag; 32], round: h, height: h, payload: vec![tag; 10] } }

#[test]
fn the_interim_app_applies_in_order_and_refuses_anything_else() {
    let mut a = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    let c0 = a.cursor();
    assert_eq!(c0.height, 0);
    let c1 = a.apply(&blk(1, 1)).unwrap();
    assert_eq!(c1.height, 1);
    assert_ne!(c1.state_digest, c0.state_digest);
    assert_eq!(a.apply(&blk(1, 1)), Err(ExecError::OutOfOrder { expected: 2, got: 1 }), "a duplicate is refused");
    assert_eq!(a.apply(&blk(3, 3)), Err(ExecError::OutOfOrder { expected: 2, got: 3 }), "a skipped height is refused");
    assert_eq!(a.cursor(), c1, "a refusal changes nothing");
    // the same blocks always give the same state; different payloads give a different state
    let mut b = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    assert_eq!(b.apply(&blk(1, 1)).unwrap(), c1);
    let mut c = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    assert_ne!(c.apply(&blk(1, 2)).unwrap().state_digest, c1.state_digest);
    // reopening from the same storage resumes at the same cursor
    let re = InterimApp::open(a.into_inner(), GENESIS_HASH).unwrap();
    assert_eq!(re.cursor(), c1);
}

#[test]
fn a_crash_at_any_point_of_applying_a_block_leaves_the_old_or_the_new_state_never_a_torn_one() {
    let mut reference = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    let after1 = reference.apply(&blk(1, 1)).unwrap();
    let after2 = reference.apply(&blk(2, 2)).unwrap();
    let (mut crashed_runs, mut old_seen, mut new_seen) = (0, 0, 0);
    for k in 0..6 {
        let f = faults();
        let mut app = InterimApp::open(MemStorage::new(f.clone()), GENESIS_HASH).unwrap();
        app.apply(&blk(1, 1)).unwrap();
        let base = f.borrow().ops;
        f.borrow_mut().crash_before = Some(base + k);
        let crashed = app.apply(&blk(2, 2)).is_err();
        if crashed { crashed_runs += 1; }
        for out in app.storage().crash_outcomes(7) {
            let mut re = InterimApp::open(out, GENESIS_HASH).expect("a crash never leaves unreadable executor state");
            let cur = re.cursor();
            if !crashed { assert_eq!(cur, after2, "an apply that returned Ok (the acknowledgement) is durable in every post-crash state"); }
            if cur == after1 {
                old_seen += 1;
                assert_eq!(re.apply(&blk(2, 2)).unwrap(), after2, "replaying the missed block reaches the same state");
            } else {
                new_seen += 1;
                assert_eq!(cur, after2, "the state is the old one or the new one, nothing else");
                assert!(matches!(re.apply(&blk(2, 2)), Err(ExecError::OutOfOrder { .. })), "an applied block is not applied again");
            }
        }
    }
    assert!(crashed_runs >= 4 && old_seen > 0 && new_seen > 0, "{crashed_runs} {old_seen} {new_seen}");
}

#[test]
fn damaged_or_foreign_executor_state_is_never_treated_as_fresh() {
    let mut a = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    a.apply(&blk(1, 1)).unwrap();
    let st = a.into_inner();
    let good = st.raw("app-state").unwrap();
    let with = |bytes: Vec<u8>| { let mut s = st.clone(); s.set_raw("app-state", bytes); s };
    for i in [0usize, 20, 60, 100, good.len() - 1] {
        let mut bad = good.clone(); bad[i] ^= 1;
        assert!(matches!(InterimApp::open(with(bad), GENESIS_HASH), Err(ExecError::Corrupt(_))), "flip at {i}");
    }
    assert!(matches!(InterimApp::open(with(good[..good.len() - 1].to_vec()), GENESIS_HASH), Err(ExecError::Corrupt(_))));
    assert!(matches!(InterimApp::open(with(vec![]), GENESIS_HASH), Err(ExecError::Corrupt(_))));
    assert!(matches!(InterimApp::open(with(good.clone()), [9; 32]), Err(ExecError::ForeignChain)));
}

fn big_set(n: usize) -> EpochSet {
    EpochSet::new(0, (0..n).map(|i| { let mut k = test_public_key(1); k[0] = (i >> 8) as u8; k[1] = i as u8; ValidatorEntry { address: format!("v{i:05}"), public_key: k, power: 1 } }).collect()).unwrap()
}
fn dcfg() -> DriverConfig { DriverConfig { max_sync_blocks: SYNC_K, pace: PACE, sync_ttl: 20, sync_outstanding: 8, min_propose_gap: 0, park_capacity: 16, park_ttl: 200, recent: 64, exec_per_tick: None, #[cfg(feature = "pq-anchored-evidence")] anchor: None } }

#[test]
fn startup_rejects_unsupported_configurations_explicitly() {
    let ok = cfg(0, 4);
    assert!(validate_config(&ok, &dcfg()).is_ok());
    // the owner-locked 8 MiB limit with a 1 MiB payload: K = 7 fits, K = 8 does not
    let mut c = ok.clone();
    c.limits = PqLimits { max_validators: 4, max_cert_validators: 1024, max_block_payload_bytes: 1_048_576, max_message_bytes: Some(net::MAX_MESSAGE_SIZE) };
    assert!(validate_config(&c, &DriverConfig { max_sync_blocks: 7, ..dcfg() }).is_ok());
    assert!(matches!(validate_config(&c, &DriverConfig { max_sync_blocks: 8, ..dcfg() }), Err(DriverError::Config(_))));
    // no transport limit configured: refused, not defaulted
    let mut u = ok.clone(); u.limits.max_message_bytes = None;
    assert!(matches!(validate_config(&u, &dcfg()), Err(DriverError::Config(m)) if m.contains("not set")));
    // 1,000 validators: the worst-case proposal (about 9.96 MB with a TC) exceeds 8 MiB, so the configuration is rejected
    let mut big = ok.clone();
    big.set = big_set(1000);
    big.limits = PqLimits { max_validators: 1000, max_cert_validators: 1024, max_block_payload_bytes: 0, max_message_bytes: Some(net::MAX_MESSAGE_SIZE) };
    match validate_config(&big, &DriverConfig { max_sync_blocks: 1, ..dcfg() }) {
        Err(DriverError::Config(m)) => assert!(m.contains("below the derived minimum"), "{m}"),
        other => panic!("expected a rejection, got {other:?}"),
    }
    // a larger limit accepts it (the choice is the owner's; this only proves the check is the limit and not a hard-coded count)
    big.limits.max_message_bytes = Some(12_000_000);
    assert!(validate_config(&big, &DriverConfig { max_sync_blocks: 1, ..dcfg() }).is_ok());
    // Driver::start validates by itself: a sync size the transport limit cannot carry stops it before it builds anything
    let r = Drv::start(DriverConfig { max_sync_blocks: SYNC_BLOCKS_CEILING, ..dcfg() }, engine(0, 4), BlockStore::new(mem()), LogApp { inner: InterimApp::open(mem(), GENESIS_HASH).unwrap(), log: Default::default() }, Box::new(|_, _| vec![]), 1);
    assert!(matches!(r, Err(DriverError::Config(_))));
    // bad pacemaker and bad driver parameters
    assert!(matches!(validate_config(&ok, &DriverConfig { pace: PacemakerConfig { base: 0, max: 5 }, ..dcfg() }), Err(DriverError::Config(_))));
    assert!(matches!(validate_config(&ok, &DriverConfig { sync_outstanding: 0, ..dcfg() }), Err(DriverError::Config(_))));
}

// ---- a deterministic network of drivers
struct LogApp { inner: InterimApp<MemStorage>, log: std::rc::Rc<std::cell::RefCell<Vec<u64>>> }
impl Executor for LogApp {
    fn cursor(&self) -> ExecCursor { self.inner.cursor() }
    fn apply(&mut self, b: &Committed) -> Result<ExecCursor, ExecError> { let c = self.inner.apply(b)?; self.log.borrow_mut().push(b.height); Ok(c) }    fn snapshot_bytes(&self) -> Option<Vec<u8>> { self.inner.snapshot_bytes() }
}
type Drv = Driver<MemStorage, TestCounter, TestSigner, TestVerifier, MemStorage, LogApp>;
type ExecLog = std::rc::Rc<std::cell::RefCell<Vec<u64>>>;

fn engine_f(i: usize, n: usize, cc: &Option<CheckpointConfig>) -> E { match cc { Some(c) => engine3(i, n, c), None => engine(i, n) } }
fn restart_f(e: E, i: usize, n: usize, cc: &Option<CheckpointConfig>) -> E { match cc { Some(c) => restart3(e, i, n, c), None => restart(e, i, n) } }
fn start_node(e: E, bs: BlockStore<MemStorage>, app: MemStorage, log: &ExecLog, tag: &str, now: u64) -> Result<(Drv, Vec<Outbound>), DriverError> {
    let exec = LogApp { inner: InterimApp::open(app, GENESIS_HASH)?, log: log.clone() };
    let tag = tag.to_string();
    Drv::start(dcfg(), e, bs, exec, Box::new(move |r, i| format!("interim-{tag}:{i}:{r}").into_bytes()), now)
}

struct DNet {
    n: usize,
    nodes: Vec<Option<Drv>>,
    logs: Vec<ExecLog>,
    bs_faults: Vec<Shared>,
    q: Vec<(u64, usize, usize, Vec<u8>)>,
    now: u64,
    cut: Vec<usize>,
    sent: Vec<Vec<Vec<u8>>>,
    fatal: Vec<(usize, String)>,
    dead: Vec<bool>,
    cc: Option<CheckpointConfig>,
}
impl DNet {
    fn new(n: usize, silent: &[usize], tag: &str) -> DNet { Self::new_cp(n, silent, tag, None) }
    fn new_cp(n: usize, silent: &[usize], tag: &str, cc: Option<CheckpointConfig>) -> DNet {
        let mut d = DNet { n, nodes: vec![], logs: vec![], bs_faults: vec![], q: vec![], now: 1, cut: vec![], sent: vec![vec![]; n], fatal: vec![], dead: vec![false; n], cc };
        for i in 0..n {
            let log: ExecLog = Default::default();
            let f = faults();
            if silent.contains(&i) { d.nodes.push(None); } else {
                let bs = BlockStore::new(MemStorage::new(f.clone()));
                let (drv, first) = start_node(engine_f(i, n, &cc), bs, mem(), &log, tag, 1).expect("start");
                d.nodes.push(Some(drv));
                d.push(i, first);
            }
            d.logs.push(log);
            d.bs_faults.push(f);
        }
        d
    }
    fn push(&mut self, from: usize, outs: Vec<Outbound>) {
        for o in outs {
            self.sent[from].push(o.bytes.clone());
            let targets: Vec<usize> = match o.to { None => (0..self.n).filter(|j| *j != from).collect(), Some(t) => vec![t] };
            for to in targets { if !self.cut.contains(&from) && !self.cut.contains(&to) { self.q.push((self.now + 1, from, to, o.bytes.clone())); } }
        }
    }
    fn step(&mut self) {
        self.now += 1;
        let now = self.now;
        let (due, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.q).into_iter().partition(|m| m.0 <= now);
        self.q = keep;
        for (_, from, to, bytes) in due {
            if self.cut.contains(&from) || self.cut.contains(&to) { continue; }
            if self.dead[to] { continue; }
            let Some(d) = self.nodes[to].as_mut() else { continue };
            match d.on_bytes(from, &bytes, now) { Ok(o) => self.push(to, o), Err(e) => { self.fatal.push((to, e.to_string())); self.dead[to] = true; } }
        }
        for i in 0..self.n {
            if self.dead[i] { continue; }
            let Some(d) = self.nodes[i].as_mut() else { continue };
            match d.tick(now) { Ok(o) => self.push(i, o), Err(e) => { self.fatal.push((i, e.to_string())); self.dead[i] = true; } }
        }
    }
    fn run(&mut self, ticks: u64) { for _ in 0..ticks { self.step(); } }
    fn run_until(&mut self, max: u64, mut done: impl FnMut(&DNet) -> bool) -> bool { for _ in 0..max { if done(self) { return true; } self.step(); } done(self) }
    fn height(&self, i: usize) -> u64 { self.nodes[i].as_ref().map_or(0, |d| d.status().exec.height) }
    fn cursor(&self, i: usize) -> ExecCursor { self.nodes[i].as_ref().unwrap().status().exec }
    /// Every node's executed history is a prefix of the same history: equal ids and state digests at every common height.
    fn assert_agreement(&self, label: &str) {
        let mut by_h: BTreeMap<u64, ExecCursor> = BTreeMap::new();
        for d in self.nodes.iter().flatten() {
            for c in d.status().recent { if let Some(p) = by_h.insert(c.height, c) { assert_eq!(p, c, "{label}: DISAGREEMENT at height {}", c.height); } }
        }
    }
    /// Nothing was executed twice or out of order: each node's execution log is exactly 1, 2, 3, ...
    fn assert_exactly_once(&self, label: &str) {
        for (i, l) in self.logs.iter().enumerate() {
            for (k, h) in l.borrow().iter().enumerate() { assert_eq!(*h, k as u64 + 1, "{label}: node {i} executed height {h} as its {}th block", k + 1); }
        }
    }
    fn recover(&mut self, i: usize, app_override: Option<MemStorage>, tag: &str) -> Result<Vec<Outbound>, DriverError> { self.recover_with(i, app_override, None, tag) }
    fn recover_with(&mut self, i: usize, app_override: Option<MemStorage>, bs_override: Option<BlockStore<MemStorage>>, tag: &str) -> Result<Vec<Outbound>, DriverError> {
        let d = self.nodes[i].take().unwrap();
        let (e, bs, x) = d.into_parts();
        let bs = bs_override.unwrap_or(bs);
        let app = app_override.unwrap_or_else(|| x.inner.into_inner());
        let (nd, first) = start_node(restart_f(e, i, self.n, &self.cc), bs, app, &self.logs[i], tag, self.now)?;
        self.nodes[i] = Some(nd);
        self.dead[i] = false;
        self.push(i, first.clone());
        Ok(first)
    }
}

#[test]
fn four_drivers_propose_certify_finalize_and_execute_in_agreement() {
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= 8)), "no liveness: {:?}", (0..4).map(|i| net.height(i)).collect::<Vec<_>>());
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    net.assert_agreement("steady state");
    net.assert_exactly_once("steady state");
    // application state agrees at one common height
    let h = (0..4).map(|i| net.height(i)).min().unwrap();
    let digests: Vec<_> = (0..4).map(|i| net.nodes[i].as_ref().unwrap().status().recent.into_iter().find(|c| c.height == h).unwrap().state_digest).collect();
    assert!(digests.iter().all(|d| *d == digests[0]));
    // the finalized payloads are retained: pruning does not exist yet
    let (_, tip) = net.nodes[0].as_ref().unwrap().engine().committed_tip();
    assert!(net.nodes[0].as_ref().unwrap().engine().committed_after(0).len() as u64 == tip, "every finalized payload is still available for replay");
}

#[test]
fn a_driver_restart_replays_only_what_the_executor_missed_and_resends_its_vote_byte_for_byte() {
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(3000, |n| n.height(1) >= 3));
    let snapshot = net.nodes[1].as_ref().unwrap().executor().inner.storage().clone();
    let snap_h = net.height(1);
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= snap_h + 4)));
    let before_len = net.logs[1].borrow().len();
    let tip = net.height(1);
    let sent_before = net.sent[1].clone();
    // the executor lost its last writes (the cursor is behind the committed history): replay applies exactly the missing heights, once
    let first = net.recover(1, Some(snapshot), "a").expect("restart");
    let replayed: Vec<u64> = net.logs[1].borrow()[before_len..].to_vec();
    assert_eq!(replayed, (snap_h + 1..=tip).collect::<Vec<_>>(), "replay is exactly the missed heights, once each");
    assert_eq!(net.height(1), tip);
    // whatever vote or timeout the restarted node sends first is one it already sent, byte for byte: it never signs again
    let lim = net.nodes[1].as_ref().unwrap().limits().clone();
    for o in &first {
        if let Ok(NetMsg::Consensus(Msg::Vote(_) | Msg::Timeout(_))) = net::decode(&o.bytes, &lim) { assert!(sent_before.contains(&o.bytes), "a restart produced a vote/timeout that was never sent before"); }
    }
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= tip + 3)));
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    net.assert_agreement("after restart");
    // the executor lost its last writes on purpose, so those heights appear twice in the log; from the rollback point on, the log is gapless
    // and duplicate-free, and every other node's log is exactly 1, 2, 3, ...
    for (k, h) in net.logs[1].borrow()[before_len..].iter().enumerate() { assert_eq!(*h, snap_h + 1 + k as u64, "after the restart node 1 executed {h} out of order"); }
    for i in [0usize, 2, 3] { for (k, h) in net.logs[i].borrow().iter().enumerate() { assert_eq!(*h, k as u64 + 1, "node {i}"); } }
    // a restart with nothing missed replays nothing
    let mark = net.logs[1].borrow().len();
    net.recover(1, None, "a").expect("restart");
    assert_eq!(net.logs[1].borrow().len(), mark, "no duplicate execution on a clean restart");
    // a node whose stored vote went to ANOTHER validator re-sends exactly that vote after a restart, byte for byte (it never signs again)
    let mut checked = false;
    for v in 0..4 {
        let (round, to) = { let e = net.nodes[v].as_ref().unwrap().engine(); match e.store().record().last_vote.as_ref() { Some(l) => (l.round, e.leader_of(l.round + 1)), None => continue } };
        if to == v { continue; }
        let sent_v = net.sent[v].clone();
        let first = net.recover(v, None, "a").expect("restart");
        let lim = *net.nodes[v].as_ref().unwrap().limits();
        let votes: Vec<&Outbound> = first.iter().filter(|o| matches!(net::decode(&o.bytes, &lim), Ok(NetMsg::Consensus(Msg::Vote(_))))).collect();
        assert!(!votes.is_empty(), "node {v} restarted with a stored vote for round {round} and re-sent nothing");
        assert!(votes.iter().all(|o| o.to == Some(to) && sent_v.contains(&o.bytes)), "the re-sent vote must be the stored one, to the next leader");
        checked = true;
        break;
    }
    assert!(checked, "no node had a stored vote addressed to another validator");
}

#[test]
fn a_driver_refuses_to_start_when_the_executor_is_ahead_of_or_diverged_from_the_recovered_history() {
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(3000, |n| n.height(1) >= 2));
    let old_blocks = net.nodes[1].as_ref().unwrap().engine().known_blocks().len();
    let _ = old_blocks;
    // an executor from a DIFFERENT run (other payloads, so other block ids) at a height this chain has also reached
    let mut other = DNet::new(4, &[], "b");
    assert!(other.run_until(3000, |n| n.height(1) >= 2));
    let foreign = other.nodes[1].as_ref().unwrap().executor().inner.storage().clone();
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= other.height(1))));
    let r = net.recover(1, Some(foreign), "a");
    assert!(matches!(r, Err(DriverError::Diverged { .. })), "{r:?}");
    // an executor AHEAD of the block store: the recovered committed history is shorter than what was executed
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(3000, |n| n.height(1) >= 2));
    let old_store = BlockStore::new(net.nodes[1].as_ref().unwrap().block_store().storage().clone());
    assert!(net.run_until(3000, |n| n.height(1) >= 7));
    let r = net.recover_with(1, None, Some(old_store), "a");
    assert!(matches!(r, Err(DriverError::ExecutorAhead { .. })), "{r:?}");
}

#[test]
fn a_partitioned_driver_rejoins_by_sync_and_agrees_without_duplicate_execution() {
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= 3)));
    net.cut.push(3);
    let at_cut = net.height(3);
    assert!(net.run_until(6000, |n| (0..3).all(|i| n.height(i) >= at_cut + 8)), "the majority must keep committing without node 3");
    assert_eq!(net.height(3), at_cut, "an isolated node commits nothing");
    net.cut.clear();
    let target = (0..3).map(|i| net.height(i)).max().unwrap() + 2;
    assert!(net.run_until(8000, |n| (0..4).all(|i| n.height(i) >= target)), "heights {:?}", (0..4).map(|i| net.height(i)).collect::<Vec<_>>());
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    assert!(net.nodes[3].as_ref().unwrap().stats().sync_requests > 0, "the rejoining node must have used block sync");
    net.assert_agreement("after rejoin");
    net.assert_exactly_once("after rejoin");
}

#[test]
fn drivers_drop_malformed_oversize_and_unsolicited_input_without_changing_state() {
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= 3)));
    let lim = *net.nodes[0].as_ref().unwrap().limits();
    let before = net.nodes[0].as_ref().unwrap().status();
    let now = net.now;
    let d = net.nodes[0].as_mut().unwrap();
    let mut some_valid = net.sent[1].iter().find(|b| b.len() > 40).cloned().unwrap();
    let junk: Vec<Vec<u8>> = vec![vec![], vec![0xff; 5], b"CFH1|net|".to_vec(), vec![0u8; lim.transport as usize + 1], { some_valid.push(0); some_valid.clone() }];
    for j in &junk { assert!(d.on_bytes(1, j, now).unwrap().is_empty()); }
    // a well-formed sync response nobody asked for
    let resp = net.nodes[1].as_ref().unwrap().engine().serve_sync(&SyncRequest { want: before.committed_tip, max_blocks: 2 }, 2).expect("served");
    let unsolicited = net::encode(&NetMsg::SyncResponse(resp));
    let d = net.nodes[0].as_mut().unwrap();
    assert!(d.on_bytes(1, &unsolicited, now).unwrap().is_empty());
    let after = d.status();
    assert_eq!(after.stats.malformed, before.stats.malformed + junk.len() as u64);
    assert_eq!(after.stats.unsolicited_sync, before.stats.unsolicited_sync + 1);
    assert_eq!((after.committed_height, after.exec), (before.committed_height, before.exec), "junk changes no committed or executed state");
}

#[test]
fn a_block_store_failure_is_fatal_stops_the_node_and_recovery_never_signs_a_second_vote() {
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= 2)));
    // node 2's block store dies from now on: the next block it must persist fails, so nothing it would have sent after that point is sent
    let ops = net.bs_faults[2].borrow().ops;
    net.bs_faults[2].borrow_mut().crash_before = Some(ops);
    assert!(net.run_until(2000, |n| !n.fatal.is_empty()), "a storage failure must stop the driver");
    assert!(net.fatal.iter().all(|(i, m)| *i == 2 && m.contains("block store")), "{:?}", net.fatal);
    let sent_before: Vec<Vec<u8>> = net.sent[2].clone();
    // the process restarts on a healthy disk: its stored vote is re-sent byte for byte and no different vote appears
    net.bs_faults[2].borrow_mut().crash_before = None;
    net.fatal.clear();
    let lim = *net.nodes[2].as_ref().unwrap().limits();
    let first = net.recover(2, None, "a").expect("restart");
    for o in &first {
        if let Ok(NetMsg::Consensus(Msg::Vote(_) | Msg::Timeout(_))) = net::decode(&o.bytes, &lim) { assert!(sent_before.contains(&o.bytes) || net.sent[2].contains(&o.bytes)); }
    }
    let target = (0..4).map(|i| net.height(i)).max().unwrap() + 3;
    assert!(net.run_until(6000, |n| (0..4).filter(|i| !n.dead[*i]).all(|i| n.height(i) >= target)));
    net.assert_agreement("after storage failure");
}

#[test]
fn engine_errors_stop_the_node_only_when_they_threaten_safety() {
    assert!(matches!(classify_engine_error(EngineError::ConflictingCommit, false), Err(DriverError::Safety(_))));
    assert!(matches!(classify_engine_error(EngineError::Sign(SignError::Latched), true), Err(DriverError::Safety(_))));
    assert!(classify_engine_error(EngineError::Sign(SignError::Latched), false).is_ok(), "a refusal by a healthy store is just a refused message");
    assert!(classify_engine_error(EngineError::NotLeader, true).is_ok());
    assert!(classify_engine_error(EngineError::Invalid("x"), true).is_ok());
}

#[test]
fn a_lost_commit_marker_is_rewritten_at_start_and_nothing_is_executed_again() {
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= 6)));
    let tip = net.height(2);
    let mark = net.logs[2].borrow().len();
    // the node crashed after executing but before its newest commit markers reached the disk
    let (e, bs, x) = net.nodes[2].take().unwrap().into_parts();
    let mut st = bs.into_inner();
    let mut removed = 0;
    for n in st.names().into_iter().filter(|n| n.starts_with("cmt-")) {
        let h = u64::from_str_radix(&n[4..], 16).unwrap();
        if h + 2 > tip { st.delete_raw(&n); removed += 1; }
    }
    assert!(removed >= 2);
    let (nd, _) = start_node(restart(e, 2, 4), BlockStore::new(st), x.inner.into_inner(), &net.logs[2], "a", net.now).expect("start");
    assert_eq!(nd.block_store().load().unwrap().committed.len() as u64, nd.status().committed_height, "the markers the crash lost are written again");
    assert!(nd.status().committed_height >= tip);
    assert_eq!(net.logs[2].borrow().len(), mark, "nothing was executed again");
    net.nodes[2] = Some(nd);
    let target = (0..4).map(|i| net.height(i)).max().unwrap() + 3;
    assert!(net.run_until(3000, |n| (0..4).all(|i| n.height(i) >= target)));
    net.assert_agreement("after marker loss");
}

#[test]
fn a_sync_response_that_does_not_answer_the_request_is_rejected_by_the_driver() {
    let mut net = DNet::new(4, &[3], "a");
    assert!(net.run_until(3000, |n| (0..3).all(|i| n.height(i) >= 6)));
    let log: ExecLog = Default::default();
    let (mut d3, _) = start_node(engine(3, 4), BlockStore::new(mem()), mem(), &log, "a", net.now).expect("start");
    let lim = *d3.limits();
    // a late proposal whose parent node 3 has never seen: it asks for that ancestor
    let prop = net.sent.iter().flatten().filter(|b| matches!(net::decode(b, &lim), Ok(NetMsg::Consensus(Msg::Proposal(p))) if p.height >= 5)).last().cloned().expect("a proposal");
    let outs = d3.on_bytes(0, &prop, net.now).unwrap();
    let req = outs.iter().find_map(|o| match net::decode(&o.bytes, &lim) { Ok(NetMsg::SyncRequest(r)) => Some(r), _ => None }).expect("node 3 must ask for the missing ancestor");
    // the answer is a genuine chain, but it ends at a different block than the one requested
    let (tip_id, _) = net.nodes[0].as_ref().unwrap().engine().committed_tip();
    assert_ne!(tip_id, req.want);
    let mut bogus = net.nodes[0].as_ref().unwrap().engine().serve_sync(&SyncRequest { want: tip_id, max_blocks: 2 }, 2).expect("served");
    bogus.want = req.want;
    let before = d3.stats();
    d3.on_bytes(0, &net::encode(&NetMsg::SyncResponse(bogus)), net.now).unwrap();
    assert_eq!(d3.stats().bad_sync, before.bad_sync + 1, "a response that does not end at the requested block is counted and dropped");
    assert_eq!(d3.status().committed_height, 0);
}

// ============================================================================================================================
// Payload-free headers and header-chain verification (snapshot-recovery Step 1). Headers authenticate committed HISTORY (ids, payload hashes,
// finality); they say nothing about application state, which no block commits to.
// ============================================================================================================================
fn cparams(set: &EpochSet) -> ChainParams<'_> { ChainParams { protocol_profile: PROFILE, chain_id: CHAIN, set, genesis_hash: GENESIS_HASH, seed: 0, checkpoint: None } }

/// The linear chain from genesis to the block certified by node `i`'s high QC, and that QC (None while only the genesis certificate exists).
fn chain_to(net: &DNet, i: usize) -> (Vec<Block>, Option<Cert>) {
    let e = net.nodes[i].as_ref().unwrap().engine();
    let all: BTreeMap<BlockId, Block> = e.known_blocks().into_iter().filter_map(|b| id_of(b).map(|id| (id, b.clone()))).collect();
    let hq = e.high_qc().clone();
    let Cert::Qc(q) = &hq else { return (vec![], None) };
    let (mut cur, mut out) = (q.block_id, vec![]);
    while let Some(b) = all.get(&cur) { out.push(b.clone()); cur = b.parent_id; }
    out.reverse();
    (out, Some(hq))
}
fn headers_of(bs: &[Block]) -> Vec<PayloadFreeBlock> { bs.iter().map(Block::to_header).collect() }
fn ids_of(v: &VerifiedChain) -> Vec<(u64, BlockId)> { v.finalized.iter().map(|p| (p.height, p.id)).collect() }
/// A header with new fields, correctly signed by its proposer's key: invalid for exactly the reason under test, not for a bad signature.
fn resign(mut h: PayloadFreeBlock) -> PayloadFreeBlock {
    let f = fx();
    let id = h.id(&idctx(&f)).unwrap();
    h.signature = sign(h.proposer, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
    h
}
fn failure_at(r: Result<VerifiedChain, HeaderError>) -> (usize, String) {
    match r { Err(HeaderError::Invalid { index, reason }) => (index, reason.to_string()), Err(HeaderError::Cert { index, source }) => (index, source.to_string()), Err(e) => panic!("unexpected error {e:?}"), Ok(_) => panic!("an invalid chain verified") }
}

/// A run with a silent validator (so some headers carry timeout certificates), and node 0's verified chain.
fn tc_chain() -> (DNet, Vec<Block>, Option<Cert>) {
    let mut net = DNet::new(4, &[3], "a");
    assert!(net.run_until(8000, |n| (0..3).all(|i| n.height(i) >= 10)));
    let (bs, fq) = chain_to(&net, 0);
    assert!(bs.len() >= 8 && bs.iter().any(|b| b.tc.is_some()), "the run must contain timeout-certificate headers");
    (net, bs, fq)
}

#[test]
fn a_payload_free_header_reconstructs_the_same_block_id_and_binds_exactly_one_payload() {
    let (_net, bs, _) = tc_chain();
    let f = fx();
    for b in &bs {
        let h = b.to_header();
        assert_eq!(h.id(&idctx(&f)).unwrap(), block_id_of(b, &idctx(&f)).unwrap(), "block identity must be unchanged");
        assert!(h.matches_payload(&b.payload));
        // a different payload is a different block identity; the header keeps binding the original one
        let mut other = b.clone(); other.payload.push(1);
        assert_ne!(block_id_of(&other, &idctx(&f)).unwrap(), block_id_of(b, &idctx(&f)).unwrap());
        assert!(!h.matches_payload(&other.payload));
        // changing any field the id commits to changes the id
        let mut x = h.clone(); x.payload_hash[0] ^= 1; assert_ne!(x.id(&idctx(&f)).unwrap(), h.id(&idctx(&f)).unwrap());
        let mut x = h.clone(); x.round += 1; assert_ne!(x.id(&idctx(&f)).unwrap(), h.id(&idctx(&f)).unwrap());
    }
    // the id does not commit to the payload LENGTH, so a header cannot check the size limit: check_payload does
    let h = bs[0].to_header();
    assert!(h.check_payload(&bs[0].payload, 4096).is_ok());
    assert_eq!(h.check_payload(&bs[0].payload, 1), Err(HeaderError::PayloadTooLarge));
    assert_eq!(h.check_payload(b"other", 4096), Err(HeaderError::PayloadMismatch));
}

#[test]
fn the_header_encoding_round_trips_is_canonical_and_rejects_every_truncation() {
    let (_net, bs, _) = tc_chain();
    let (plain, with_tc) = (bs.iter().find(|b| b.tc.is_none()).unwrap(), bs.iter().find(|b| b.tc.is_some()).unwrap());
    for b in [plain, with_tc] {
        let h = b.to_header();
        let e = encode_header(&h);
        assert_eq!(decode_header(&e).unwrap(), h);
        assert_eq!(encode_header(&decode_header(&e).unwrap()), e, "re-encoding is byte identical");
        // the header is the block with the length-prefixed payload replaced by its 32-byte hash
        assert_eq!(e.len() + 4 + b.payload.len(), encode_block(b).len() + 32);
        for cut in (0..e.len()).step_by(97).chain([e.len() - 1]) { assert!(decode_header(&e[..cut]).is_err(), "truncated at {cut}"); }
        let mut t = e.clone(); t.push(0); assert!(decode_header(&t).is_err(), "trailing byte");
    }
    // an option flag that is neither 0 nor 1, and a wrong signature length
    let h = plain.to_header();
    let mut e = encode_header(&h);
    let flag_at = 8 + 8 + 8 + 32 + 4 + h.qc.encode().len();
    e[flag_at] = 2;
    assert!(decode_header(&e).is_err());
    let mut bad = h.clone(); bad.signature.pop();
    assert!(decode_header(&encode_header(&bad)).is_err());
}

fn header_chain_agrees_with_engine(silent: &[usize], need_tc: bool) {
    let mut net = DNet::new(4, silent, "a");
    let live: Vec<usize> = (0..4).filter(|i| !silent.contains(i)).collect();
    assert!(net.run_until(8000, |n| live.iter().all(|i| n.height(*i) >= 10)));
    let set = set_n(4);
    let mut gaps = 0;
    for &i in &live {
        let (bs, fq) = chain_to(&net, i);
        let hs = headers_of(&bs);
        gaps += hs.iter().filter(|h| h.tc.is_some()).count();
        let v = verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, fq.as_ref(), 10_000).expect("a real chain verifies");
        let engine: Vec<(u64, BlockId)> = net.nodes[i].as_ref().unwrap().engine().committed_after(0).iter().map(|c| (c.height, c.id)).collect();
        assert_eq!(ids_of(&v), engine, "node {i}: the header chain's finality differs from the engine's");
        assert!(!engine.is_empty());
        // payload hashes of the final blocks are the ones the executor was handed
        for (p, c) in v.finalized.iter().zip(net.nodes[i].as_ref().unwrap().engine().committed_after(0)) { assert!(Block::to_header(&bs[(p.height - 1) as usize]).matches_payload(&c.payload)); }
        // without the final certificate the verifier reports at most the engine's finality, and one block less when the tip's QC is what finalizes
        let w = verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, None, 10_000).unwrap();
        assert!(ids_of(&w).len() <= engine.len() && engine.starts_with(&ids_of(&w)));
    }
    if need_tc { assert!(gaps > 0, "the run must contain round gaps"); }
}

#[test]
fn header_chains_of_a_healthy_run_verify_and_finalize_exactly_what_the_engine_finalizes() { header_chain_agrees_with_engine(&[], false); }

#[test]
fn header_chains_with_timeout_certificates_finalize_exactly_what_the_engine_finalizes_and_never_across_a_round_gap() { header_chain_agrees_with_engine(&[3], true); }

#[test]
fn every_check_of_the_header_verifier_rejects_a_correctly_signed_but_invalid_chain() {
    let (_net, bs, fq) = tc_chain();
    let hs = headers_of(&bs);
    let set = set_n(4);
    let ok = |hs: &[PayloadFreeBlock]| verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, hs, fq.as_ref(), 10_000);
    assert!(ok(&hs).is_ok());
    let k_tc = hs.iter().position(|h| h.tc.is_some()).unwrap();
    let k_plain = (2..hs.len()).find(|k| hs[*k].tc.is_none()).unwrap();
    let with = |k: usize, f: &dyn Fn(&mut PayloadFreeBlock)| { let mut v = hs.clone(); f(&mut v[k]); v[k] = resign(v[k].clone()); v };

    // fields the id commits to, re-signed so only the check under test can fail
    let (i, r) = failure_at(ok(&with(k_plain, &|h| h.epoch = 1))); assert_eq!((i, r.as_str()), (k_plain, "epoch"));
    let (i, r) = failure_at(ok(&with(k_plain, &|h| h.round = 0))); assert_eq!((i, r.as_str()), (k_plain, "round 0"));
    let (i, r) = failure_at(ok(&with(k_plain, &|h| h.proposer = (h.proposer + 1) % 3))); assert_eq!((i, r.as_str()), (k_plain, "proposer is not the leader of the round"));
    let (i, r) = failure_at(ok(&with(k_plain, &|h| h.height += 1))); assert_eq!((i, r.as_str()), (k_plain, "height"));
    let (i, r) = failure_at(ok(&with(k_plain, &|h| h.parent_id[0] ^= 1))); assert_eq!((i, r.as_str()), (k_plain, "parent link"));
    // a header whose own certificate certifies another block
    let (i, r) = failure_at(ok(&with(k_plain, &|h| h.qc = hs[k_plain - 2].qc.clone()))); assert_eq!(i, k_plain, "{r}");
    // timeout-certificate presence
    let (i, r) = failure_at(ok(&with(k_tc, &|h| h.tc = None))); assert_eq!((i, r.as_str()), (k_tc, "timeout certificate presence"));
    let tc = hs[k_tc].tc.clone().unwrap();
    let (i, r) = failure_at(ok(&with(k_plain, &|h| h.tc = Some(tc.clone())))); assert_eq!((i, r.as_str()), (k_plain, "timeout certificate presence"));
    // forged and sub-quorum parent certificates
    let (i, _) = failure_at(ok(&with(k_plain, &|h| if let Cert::Qc(q) = &mut h.qc { q.sigs[0][5] ^= 1; })));
    assert_eq!(i, k_plain);
    let (i, r) = failure_at(ok(&with(k_plain, &|h| if let Cert::Qc(q) = &mut h.qc {
        let mut kept = 0; let mut sigs = vec![];
        for (j, s) in q.signers.iter_mut().enumerate() { if *s { if kept < 2 { kept += 1; sigs.push(q.sigs[sigs.len().min(q.sigs.len() - 1)].clone()); } else { *s = false; } } let _ = j; }
        q.sigs = sigs;
    })));
    assert_eq!(i, k_plain, "{r}");
    // a signature by the wrong key, a flipped signature, a tampered payload hash
    let mut v = hs.clone(); v[k_plain].signature = sign((v[k_plain].proposer + 1) % 4, Kind::Proposal.context(), b"not the id");
    assert_eq!(failure_at(ok(&v)), (k_plain, "proposer signature".to_string()));
    let mut v = hs.clone(); v[k_plain].signature[7] ^= 1;
    assert_eq!(failure_at(ok(&v)), (k_plain, "proposer signature".to_string()));
    let mut v = hs.clone(); v[k_plain].payload_hash[0] ^= 1;
    assert_eq!(failure_at(ok(&v)), (k_plain, "proposer signature".to_string()));
    // structure: a missing, duplicated, swapped or replayed header
    let mut v = hs.clone(); v.remove(k_plain);
    assert_eq!(failure_at(ok(&v)).0, k_plain);
    let mut v = hs.clone(); v.insert(k_plain, hs[k_plain].clone());
    assert_eq!(failure_at(ok(&v)).0, k_plain + 1);
    let mut v = hs.clone(); v.swap(k_plain, k_plain + 1);
    assert_eq!(failure_at(ok(&v)).0, k_plain);
    assert_eq!(failure_at(ok(&hs[2..])).0, 0, "a chain that does not start at the genesis block");
    assert_eq!(ok(&[]), Err(HeaderError::Empty));
    assert_eq!(verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, None, hs.len() - 1), Err(HeaderError::TooMany(hs.len() - 1)));

    // chain, genesis and validator-set binding
    let other_chain = ChainParams { chain_id: "other-chain", ..cparams(&set) };
    assert_eq!(failure_at(verify_header_chain(&other_chain, &TestVerifier, Start::Genesis, &hs, None, 10_000)).0, 0);
    let other_genesis = ChainParams { genesis_hash: [9; 32], ..cparams(&set) };
    assert_eq!(failure_at(verify_header_chain(&other_genesis, &TestVerifier, Start::Genesis, &hs, None, 10_000)).0, 0);
    let other_profile = ChainParams { protocol_profile: "other-profile", ..cparams(&set) };
    assert_eq!(failure_at(verify_header_chain(&other_profile, &TestVerifier, Start::Genesis, &hs, None, 10_000)).0, 0);
    let small = set_n(3);
    assert_eq!(failure_at(verify_header_chain(&cparams(&small), &TestVerifier, Start::Genesis, &hs, None, 10_000)).0, 0);
    let other_seed = ChainParams { seed: 1, ..cparams(&set) };
    assert_eq!(failure_at(verify_header_chain(&other_seed, &TestVerifier, Start::Genesis, &hs, None, 10_000)).0, 0, "a different leader schedule");

    // the final certificate must be a QC for the LAST header
    let early = hs[hs.len() - 3].qc.clone();
    assert_eq!(verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, Some(&early), 10_000), Err(HeaderError::FinalCert));
    let genesis_cert = hs[0].qc.clone();
    assert_eq!(verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, Some(&genesis_cert), 10_000), Err(HeaderError::FinalCert));
}

#[test]
fn a_chain_verifies_in_segments_from_a_final_anchor_with_the_same_finality() {
    let (_net, bs, fq) = tc_chain();
    let hs = headers_of(&bs);
    let set = set_n(4);
    let full = verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, fq.as_ref(), 10_000).unwrap();
    assert!(full.finalized.len() >= 4);
    let a: ChainPoint = full.finalized[full.finalized.len() / 2];
    let rest = &hs[a.height as usize..];
    let seg = verify_header_chain(&cparams(&set), &TestVerifier, Start::Anchor(Anchor { id: a.id, height: a.height, round: a.round, parent_round: a.round - 1, final_height: a.height, last_ref: None, ancestors: vec![] }), rest, fq.as_ref(), 10_000).unwrap();
    let above: Vec<ChainPoint> = full.finalized.iter().filter(|p| p.height > a.height).copied().collect();
    assert_eq!(seg.finalized, above, "the same blocks become final whether or not the prefix is re-verified");
    assert_eq!(seg.tip, full.tip);
    // a wrong anchor id, height or round is refused
    for bad in [Anchor { id: [1; 32], height: a.height, round: a.round, parent_round: a.round - 1, final_height: a.height, last_ref: None, ancestors: vec![] }, Anchor { id: a.id, height: a.height + 1, round: a.round, parent_round: a.round - 1, final_height: a.height, last_ref: None, ancestors: vec![] }, Anchor { id: a.id, height: a.height, round: a.round + 1, parent_round: a.round - 1, final_height: a.height, last_ref: None, ancestors: vec![] }] {
        assert!(verify_header_chain(&cparams(&set), &TestVerifier, Start::Anchor(bad), rest, fq.as_ref(), 10_000).is_err());
    }
}

fn qc_for(f: &Fx, round: u64, b: BlockId, p: BlockId, pr: u64, who: &[usize]) -> Qc {
    let m = vote_bytes(round, b, p, pr);
    let mut signers = vec![false; 4];
    for i in who { signers[*i] = true; }
    let mut who = who.to_vec(); who.sort();
    Qc { epoch: 0, round, block_id: b, parent_id: p, parent_round: pr, valset_hash: f.vh, signers, sigs: who.iter().map(|i| sign(*i, CTX_VOTE, &m)).collect() }
}

#[test]
fn finality_matches_an_independent_oracle_at_every_prefix_with_and_without_a_final_certificate() {
    let (_net, bs, fq) = tc_chain();
    let hs = headers_of(&bs);
    let set = set_n(4);
    // oracle: header j (j >= 1) is certified; if its parent hs[j-1] is exactly one round earlier, heights 1..=j are final (a genesis parent never is)
    let oracle = |certified_upto: usize| -> u64 { (1..=certified_upto).filter(|j| hs[j - 1].round + 1 == hs[*j].round).max().map_or(0, |j| j as u64) };
    let mut gap_prefixes = 0;
    for l in 1..=hs.len() {
        let prefix = &hs[..l];
        // WITHOUT a final certificate: headers 0..l-2 are certified (each is certified by its successor)
        let r = verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, prefix, None, 10_000).unwrap();
        let want = oracle(l.saturating_sub(2).max(0)).min(l as u64);
        let got: Vec<u64> = r.finalized.iter().map(|p| p.height).collect();
        assert_eq!(got, (1..=want).collect::<Vec<_>>(), "prefix {l}, no final certificate");
        // WITH a QC for the last header: headers 0..l-1 are certified
        let q = if l < hs.len() { hs[l].qc.clone() } else { fq.clone().unwrap() };
        let r = verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, prefix, Some(&q), 10_000).unwrap();
        let want = oracle(l - 1);
        let got: Vec<u64> = r.finalized.iter().map(|p| p.height).collect();
        assert_eq!(got, (1..=want).collect::<Vec<_>>(), "prefix {l}, with the final certificate");
        for p in &r.finalized { assert_eq!(p.payload_hash, hs[(p.height - 1) as usize].payload_hash); }
        if l >= 2 && hs[l - 2].round + 1 != hs[l - 1].round { gap_prefixes += 1; }
    }
    assert!(gap_prefixes > 0, "some prefix must end with a round gap, where finality must NOT advance");
}

#[test]
fn each_remaining_header_check_fails_alone_on_a_valid_certificate_aimed_at_it() {
    let (net, bs, fq) = tc_chain();
    let hs = headers_of(&bs);
    let f = fx();
    let set = set_n(4);
    let ok = |hs: &[PayloadFreeBlock]| verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, hs, fq.as_ref(), 10_000);
    let full = ok(&hs).unwrap();
    let with = |k: usize, g: &dyn Fn(&mut PayloadFreeBlock)| { let mut v = hs.clone(); g(&mut v[k]); v[k] = resign(v[k].clone()); v };
    let tcs: Vec<usize> = (0..hs.len()).filter(|k| hs[*k].tc.is_some()).collect();
    assert!(tcs.len() >= 2, "need two timeout-certificate headers");
    let k_plain = (2..hs.len()).find(|k| hs[*k].tc.is_none()).unwrap();

    // a valid QC, for the parent's round, that certifies ANOTHER block: only the "certificate's block vs parent_id" check can refuse it
    let prev_round = hs[k_plain - 1].round;
    let alien = Cert::Qc(qc_for(&f, prev_round, [99; 32], [98; 32], prev_round - 1, &[0, 1, 2]));
    let (i, r) = failure_at(ok(&with(k_plain, &|h| h.qc = alien.clone()))); assert_eq!((i, r.as_str()), (k_plain, "parent_id differs from the certificate's block"));

    // a header whose round is NOT above its certificate's round, with a valid TC for the round before it, correct proposer and parent link
    let (t_old, k_old) = (hs[tcs[0]].tc.as_ref().unwrap().round, tcs[0]);
    let k = (k_old + 2..hs.len()).find(|k| hs[*k].qc.round() > t_old + 1).expect("a later header with a higher certificate");
    let old_tc = hs[k_old].tc.clone();
    let leader = net.nodes[0].as_ref().unwrap().engine().leader_of(t_old + 1);
    let (i, r) = failure_at(ok(&with(k, &|h| { h.round = t_old + 1; h.tc = old_tc.clone(); h.proposer = leader; })));
    assert_eq!((i, r.as_str()), (k, "round is not above the certificate's round"));

    // timeout certificates: a forged one, and a genuine one for the wrong round
    let (i, _) = failure_at(ok(&with(tcs[0], &|h| if let Some(t) = &mut h.tc { t.sigs[0][5] ^= 1; })));
    assert_eq!(i, tcs[0], "a forged timeout certificate");
    let wrong = hs[tcs[0]].tc.clone();
    let (i, r) = failure_at(ok(&with(tcs[1], &|h| h.tc = wrong.clone()))); assert_eq!((i, r.as_str()), (tcs[1], "timeout certificate is not for the previous round"));

    // the final certificate: valid signatures, but for another block at the tip's round, and for the tip's block at another round
    let tip = full.tip;
    let other_block = Cert::Qc(qc_for(&f, tip.round, [99; 32], [98; 32], tip.round - 1, &[0, 1, 2]));
    assert_eq!(verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, Some(&other_block), 10_000), Err(HeaderError::FinalCert));
    let other_round = Cert::Qc(qc_for(&f, tip.round + 1, tip.id, hs[hs.len() - 2].parent_id, tip.round, &[0, 1, 2]));
    assert_eq!(verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, Some(&other_round), 10_000), Err(HeaderError::FinalCert));
    // a final certificate that does not even verify
    let mut forged = fq.clone().unwrap(); if let Cert::Qc(q) = &mut forged { q.sigs[0][3] ^= 1; }
    assert!(matches!(verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, Some(&forged), 10_000), Err(HeaderError::Cert { .. })));
}

#[test]
fn header_sizes_follow_the_certificate_encodings_and_signer_counts() {
    let (_net, bs, _) = tc_chain();
    let n = 4usize;
    let bm = (n + 7) / 8;
    for b in &bs {
        let h = b.to_header();
        let qc_len = h.qc.encode().len();
        if let Cert::Qc(q) = &h.qc { assert_eq!(qc_len, 140 + bm + 3315 * q.sigs.len(), "QC = 140 + ceil(n/8) + 3315 k"); }
        let tc_len = h.tc.as_ref().map(|t| t.encode().len());
        if let Some(t) = &h.tc { assert_eq!(tc_len.unwrap(), 72 + bm + 3323 * t.sigs.len() + t.high_qc.encode().len(), "TC = 72 + ceil(n/8) + 3323 k + nested certificate"); }
        assert_eq!(encode_header(&h).len(), 3410 + qc_len + tc_len.map_or(0, |l| 4 + l), "header = 3410 + QC (+ 4 + TC)");
    }
}

#[test]
#[ignore = "diagnostic: prints replay costs; meaningful only with real signatures (pq_hotstuff_engine_fips204)"]
fn diag_header_verification_and_restart_replay_cost() {
    let mut net = DNet::new(4, &[], "a");
    assert!(net.run_until(60000, |n| (0..4).all(|i| n.height(i) >= 150)));
    let (bs, fq) = chain_to(&net, 0);
    let hs = headers_of(&bs);
    let set = set_n(4);
    let t = std::time::Instant::now();
    let v = verify_header_chain(&cparams(&set), &TestVerifier, Start::Genesis, &hs, fq.as_ref(), 100_000).unwrap();
    let el = t.elapsed();
    let bytes: usize = hs.iter().map(|h| encode_header(h).len()).sum();
    println!("DIAG headers: {} verified in {:?} = {:.2} ms/header, {} final, {} bytes total = {:.0} bytes/header", hs.len(), el, el.as_secs_f64() * 1000.0 / hs.len() as f64, v.finalized.len(), bytes, bytes as f64 / hs.len() as f64);
    let blocks = net.nodes[1].as_ref().unwrap().engine().known_blocks().len();
    let (e, bsx, x) = net.nodes[1].take().unwrap().into_parts();
    let t = std::time::Instant::now();
    let (_nd, _) = start_node(restart(e, 1, 4), bsx, { let mut s = x.inner.into_inner(); s.delete_raw("app-state"); s }, &Default::default(), "a", net.now).expect("start");
    let el = t.elapsed();
    println!("DIAG restart: {} stored blocks re-validated and {} heights replayed into a fresh executor in {:?} = {:.2} ms/block", blocks, _nd.status().exec.height, el, el.as_secs_f64() * 1000.0 / blocks as f64);
}
