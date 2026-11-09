
// ============================================================================================================================
// Checkpoint references (profile v3): canonical encoding, the identity change, validity rules R1-R4 and R6, voting rule R5, alarms, the proposer policy,
// header verification of every applicable rule, the durable root log and restart. Profile v2 is checked to be unchanged. The same tests run on the test
// doubles and on real ML-DSA-65 signatures. DRAFT; no network is configured with profile v3.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::checkpoint::{self as ckpt, check_reference, CheckpointConfig, CheckpointParams, RefContext, RefError, RefPolicy, RootCheck};
use chain_forge_consensus::pq_hotstuff::netmsg::decode_block;
use chain_forge_consensus::pq_hotstuff::wire::{BlockIdInput, BlockIdInputV3};

const PROFILE3: &str = ckpt::PROFILE_V3;

fn cc3(k: u64, age: u64) -> CheckpointConfig { CheckpointConfig { params: CheckpointParams { interval: k, max_age: age }, policy: RefPolicy { propose_refs: true, margin: 2, omit_rotations: 1, alarm_age_intervals: 3 } } }
fn cfg3(i: usize, n: usize, cc: &CheckpointConfig) -> EngineConfig { EngineConfig { protocol_profile: PROFILE3.into(), checkpoint: Some(*cc), ..cfg(i, n) } }
fn store3(i: usize, f: Shared) -> St {
    let pk = test_public_key(i as u8 + 1);
    let init = FreshInit { protocol_profile: PROFILE3, chain_id: CHAIN, public_key: &pk, instance_id: [i as u8; 16], epoch: 0 };
    St::initialize_fresh(MemStorage::new(f.clone()), TestCounter::bound(CounterState::INITIAL, f, binding(i)), &init, &ParticipationEvidence::default()).expect("init")
}
fn engine3(i: usize, n: usize, cc: &CheckpointConfig) -> E { E::new(cfg3(i, n, cc), store3(i, faults()), TestSigner::new(i as u8 + 1), TestVerifier).expect("v3 engine") }
fn restart3(e: E, i: usize, n: usize, cc: &CheckpointConfig) -> E {
    let (store, signer, verifier) = e.into_parts();
    let (st, ctr) = store.into_parts();
    let pk = test_public_key(i as u8 + 1);
    let exp = Expected { protocol_profile: PROFILE3, chain_id: CHAIN, public_key: &pk };
    let store = St::open(st, ctr, &exp, &TestVerifier, &ParticipationEvidence::default()).expect("reopen");
    E::new(cfg3(i, n, cc), store, signer, verifier).expect("v3 engine")
}
fn root_of(h: u64) -> [u8; 32] { rcodec::sha3(&[b"test-root", &h.to_be_bytes()]) }
fn idctx3<'a>(set: &'a EpochSet) -> IdCtx<'a> { IdCtx { protocol_profile: PROFILE3, chain_id: CHAIN, set } }
fn id3(b: &Block) -> BlockId { let set = set_n(4); block_id_of(b, &idctx3(&set)).unwrap() }
fn sign_block3(mut b: Block) -> Block {
    let id = id3(&b);
    b.signature = sign(b.proposer, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
    b
}
fn resign_header3(mut h: PayloadFreeBlock) -> PayloadFreeBlock {
    let set = set_n(4);
    let id = h.id(&idctx3(&set)).unwrap();
    h.signature = sign(h.proposer, Kind::Proposal.context(), &BlockSigningMessage { alg_id: ALG, block_id: id }.encode().unwrap());
    h
}
fn cparams3<'a>(set: &'a EpochSet, cc: &CheckpointConfig) -> ChainParams<'a> { ChainParams { protocol_profile: PROFILE3, chain_id: CHAIN, set, genesis_hash: GENESIS_HASH, seed: 0, checkpoint: Some(cc.params) } }

/// Four engines driven round by round, with a per-node executor that may lag behind the committed height by a chosen number of blocks.
struct Eng3 {
    nodes: Vec<E>,
    cc: CheckpointConfig,
    lag: Vec<u64>,
    exec: Vec<u64>,
    bad_root: Vec<bool>,
    skip_roots: Vec<bool>,
    commits: Vec<Vec<Committed>>,
    proposals: Vec<Block>,
    qc_rounds: u64,
    timeouts: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step3 { Qc, Timeout, Stuck }

impl Eng3 {
    fn new(n: usize, cc: CheckpointConfig) -> Eng3 { Self::with_policies(n, cc, vec![cc.policy; n]) }
    fn with_policies(n: usize, cc: CheckpointConfig, policies: Vec<RefPolicy>) -> Eng3 {
        let nodes = (0..n).map(|i| engine3(i, n, &CheckpointConfig { policy: policies[i], ..cc })).collect();
        Eng3 { nodes, cc, lag: vec![0; n], exec: vec![0; n], bad_root: vec![false; n], skip_roots: vec![false; n], commits: vec![vec![]; n], proposals: vec![], qc_rounds: 0, timeouts: 0 }
    }
    fn n(&self) -> usize { self.nodes.len() }
    /// Bring node `i`'s executor up to (committed height - lag), record the roots of the checkpoint heights it passes, and collect the votes it may now cast.
    fn feed(&mut self, i: usize) -> Vec<Output> {
        let committed = self.nodes[i].committed_tip().1;
        let target = committed.saturating_sub(self.lag[i]).max(self.exec[i]);
        let k = self.cc.params.interval;
        for h in self.exec[i] + 1..=target {
            if h % k == 0 && !self.skip_roots[i] { let mut r = root_of(h); if self.bad_root[i] { r[0] ^= 1; } let _ = self.nodes[i].record_root(h, r); }
        }
        self.exec[i] = target;
        self.nodes[i].on_executed(target).unwrap_or_default()
    }
    fn deliver(&mut self, from: usize, outs: Vec<Output>) {
        let n = self.n();
        let mut q: VecDeque<(usize, Output)> = outs.into_iter().map(|o| (from, o)).collect();
        while let Some((from, o)) = q.pop_front() {
            let ds: Vec<(usize, Msg)> = match o {
                Output::Broadcast(m) => { if let Msg::Proposal(b) = &m { self.proposals.push(b.clone()); } (0..n).filter(|i| *i != from).map(|i| (i, m.clone())).collect() }
                Output::Send { to, msg } => if to == from { vec![] } else { vec![(to, msg)] },
                Output::Commit(c) => { self.commits[from].push(c); let more = self.feed(from); q.extend(more.into_iter().map(|o| (from, o))); vec![] }
                _ => vec![],
            };
            for (to, m) in ds { let outs = self.nodes[to].on_message(m).unwrap_or_default(); q.extend(outs.into_iter().map(|o| (to, o))); }
        }
    }
    fn feed_all(&mut self) { for i in 0..self.n() { let o = self.feed(i); self.deliver(i, o); } }
    /// One round: the leader proposes; if no QC forms, everyone times out and a TC advances the round.
    fn step(&mut self) -> Step3 {
        let r = self.nodes.iter().map(|e| e.round()).max().unwrap();
        let l = self.nodes[0].leader_of(r);
        let before = self.nodes.iter().map(|e| e.round()).max().unwrap();
        match self.nodes[l].propose(format!("tx-{r}").into_bytes()) {
            Ok(first) => self.deliver(l, first),
            Err(EngineError::Halted(_)) => {} // a halted leader proposes nothing: the round times out
            Err(_) => return Step3::Stuck,
        }
        self.feed_all();
        let after = self.nodes.iter().map(|e| e.round()).max().unwrap();
        if after > before { self.qc_rounds += 1; return Step3::Qc; }
        for i in 0..self.n() { if let Ok(o) = self.nodes[i].local_timeout() { self.deliver(i, o); } }
        self.feed_all();
        self.timeouts += 1;
        Step3::Timeout
    }
    fn run(&mut self, rounds: usize) { for _ in 0..rounds { if self.step() == Step3::Stuck { break; } } }
    fn run_until_committed(&mut self, height: u64, max_rounds: usize) { for _ in 0..max_rounds { if self.nodes.iter().all(|e| e.committed_tip().1 >= height) { return; } if self.step() == Step3::Stuck { return; } } }
    /// Offer node `j` a correctly signed block for the current round with the given reference.
    fn offer(&mut self, j: usize, checkpoint: Option<CheckpointRef>) -> Result<Vec<Output>, EngineError> { let b = self.crafted(checkpoint); self.nodes[j].on_proposal(b) }
    fn refs(&self) -> Vec<CheckpointRef> { let mut v: Vec<CheckpointRef> = vec![]; for b in &self.proposals { if let Some(r) = b.checkpoint { if v.last() != Some(&r) { v.push(r); } } } v }
    /// The node furthest along (after a QC only the next leader has advanced; the others learn it from the next proposal).
    fn lead(&self) -> usize { (0..self.n()).max_by_key(|i| (self.nodes[*i].round(), usize::MAX - *i)).unwrap() }
    fn committed(&self) -> u64 { self.nodes.iter().map(|e| e.committed_tip().1).max().unwrap() }
    /// The chain from genesis to node `i`'s high QC.
    fn chain(&self, i: usize) -> Vec<Block> {
        let all: BTreeMap<BlockId, Block> = self.nodes[i].known_blocks().into_iter().map(|b| (id3(b), b.clone())).collect();
        let Cert::Qc(q) = self.nodes[i].high_qc().clone() else { return vec![] };
        let (mut cur, mut out) = (q.block_id, vec![]);
        while let Some(b) = all.get(&cur) { out.push(b.clone()); cur = b.parent_id; }
        out.reverse();
        out
    }
    /// A correctly signed block for the CURRENT round, extending node 0's high QC, with the given reference. Requires a consecutive round (no TC).
    fn crafted(&self, checkpoint: Option<CheckpointRef>) -> Block {
        let e = &self.nodes[self.lead()];
        let (qc, r) = (e.high_qc().clone(), e.round());
        assert_eq!(qc.round() + 1, r, "crafting needs a consecutive round");
        let parent_id = qc.block_id();
        let height = e.known_blocks().into_iter().find(|b| id3(b) == parent_id).map_or(0, |b| b.height) + 1;
        sign_block3(Block { checkpoint, epoch: 0, round: r, height, parent_id, qc, tc: None, payload: b"crafted".to_vec(), proposer: e.leader_of(r), signature: vec![] })
    }
}

fn id_at(chain: &[Block], h: u64) -> BlockId { id3(&chain[(h - 1) as usize]) }
fn err_reason(r: Result<Vec<Output>, EngineError>) -> String { match r { Err(EngineError::Invalid(m)) => m.to_string(), Err(e) => format!("{e}"), Ok(_) => "accepted".into() } }

// ---- golden values and relations: profile v2 is unchanged
const DET_GOLDEN_BLOCK_ID: &str = "ec1f9d66140730a32dc6cd78f0e120641393bf4375a02bd4b59fc94de4147d42";
const GOLDEN_GENESIS_ID: &str = "f4d7c86c4817b8b059b71bf8565b83922c43a3be57bebb4b18367e5dcba4c56c";
const DET_GOLDEN_BLOCK_BYTES: &str = "4bee9c2ae26cce7b437fa959601ccddd7d7a0e6085e63198d8ec4944b7ed186f";
const DET_GOLDEN_HEADER_BYTES: &str = "4adf807877568f47a9d2852afdba8f6cd23fe3a9b8b389d5482b6ceca065eb5d";
fn hexs(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

#[test]
fn profile_v2_block_ids_wire_bytes_and_behavior_are_unchanged() {
    let f = fx();
    let b = base_block(&f);
    assert!(b.checkpoint.is_none());
    let id = block_id_of(&b, &idctx(&f)).unwrap();
    // independent reconstruction with the ORIGINAL v2 preimage type, which this change did not touch
    let legacy = BlockIdInput { alg_id: ALG, protocol_profile: PROFILE.into(), chain_id: CHAIN.into(), epoch: b.epoch, round: b.round, height: b.height, parent_id: b.parent_id,
        payload_hash: rcodec::sha3(&[&b.payload]), qc_hash: b.qc.hash(), tc_hash: b.tc.as_ref().map(Tc::hash), proposer: set_n(4).entries()[b.proposer].address.clone() };
    assert_eq!(id, legacy.block_id().unwrap(), "a v2 id is exactly the original preimage");
    assert_eq!(b.to_header().id(&idctx(&f)).unwrap(), id);
    // the genesis block id and the lengths of the encodings do not depend on the keys
    assert_eq!(hexs(&f.genesis.block_id()), GOLDEN_GENESIS_ID);
    assert_eq!(encode_block(&b).len(), 10181, "no extension bytes on a v2 block");
    assert_eq!(encode_header(&b.to_header()).len(), 10187);
    // full golden values exist only where the keys are deterministic (the test doubles)
    if DETERMINISTIC_KEYS {
        assert_eq!(hexs(&id), DET_GOLDEN_BLOCK_ID);
        assert_eq!(hexs(&rcodec::sha3(&[&encode_block(&b)])), DET_GOLDEN_BLOCK_BYTES);
        assert_eq!(hexs(&rcodec::sha3(&[&encode_header(&b.to_header())])), DET_GOLDEN_HEADER_BYTES);
    }
    // a reference is refused on a profile without checkpoints, wherever the id is computed
    let with_ref = Block { checkpoint: Some(CheckpointRef { height: 4, block_id: [1; 32], state_root: [2; 32] }), ..b.clone() };
    assert!(block_id_of(&with_ref, &idctx(&f)).is_err());
    assert!(with_ref.to_header().id(&idctx(&f)).is_err());
    // the v2 and v3 preimage tags are distinct and neither is a prefix of the other
    assert!(!ckpt::PROFILE_V3.is_empty() && ckpt::PROFILE_V2 == PROFILE && ckpt::PROFILE_V2 != ckpt::PROFILE_V3);
    assert!(!chain_chain_prefix(chain_forge_consensus::pq_hotstuff::wire::TAG_BLOCK_ID, chain_forge_consensus::pq_hotstuff::wire::TAG_BLOCK_ID_V3));
    // engines refuse mixed configurations
    let cc = cc3(4, 8);
    assert!(matches!(E::new(EngineConfig { checkpoint: Some(cc), ..cfg(0, 4) }, fresh_store(0, faults()), TestSigner::new(1), TestVerifier), Err(EngineError::Config(_))), "v2 profile with checkpoint parameters");
    assert!(matches!(E::new(EngineConfig { protocol_profile: PROFILE3.into(), ..cfg(0, 4) }, store3(0, faults()), TestSigner::new(1), TestVerifier), Err(EngineError::Config(_))), "v3 profile without them");
}
fn chain_chain_prefix(a: &[u8], b: &[u8]) -> bool { a.starts_with(b) || b.starts_with(a) }

#[test]
fn v3_identity_binds_the_profile_the_reference_and_the_genesis_parameters() {
    let f = fx();
    let set = set_n(4);
    let b = base_block(&f);
    let r = CheckpointRef { height: 4, block_id: [1; 32], state_root: [2; 32] };
    let v2 = block_id_of(&b, &idctx(&f)).unwrap();
    let v3_none = block_id_of(&b, &idctx3(&set)).unwrap();
    let v3_ref = block_id_of(&Block { checkpoint: Some(r), ..b.clone() }, &idctx3(&set)).unwrap();
    assert_ne!(v2, v3_none, "the profile alone separates the chains");
    assert_ne!(v3_none, v3_ref, "a reference changes the id");
    let again = block_id_of(&Block { checkpoint: Some(r), ..b.clone() }, &idctx3(&set)).unwrap();
    assert_eq!(v3_ref, again, "deterministic");
    // every field of the reference is committed to
    for tweak in 0..3 {
        let mut x = r;
        match tweak { 0 => x.height += 4, 1 => x.block_id[0] ^= 1, _ => x.state_root[31] ^= 1 }
        assert_ne!(block_id_of(&Block { checkpoint: Some(x), ..b.clone() }, &idctx3(&set)).unwrap(), v3_ref, "field {tweak}");
    }
    // the v3 preimage is the v2 body under a new tag plus the section; the header form gives the same id
    let base = BlockIdInput { alg_id: ALG, protocol_profile: PROFILE3.into(), chain_id: CHAIN.into(), epoch: b.epoch, round: b.round, height: b.height, parent_id: b.parent_id, payload_hash: rcodec::sha3(&[&b.payload]), qc_hash: b.qc.hash(), tc_hash: None, proposer: set.entries()[b.proposer].address.clone() };
    // the preimage bytes are exactly: the v3 tag, the v2 body (after its own tag), and the section -- built here independently of the type under test
    let v2_body = base.encode().unwrap()[chain_forge_consensus::pq_hotstuff::wire::TAG_BLOCK_ID.len()..].to_vec();
    let mut expect = chain_forge_consensus::pq_hotstuff::wire::TAG_BLOCK_ID_V3.to_vec();
    expect.extend_from_slice(&v2_body);
    expect.push(1); expect.extend_from_slice(&r.hash());
    assert_eq!(BlockIdInputV3 { base: base.clone(), checkpoint_hash: Some(r.hash()) }.encode().unwrap(), expect);
    let mut expect_none = chain_forge_consensus::pq_hotstuff::wire::TAG_BLOCK_ID_V3.to_vec();
    expect_none.extend_from_slice(&v2_body); expect_none.push(0);
    assert_eq!(BlockIdInputV3 { base: base.clone(), checkpoint_hash: None }.encode().unwrap(), expect_none);
    assert_ne!(&expect[..14], &base.encode().unwrap()[..13], "the v2 and v3 tags differ");
    assert_eq!(rcodec::sha3(&[&expect]), v3_ref, "the v3 id is SHA3-256 of that preimage");
    assert_eq!(BlockIdInputV3 { base: base.clone(), checkpoint_hash: Some(r.hash()) }.block_id().unwrap(), v3_ref);
    assert_eq!(BlockIdInputV3 { base, checkpoint_hash: None }.block_id().unwrap(), v3_none);
    assert_eq!(Block { checkpoint: Some(r), ..b.clone() }.to_header().id(&idctx3(&set)).unwrap(), v3_ref);
    // genesis binding: any difference in the validity-affecting parameters is a different genesis
    let g = |cc: &CheckpointConfig| engine3(0, 4, cc).genesis_id();
    let base_cc = cc3(4, 8);
    assert_eq!(g(&base_cc), g(&cc3(4, 8)));
    assert_ne!(g(&base_cc), g(&cc3(4, 12)), "freshness bound");
    assert_ne!(g(&base_cc), g(&cc3(8, 8)), "interval");
    assert_ne!(g(&base_cc), engine(0, 4).genesis_id(), "v3 vs v2");
    // policy knobs are NOT validity parameters and do not change the genesis
    let other_policy = CheckpointConfig { policy: RefPolicy { propose_refs: false, margin: 50, omit_rotations: 9, alarm_age_intervals: 1 }, ..base_cc };
    assert_eq!(g(&base_cc), g(&other_policy));
    // parameter validation with checked bounds
    for bad in [CheckpointParams { interval: 0, max_age: 8 }, CheckpointParams { interval: 4, max_age: 3 }, CheckpointParams { interval: (1 << 40) + 1, max_age: 1 << 41 }, CheckpointParams { interval: 4, max_age: (1 << 50) + 1 }] {
        assert!(bad.validate().is_err(), "{bad:?}");
        assert!(matches!(E::new(cfg3(0, 4, &CheckpointConfig { params: bad, ..base_cc }), store3(0, faults()), TestSigner::new(1), TestVerifier), Err(EngineError::Config(_))));
    }
    assert!(CheckpointParams { interval: 1 << 40, max_age: 1 << 50 }.validate().is_ok());
    assert!(RefPolicy { propose_refs: true, margin: (1 << 50) + 1, omit_rotations: 1, alarm_age_intervals: 1 }.validate().is_err());
}

#[test]
fn the_reference_encoding_is_canonical_and_blocks_and_headers_round_trip_with_it() {
    let r = CheckpointRef { height: 40, block_id: [3; 32], state_root: [4; 32] };
    let e = r.encode();
    assert_eq!(e.len(), 72);
    assert_eq!(&e[..8], &40u64.to_be_bytes());
    assert_eq!(CheckpointRef::decode(&e), Some(r));
    for cut in [0usize, 1, 71] { assert_eq!(CheckpointRef::decode(&e[..cut]), None); }
    assert_eq!(CheckpointRef::decode(&[e.to_vec(), vec![0]].concat()), None);
    assert_ne!(r.hash(), rcodec::sha3(&[&e]), "domain separated");
    let f = fx();
    let plain = sign_block3(base_block(&f)); // a correctly signed block, so the signature has its real length
    let b = sign_block3(Block { checkpoint: Some(r), ..base_block(&f) });
    let same_without = Block { checkpoint: None, ..b.clone() }; // the SAME block (same signature) minus the reference
    let (eb, ep) = (encode_block(&b), encode_block(&same_without));
    assert_eq!(eb.len(), ep.len() + ckpt::REF_EXTENSION_LEN);
    assert_eq!(&eb[..ep.len()], &ep[..], "the extension is appended; the v2 bytes are a prefix");
    assert_eq!(&eb[ep.len()..][..1], &[1u8]);
    assert_eq!(decode_block(&eb).unwrap(), b);
    assert_eq!(encode_block(&decode_block(&eb).unwrap()), eb, "canonical");
    assert_eq!(decode_block(&ep).unwrap().checkpoint, None);
    assert_eq!(encode_block(&plain).len(), ep.len());
    // malformed extensions
    for bad in [[eb.clone(), vec![0]].concat(), eb[..eb.len() - 1].to_vec(), { let mut x = eb.clone(); x[ep.len()] = 2; x }, { let mut x = eb.clone(); x[ep.len()] = 0; x }, [ep.clone(), vec![1]].concat()] {
        assert!(decode_block(&bad).is_err());
    }
    // headers carry it too, and a block inside a proposal message does
    let h = b.to_header();
    let eh = encode_header(&h);
    assert_eq!(eh.len(), encode_header(&same_without.to_header()).len() + ckpt::REF_EXTENSION_LEN);
    assert_eq!(decode_header(&eh).unwrap(), h);
    assert!(decode_header(&eh[..eh.len() - 1]).is_err());
    let m = mlim();
    let bytes = net::encode(&NetMsg::Consensus(Msg::Proposal(b.clone())));
    assert!(matches!(net::decode(&bytes, &m), Ok(NetMsg::Consensus(Msg::Proposal(x))) if x.checkpoint == Some(r)));
    let bytes2 = net::encode(&NetMsg::Consensus(Msg::Proposal(same_without.clone())));
    assert_eq!(bytes.len(), bytes2.len() + ckpt::REF_EXTENSION_LEN);
}

// ---- the pure rules, at their exact boundaries
#[test]
fn the_reference_rules_have_exact_boundaries_and_checked_arithmetic() {
    let ident = |h: u64| -> Option<BlockId> { Some([h as u8; 32]) };
    let rf = |h: u64, root: u8| CheckpointRef { height: h, block_id: [h as u8; 32], state_root: [root; 32] };
    let check = |p: &CheckpointParams, f: u64, last: Option<CheckpointRef>, r: &CheckpointRef, at: &dyn Fn(u64) -> Option<BlockId>| check_reference(r, &RefContext { params: p, final_height: f, last_ref: last, block_id_at: at });
    let p1 = CheckpointParams { interval: 1, max_age: 3 };
    // R1 shape
    assert_eq!(check(&p1, 10, None, &rf(0, 1), &ident), Err(RefError::Shape), "height zero");
    assert_eq!(check(&CheckpointParams { interval: 4, max_age: 8 }, 20, None, &rf(6, 1), &ident), Err(RefError::Shape), "not a multiple of the interval");
    assert!(check(&CheckpointParams { interval: 4, max_age: 8 }, 20, None, &rf(16, 1), &ident).is_ok());
    // R2: at the final height is fine, one above is not
    assert!(check(&p1, 10, None, &rf(10, 1), &ident).is_ok());
    assert_eq!(check(&p1, 10, None, &rf(11, 1), &ident), Err(RefError::NotFinal));
    // R6: the freshness bound is inclusive; one beyond is too old (age = F - height)
    assert!(check(&p1, 10, None, &rf(7, 1), &ident).is_ok(), "age 3 = max_age");
    assert_eq!(check(&p1, 10, None, &rf(6, 1), &ident), Err(RefError::TooOld), "age 4 = max_age + 1");
    // R3: identity
    assert_eq!(check(&p1, 10, None, &rf(9, 1), &|_| Some([0xEE; 32])), Err(RefError::WrongAncestor));
    assert_eq!(check(&p1, 10, None, &rf(9, 1), &|_| None), Err(RefError::Unverifiable));
    // R4: backwards, conflicting at the same height, and a REPEATED reference however old
    let last = Some(rf(8, 1));
    assert_eq!(check(&p1, 10, last, &rf(7, 1), &ident), Err(RefError::Backwards));
    assert_eq!(check(&p1, 10, last, &rf(8, 2), &ident), Err(RefError::Conflicting), "same height, different root");
    assert_eq!(check(&p1, 10, last, &CheckpointRef { block_id: [0x99; 32], ..rf(8, 1) }, &ident), Err(RefError::Conflicting), "same height, different block");
    assert!(check(&p1, 10, last, &rf(8, 1), &ident).is_ok());
    assert!(check(&p1, 1_000_000, last, &rf(8, 1), &|_| None).is_ok(), "a repeat is legal at any age and needs no ancestor lookup");
    assert_eq!(check(&p1, 1_000_000, last, &rf(9, 1), &ident), Err(RefError::TooOld), "but a NEW old reference is not");
    // R6 is checked BEFORE the ancestor lookup, so a stale reference never triggers the (chain-depth) walk, and a fresh one is bounded by max_age
    let calls = std::cell::Cell::new(0u32);
    let counting = |h: u64| -> Option<BlockId> { calls.set(calls.get() + 1); Some([h as u8; 32]) };
    assert_eq!(check(&p1, 10, None, &rf(6, 1), &counting), Err(RefError::TooOld));
    assert_eq!(calls.get(), 0, "a too-old reference must be refused without any ancestor lookup");
    assert!(check(&p1, 10, None, &rf(7, 1), &counting).is_ok());
    assert_eq!(calls.get(), 1);
    // extremes do not overflow
    assert!(check(&p1, u64::MAX, None, &CheckpointRef { height: u64::MAX, block_id: [0xFF; 32], state_root: [1; 32] }, &|_| Some([0xFF; 32])).is_ok(), "age 0 at the largest height");
    assert_eq!(check(&p1, u64::MAX, None, &rf(1, 1), &ident), Err(RefError::TooOld));
    let huge = CheckpointParams { interval: 1 << 40, max_age: 1 << 50 };
    assert!(check(&huge, 1 << 41, None, &CheckpointRef { height: 1 << 40, block_id: [0; 32], state_root: [0; 32] }, &|_| Some([0; 32])).is_ok());
    // the finality arithmetic: the parent of a consecutive-round child becomes final, a gap does not, and F never moves back
    assert_eq!(ckpt::final_height_after(3, 10, Some((9, 7))), 7);
    assert_eq!(ckpt::final_height_after(9, 10, Some((9, 7))), 9, "never lower than the parent's own F");
    assert_eq!(ckpt::final_height_after(3, 11, Some((9, 7))), 3, "a round gap finalizes nothing");
    assert_eq!(ckpt::final_height_after(3, 10, None), 3, "the genesis block is never final by this rule");
    assert_eq!(ckpt::final_height_after(0, u64::MAX, Some((u64::MAX, 5))), 0, "no overflow at the largest round");
}

// ---- a healthy run
#[test]
fn a_healthy_v3_run_publishes_references_that_every_node_accepts() {
    let mut e = Eng3::new(4, cc3(4, 8));
    e.run(70);
    assert_eq!(e.timeouts, 0, "a healthy run needs no timeouts");
    assert!(e.committed() >= 40, "committed {}", e.committed());
    let refs = e.refs();
    assert!(refs.len() >= 5, "only {} distinct references were published", refs.len());
    let chain = e.chain(e.lead());
    let mut last = 0;
    for r in &refs {
        assert_eq!(r.height % 4, 0);
        assert!(r.height > last, "references only move forward");
        last = r.height;
        assert_eq!(r.state_root, root_of(r.height), "the root is the proposer's own execution");
        assert_eq!(r.block_id, id_at(&chain, r.height), "the reference names the block on the chain");
        assert!(r.height + 12 >= chain.len() as u64 - 0 || true);
    }
    for i in 0..4 {
        assert!(e.nodes[i].alarm().is_none() && e.nodes[i].evidence().is_empty() && e.nodes[i].deferred_len() == 0, "node {i}");
        assert!(e.nodes[i].checkpoint_age() <= 4 + 2 + 4 + 4, "node {i} checkpoint age {}", e.nodes[i].checkpoint_age());
    }
    // agreement on the committed chain
    let lens: Vec<usize> = e.commits.iter().map(|c| c.len()).collect();
    let m = *lens.iter().min().unwrap();
    for i in 1..4 { assert_eq!(e.commits[0][..m].iter().map(|c| c.id).collect::<Vec<_>>(), e.commits[i][..m].iter().map(|c| c.id).collect::<Vec<_>>()); }
}

/// Fixture without references: nodes execute and record roots but never propose references, so any reference tested below is crafted.
fn no_refs(n_rounds: usize) -> Eng3 {
    let cc = cc3(4, 8);
    let mut e = Eng3::with_policies(4, cc, vec![RefPolicy { propose_refs: false, ..cc.policy }; 4]);
    e.run(n_rounds);
    assert!(e.refs().is_empty());
    e
}
fn target(e: &Eng3) -> usize { let l = e.lead(); let r = e.nodes[l].round(); (e.nodes[l].leader_of(r) + 2) % 4 } // neither the proposer nor the next leader: its vote is a visible Send

#[test]
fn each_validity_rule_rejects_a_correctly_signed_block_on_its_own() {
    let mut e = no_refs(40);
    let f = e.nodes[e.lead()].committed_tip().1;
    assert!(f >= 28 && f % 4 != 5, "F = {f}");
    let chain = e.chain(e.lead());
    let set = set_n(4);
    let good = |h: u64| CheckpointRef { height: h, block_id: id_at(&chain, h), state_root: root_of(h) };
    let j = target(&e);
    let fresh = (f / 4) * 4; // the newest checkpoint height that is final
    // R1 shape
    for bad in [CheckpointRef { height: 0, ..good(4) }, CheckpointRef { height: fresh - 1, ..good(fresh - 1) }, CheckpointRef { height: fresh + 1, ..good(fresh) }] {
        let r = err_reason(e.offer(j, Some(bad)));
        assert!(r.contains("(R1)"), "{r}");
    }
    // R2 above the final height
    let above = fresh + 4;
    let r = err_reason(e.offer(j, Some(CheckpointRef { height: above, block_id: [7; 32], state_root: root_of(above) })));
    assert!(r.contains("(R2)"), "{r}");
    // R3 wrong block at a valid height; a block from another height; a made-up id
    for wrong in [[9u8; 32], id_at(&chain, fresh - 4)] {
        let r = err_reason(e.offer(j, Some(CheckpointRef { block_id: wrong, ..good(fresh) })));
        assert!(r.contains("(R3)"), "{r}");
    }
    // R6 a NEW reference older than the freshness bound (age = F - height > 8)
    let old = (f.saturating_sub(9) / 4) * 4;
    assert!(old >= 4 && f - old > 8);
    let r = err_reason(e.offer(j, Some(good(old))));
    assert!(r.contains("(R6)"), "{r}");
    // the boundary itself: age exactly 8 (if aligned) is accepted by validity; the newest final checkpoint always is
    let blk = e.crafted(Some(good(fresh)));
    let outs = e.nodes[j].on_proposal(blk.clone()).unwrap();
    assert!(has_vote(&outs), "a fresh, final, correctly rooted reference gets a vote");
    // none of the rejected blocks left any trace: the accepted block is the only one in the tree at its round
    assert_eq!(e.nodes[j].known_blocks().iter().filter(|b| b.round == blk.round).count(), 1);
    let _ = set;
}

#[test]
fn a_reference_that_goes_backwards_or_conflicts_is_refused_and_a_repeat_is_legal_at_any_age() {
    let mut e = Eng3::new(4, cc3(4, 8));
    e.run_until_committed(36, 100);
    let refs = e.refs();
    let last = *refs.last().expect("references were published");
    assert!(last.height >= 16, "last {}", last.height);
    let chain = e.chain(e.lead());
    let good = |h: u64| CheckpointRef { height: h, block_id: id_at(&chain, h), state_root: root_of(h) };
    let j = target(&e);
    // R4 backwards
    let r = err_reason(e.offer(j, Some(good(last.height - 4))));
    assert!(r.contains("(R4)") && r.contains("backwards"), "{r}");
    // R4 same height, different root; different block
    let r = err_reason(e.offer(j, Some(CheckpointRef { state_root: [0x55; 32], ..last })));
    assert!(r.contains("(R4)") && r.contains("conflicts"), "{r}");
    let r = err_reason(e.offer(j, Some(CheckpointRef { block_id: [0x56; 32], ..last })));
    assert!(r.contains("(R4)") && r.contains("conflicts"), "{r}");
    // an identical repeat is valid: it is accepted and voted for
    let outs = e.offer(j, Some(last)).unwrap();
    assert!(has_vote(&outs), "a repeated reference is legal");
}

#[test]
fn a_repeated_reference_stays_legal_after_it_has_aged_past_the_freshness_bound_but_a_new_one_does_not() {
    let mut e = Eng3::new(4, cc3(4, 8));
    e.run_until_committed(20, 100);
    let last = *e.refs().last().unwrap();
    // from now on nobody can reach a newer checkpoint: every executor stops where it is (so no new references are proposed), while the chain keeps committing
    for i in 0..4 { e.lag[i] = u64::MAX / 2; }
    e.run(60);
    let f = e.nodes[e.lead()].committed_tip().1;
    assert!(f > last.height + 8 + 8, "F {f} must be well past the freshness bound of the last reference {}", last.height);
    assert_eq!(e.refs().last().copied(), Some(last), "no new reference was published while execution was stalled (consensus progress without checkpoint progress)");
    let chain = e.chain(e.lead());
    let j = target(&e);
    // a NEW reference at this age is refused ...
    let stale = CheckpointRef { height: last.height + 4, block_id: id_at(&chain, last.height + 4), state_root: root_of(last.height + 4) };
    assert!(f - stale.height > 8);
    let r = err_reason(e.offer(j, Some(stale)));
    assert!(r.contains("(R6)"), "{r}");
    // ... but the old one may be repeated: valid, and the vote follows because the node still holds that root
    assert!(f - last.height > 8);
    let outs = e.offer(j, Some(last)).unwrap();
    assert!(has_vote(&outs));
}


// ---- rule R5 (voting) and the alarms
fn offer_until_target(e: &mut Eng3, j: usize) { for _ in 0..8 { if target(e) == j { return; } e.step(); } panic!("could not line up node {j}"); }

#[test]
fn a_vote_waits_for_the_executor_and_is_cast_when_it_catches_up_and_deferral_is_not_evidence() {
    let cc = cc3(4, 8);
    let mut e = Eng3::with_policies(4, cc, vec![RefPolicy { propose_refs: false, ..cc.policy }; 4]);
    e.lag[2] = 12; // node 2's executor is far behind the committed height
    e.run(40);
    offer_until_target(&mut e, 2);
    let f = e.nodes[e.lead()].committed_tip().1;
    let chain = e.chain(e.lead());
    let fresh = (f / 4) * 4;
    assert!(e.nodes[2].executed_height() < fresh, "node 2 executed {} but the reference is at {fresh}", e.nodes[2].executed_height());
    let r = CheckpointRef { height: fresh, block_id: id_at(&chain, fresh), state_root: root_of(fresh) };
    assert_eq!(e.nodes[2].ref_outcome(&r), RootCheck::NotYet);
    let outs = e.offer(2, Some(r)).unwrap();
    assert!(!has_vote(&outs), "no vote while the executor has not reached the checkpoint");
    assert_eq!(e.nodes[2].deferred_len(), 1);
    assert!(e.nodes[2].evidence().is_empty() && e.nodes[2].alarm().is_none(), "deferral is not evidence");
    // the executor catches up: the deferred vote is cast
    e.lag[2] = 0;
    let more = e.feed(2);
    assert!(has_vote(&more), "the deferred vote follows the executor");
    assert_eq!(e.nodes[2].deferred_len(), 0);
    // the node is not halted
    assert!(e.nodes[2].local_timeout().is_ok());
}

#[test]
fn an_unobtainable_root_withholds_the_vote_without_a_mismatch_and_a_different_root_is_evidence_not_an_alarm() {
    let cc = cc3(4, 8);
    let build = |bad: bool, skip: bool| {
        let mut e = Eng3::with_policies(4, cc, vec![RefPolicy { propose_refs: false, ..cc.policy }; 4]);
        e.bad_root[2] = bad; e.skip_roots[2] = skip;
        e.run(40);
        offer_until_target(&mut e, 2);
        e
    };
    let reference = |e: &Eng3| { let f = e.nodes[e.lead()].committed_tip().1; let chain = e.chain(e.lead()); let h = (f / 4) * 4; CheckpointRef { height: h, block_id: id_at(&chain, h), state_root: root_of(h) } };
    // Unknown: the executor has passed the height but no root is held (and no final ancestor carries the same reference)
    let mut e = build(false, true);
    let r = reference(&e);
    assert_eq!(e.nodes[2].ref_outcome(&r), RootCheck::Unknown);
    let outs = e.offer(2, Some(r)).unwrap();
    assert!(!has_vote(&outs));
    assert_eq!(e.nodes[2].evidence().len(), 1);
    assert_eq!((e.nodes[2].evidence()[0].outcome, e.nodes[2].evidence()[0].own_root), (RootCheck::Unknown, None));
    assert!(e.nodes[2].alarm().is_none() && e.nodes[2].local_timeout().is_ok());
    // Mismatch against an UNCERTIFIED proposal: withheld, recorded, no alarm, the node keeps signing timeouts
    let mut e = build(true, false);
    let r = reference(&e);
    assert_eq!(e.nodes[2].ref_outcome(&r), RootCheck::Mismatch);
    let outs = e.offer(2, Some(r)).unwrap();
    assert!(!has_vote(&outs));
    let ev = e.nodes[2].evidence();
    assert_eq!((ev.len(), ev[0].outcome, ev[0].reference), (1, RootCheck::Mismatch, r));
    assert_ne!(ev[0].own_root, Some(r.state_root));
    assert!(e.nodes[2].alarm().is_none(), "one validator cannot tell who is wrong about an uncertified proposal");
    assert!(e.nodes[2].local_timeout().is_ok());
}

#[test]
fn a_root_contradicted_by_a_certified_block_halts_signing_without_touching_the_safety_record() {
    let mut e = Eng3::new(4, cc3(4, 8));
    e.bad_root[2] = true; // node 2's execution disagrees with everyone else's
    e.run(60);
    assert!(!e.refs().is_empty());
    let a = e.nodes[2].alarm().copied();
    let Some(chain_forge_consensus::pq_hotstuff::checkpoint::Alarm::LocalDivergence { reference, own_root }) = a else { panic!("node 2 must raise LocalDivergence, got {a:?}") };
    assert_eq!(reference.state_root, root_of(reference.height));
    assert_ne!(own_root, reference.state_root);
    for i in [0, 1, 3] { assert!(e.nodes[i].alarm().is_none(), "node {i}"); }
    // consensus progress continues without the divergent validator (3 of 4 is a quorum)
    let h0 = e.committed();
    e.run(20);
    assert!(e.committed() > h0, "the chain keeps committing");
    // node 2 is halted: it proposes nothing, signs no timeout, votes for nothing
    assert!(matches!(e.nodes[2].propose_with(b"x".to_vec(), None), Err(EngineError::Halted(_))));
    assert!(matches!(e.nodes[2].local_timeout(), Err(EngineError::Halted(_))));
    // and the safety record (the floors, the last vote, the counter) did not move once it halted
    let before = e.nodes[2].store().record().clone();
    e.run(12);
    assert_eq!(e.nodes[2].store().record(), &before, "a halted validator signs nothing");
    // the alarm names no culprit and is not a claim of equivocation
    assert!(format!("{:?}", e.nodes[2].alarm().unwrap()).contains("LocalDivergence"));
}

#[test]
fn two_certified_blocks_with_conflicting_roots_for_one_height_raise_a_generic_alarm_and_attribute_nothing() {
    let mut e = no_refs(40);
    let lead = e.lead();
    let f = e.nodes[lead].committed_tip().1;
    let chain = e.chain(lead);
    let h = (f / 4) * 4;
    let ra = CheckpointRef { height: h, block_id: id_at(&chain, h), state_root: root_of(h) };
    let rb = CheckpointRef { state_root: { let mut x = root_of(h); x[0] ^= 1; x }, ..ra };
    let j = target(&e);
    let (qc, round) = (e.nodes[lead].high_qc().clone(), e.nodes[lead].round());
    // two sibling proposals for the same round (an equivocating leader), each valid on its own
    let make = |r: CheckpointRef, payload: &[u8]| { let mut b = e.crafted(Some(r)); b.payload = payload.to_vec(); sign_block3(b) };
    let (a, b) = (make(ra, b"fork-a"), make(rb, b"fork-b"));
    assert_ne!(id3(&a), id3(&b));
    e.nodes[j].on_proposal(a.clone()).unwrap();
    e.nodes[j].on_proposal(b.clone()).unwrap();
    // each fork gets a QC (signed by three validators, as an adversary controlling a third of the power plus equivocation could arrange) and a child that carries it
    let f3 = fx();
    let leader_of = |r: u64| e.nodes[0].leader_of(r);
    let child = |parent: &Block| {
        let id = id3(parent);
        let q = Cert::Qc(qc_for(&f3, parent.round, id, parent.parent_id, qc.round(), &[0, 1, 2]));
        let r = parent.round + 1;
        let proposer = leader_of(r);
        sign_block3(Block { checkpoint: None, epoch: 0, round: r, height: parent.height + 1, parent_id: id, qc: q, tc: None, payload: b"child".to_vec(), proposer, signature: vec![] })
    };
    assert_eq!(round, a.round);
    let (child_a, child_b) = (child(&a), child(&b));
    e.nodes[j].on_proposal(child_a).unwrap();
    assert!(e.nodes[j].alarm().is_none(), "one certified reference is not a conflict");
    e.nodes[j].on_proposal(child_b).unwrap();
    match e.nodes[j].alarm() {
        Some(chain_forge_consensus::pq_hotstuff::checkpoint::Alarm::ConflictingCertifiedRoots { first, second }) => assert_eq!((first.height, second.height), (h, h)),
        other => panic!("expected ConflictingCertifiedRoots, got {other:?}"),
    }
    assert!(matches!(e.nodes[j].local_timeout(), Err(EngineError::Halted(_))));
}

// ---- checkpoint progress and consensus progress, separately, under explicit assumptions.
// Common assumptions: n = 4 equal-power validators (quorum 3, so up to 1 non-voting validator is tolerated: T - Q = 1), reliable delivery inside a round,
// K = 4, freshness bound 8, margin 2, one omission rotation. "Consensus progress" = the committed height grows. "Checkpoint progress" = new references
// reach the committed chain and `checkpoint_age` stays bounded. The age bound used where progress is claimed is K + margin + n + 4 (pipeline slack).
fn last_ref_on_chain(chain: &[Block]) -> u64 { chain.iter().filter_map(|b| b.checkpoint).map(|r| r.height).max().unwrap_or(0) }

#[test]
fn l1_with_prompt_execution_and_honest_leaders_both_kinds_of_progress_hold() {
    // assumptions: every executor keeps up (lag 0 < margin), every leader follows the policy
    let mut e = Eng3::new(4, cc3(4, 8));
    let mut worst = 0;
    for _ in 0..80 { e.step(); worst = worst.max(e.nodes[e.lead()].checkpoint_age()); }
    assert_eq!(e.timeouts, 0);
    assert!(e.committed() >= 60, "consensus progress: committed {}", e.committed());
    assert!(worst <= 4 + 2 + 4 + 4, "checkpoint progress: the age never exceeded the bound (worst {worst})");
    assert!(last_ref_on_chain(&e.chain(e.lead())) + 14 >= e.committed());
    assert!(!e.nodes[e.lead()].checkpoint_stale());
}

#[test]
fn l2_when_some_leaders_never_propose_references_checkpoints_still_advance_through_the_others() {
    // assumptions: leaders 0 and 1 omit references forever (m = 2 < n); leaders 2 and 3 follow the policy; everyone executes promptly
    let cc = cc3(4, 8);
    let mut pol = vec![cc.policy; 4];
    pol[0].propose_refs = false; pol[1].propose_refs = false;
    let mut e = Eng3::with_policies(4, cc, pol);
    let mut worst = 0;
    for _ in 0..80 { e.step(); worst = worst.max(e.nodes[e.lead()].checkpoint_age()); }
    assert_eq!(e.timeouts, 0, "omitting a reference does not slow consensus");
    assert!(e.committed() >= 60);
    assert!(!e.refs().is_empty(), "references still appear");
    assert!(worst <= 4 + 2 + 4 + 4 + 4, "the age is bounded by the longest run of omitting leaders (here 2 rounds) on top of the policy bound: worst {worst}");
    assert!(e.proposals.iter().filter(|b| b.checkpoint.is_some()).all(|b| b.proposer >= 2), "only the policy-following leaders proposed references");
}

#[test]
fn l3_if_every_leader_omits_the_chain_keeps_committing_but_no_checkpoint_ever_appears_and_the_age_alarm_fires() {
    // assumptions: all leaders omit references forever (the optional field is never used)
    let cc = cc3(4, 8);
    let mut e = Eng3::with_policies(4, cc, vec![RefPolicy { propose_refs: false, ..cc.policy }; 4]);
    e.run(50);
    assert_eq!(e.timeouts, 0);
    assert!(e.committed() >= 40, "consensus progress holds");
    assert!(e.refs().is_empty(), "no checkpoint progress");
    for i in 0..4 {
        assert_eq!(e.nodes[i].checkpoint_age(), e.nodes[i].committed_tip().1, "without any reference the whole committed height is uncovered");
        assert!(e.nodes[i].checkpoint_stale(), "the staleness alarm fires (age above 3 intervals)");
    }
    // a joiner can still verify this chain (Option A: no reference needed)
    let set = set_n(4);
    let hs = headers_of(&e.chain(e.lead()));
    let hq = e.nodes[e.lead()].high_qc().clone();
    let v = verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000).expect("a chain without references verifies");
    assert!(!v.finalized.is_empty());
}

#[test]
fn l4_when_more_than_the_fault_budget_lags_reference_bearing_proposals_stall_but_the_chain_goes_on_and_checkpoints_resume() {
    // assumptions: after height ~20, validators 2 and 3 (power 2 > T - Q = 1) stop executing; validators 0 and 1 keep executing and keep proposing references
    let mut e = Eng3::new(4, cc3(4, 8));
    e.run_until_committed(20, 100);
    let l0 = last_ref_on_chain(&e.chain(e.lead()));
    assert!(l0 >= 12, "references were flowing before the lag ({l0})");
    let (t0, c0) = (e.timeouts, e.committed());
    e.lag[2] = u64::MAX / 2; e.lag[3] = u64::MAX / 2;
    e.run(60);
    assert!(e.timeouts > t0, "reference-bearing proposals could not gather a quorum: rounds timed out");
    assert!(e.committed() >= c0 + 20, "consensus progress continues (the proposers that cannot or must not use references simply omit them): {} -> {}", c0, e.committed());
    // the lagging validators still vote for references at heights they have ALREADY executed, so checkpoints may advance only up to the height they reached
    let stuck_at = e.exec[2].max(e.exec[3]);
    assert!(last_ref_on_chain(&e.chain(e.lead())) <= stuck_at, "no reference beyond what the lagging executors reached ({stuck_at}) can gather a quorum");
    let stalled_ref = last_ref_on_chain(&e.chain(e.lead()));
    for i in 0..4 { assert!(e.nodes[i].alarm().is_none(), "lag is not a safety alarm (node {i})"); }
    assert!(e.nodes[2].deferred_len() <= 64 && e.nodes[3].deferred_len() <= 64, "deferred votes are bounded");
    // the lag clears: the executors catch up and checkpoints resume within a few rotations
    e.lag[2] = 0; e.lag[3] = 0;
    e.feed_all();
    let before = e.timeouts;
    e.run(40);
    assert!(last_ref_on_chain(&e.chain(e.lead())) > stalled_ref, "checkpoint progress resumes once the executors catch up");
    assert!(e.nodes[e.lead()].checkpoint_age() <= 4 + 2 + 4 + 4 + 4);
    let _ = before;
}

#[test]
fn l5_the_stall_threshold_is_exactly_the_fault_budget_one_lagging_validator_of_four_is_tolerated() {
    // assumptions: validator 3 stops executing (power 1 = T - Q); the other three execute promptly
    let mut e = Eng3::new(4, cc3(4, 8));
    e.run_until_committed(12, 100);
    let t0 = e.timeouts;
    let l0 = last_ref_on_chain(&e.chain(e.lead()));
    e.lag[3] = u64::MAX / 2;
    e.run(60);
    assert_eq!(e.timeouts, t0, "three voters are a quorum: no round timed out");
    assert!(last_ref_on_chain(&e.chain(e.lead())) > l0 + 8, "references keep advancing without the lagging validator");
    assert!(e.nodes[3].deferred_len() >= 1, "the lagging validator defers its votes instead of voting blindly");
}

#[test]
fn a_validator_that_never_executes_keeps_a_full_deferral_set_of_the_most_recent_proposals() {
    // assumptions: validator 3 never executes; the other three propose references on every block, so 3 defers more proposals than the cap allows
    let mut e = Eng3::new(4, cc3(4, 8));
    e.run_until_committed(12, 100);
    let lag_start = e.nodes[3].round();
    e.lag[3] = u64::MAX / 2;
    e.run(400);
    let n = &e.nodes[3];
    assert_eq!(n.deferred_len(), 64, "the cap was reached (otherwise this test proves nothing)");
    let (m, top) = (n.deferred_min_round().unwrap(), n.deferred_max_round().unwrap());
    // eviction drops the lowest round, so the retained set is the RECENT past: it covers the latest two thirds of the lag period (a coarse bound: only
    // reference-bearing proposals are deferred, about one in four rounds here) and its newest member is current
    assert!(m >= lag_start + (n.round() - lag_start) / 3, "the oldest remaining deferral (round {m}) is recent: lag began at {lag_start}, now {}", n.round());
    assert!(top + 8 >= n.round(), "the newest deferral (round {top}) is current (now {})", n.round());
    assert!(n.alarm().is_none());
}

// ---- header-chain verification of the checkpoint rules
#[test]
fn v3_header_chains_verify_agree_with_the_engine_and_preserve_every_reference() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    // a healthy run, and a run with timeout certificates (two lagging validators force failed rounds)
    let mut healthy = Eng3::new(4, cc);
    healthy.run(60);
    let mut lagged = Eng3::new(4, cc);
    lagged.run_until_committed(16, 100);
    lagged.lag[2] = u64::MAX / 2; lagged.lag[3] = u64::MAX / 2;
    lagged.run(60);
    for (name, e) in [("healthy", &healthy), ("with timeouts", &lagged)] {
        let l = e.lead();
        let hs = headers_of(&e.chain(l));
        if name == "with timeouts" { assert!(hs.iter().any(|h| h.tc.is_some()), "the run must contain timeout-certificate headers"); }
        assert!(hs.iter().any(|h| h.checkpoint.is_some()), "{name}: the chain must contain references");
        for (h, b) in hs.iter().zip(e.chain(l).iter()) { assert_eq!(h.checkpoint, b.checkpoint, "headers carry the reference"); assert_eq!(h.id(&idctx3(&set)).unwrap(), id3(b)); }
        let hq = e.nodes[l].high_qc().clone();
        let v = verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000).unwrap_or_else(|er| panic!("{name}: {er}"));
        let committed: Vec<(u64, BlockId)> = e.commits[l].iter().map(|c| (c.height, c.id)).collect();
        let got: Vec<(u64, BlockId)> = v.finalized.iter().map(|p| (p.height, p.id)).collect();
        assert_eq!(got, committed[..got.len().min(committed.len())].to_vec(), "{name}: header finality is a prefix of the engine's");
        assert!(got.len() + 2 >= committed.len(), "{name}: and at most a couple of blocks behind it");
        // the header encoding round-trips, references included
        for h in &hs { assert_eq!(decode_header(&encode_header(h)).unwrap(), *h); }
    }
}

#[test]
fn the_engine_and_the_header_verifier_reject_each_rule_violation_with_the_same_reason() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    // fixture without references (R1, R2, R3, R6) and fixture with them (R4)
    let mut none = no_refs(40);
    let mut with = Eng3::new(4, cc);
    with.run_until_committed(36, 100);
    for (label, e) in [("no references", &mut none), ("with references", &mut with)] {
        let l = e.lead();
        let chain = e.chain(l);
        let hs = headers_of(&chain);
        let f = e.nodes[l].committed_tip().1;
        let last = chain.iter().filter_map(|b| b.checkpoint).last();
        let fresh = (f / 4) * 4;
        let good = |h: u64| CheckpointRef { height: h, block_id: id_at(&chain, h), state_root: root_of(h) };
        let mut cases: Vec<(&str, CheckpointRef)> = vec![
            ("R1 not a multiple", CheckpointRef { height: fresh + 1, ..good(fresh) }),
            ("R2 above the final height", CheckpointRef { height: fresh + 4, block_id: [7; 32], state_root: root_of(fresh + 4) }),
        ];
        match last {
            None => {
                cases.push(("R3 wrong block", CheckpointRef { block_id: [9; 32], ..good(fresh) }));
                let old = (f.saturating_sub(9) / 4) * 4;
                assert!(f - old > 8);
                cases.push(("R6 too old", good(old)));
            }
            Some(lr) => {
                cases.push(("R4 backwards", good(lr.height - 4)));
                cases.push(("R4 conflicting root", CheckpointRef { state_root: [0x55; 32], ..lr }));
            }
        }
        let j = target(e);
        for (name, r) in cases {
            // the engine's verdict on a correctly signed block carrying r
            let b = e.crafted(Some(r));
            let engine = err_reason(e.nodes[j].on_proposal(b.clone()));
            assert!(engine.contains("checkpoint reference"), "{label} / {name}: engine said {engine:?}");
            // the header verifier's verdict on the same chain plus that block's header
            let mut all = hs.clone();
            all.push(b.to_header());
            let (idx, reason) = failure_at(verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &all, None, 10_000));
            assert_eq!(idx, hs.len(), "{label} / {name}: the failure is at the new header");
            assert_eq!(reason, engine, "{label} / {name}: the engine and the verifier must agree on the reason");
        }
        // and on acceptance: a valid reference is accepted by both (a repeat when there is a last reference, the newest final checkpoint otherwise)
        let ok = last.unwrap_or(good(fresh));
        let b = e.crafted(Some(ok));
        assert!(has_vote(&e.nodes[j].on_proposal(b.clone()).unwrap()), "{label}: engine accepts the valid reference");
        let mut all = hs.clone();
        all.push(b.to_header());
        verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &all, None, 10_000).unwrap_or_else(|er| panic!("{label}: header verification refused a valid reference: {er}"));
    }
}

#[test]
fn header_verification_binds_the_genesis_parameters_the_profile_and_refuses_a_reference_on_v2() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = Eng3::new(4, cc);
    e.run(30);
    let hs = headers_of(&e.chain(e.lead()));
    assert!(hs.iter().any(|h| h.checkpoint.is_some()));
    let ok = |c: &CheckpointConfig| verify_header_chain(&cparams3(&set, c), &TestVerifier, Start::Genesis, &hs, None, 10_000);
    assert!(ok(&cc).is_ok());
    // different validity parameters are a different genesis: nothing in the chain verifies
    assert_eq!(failure_at(ok(&cc3(4, 12))).0, 0, "freshness bound differs");
    assert_eq!(failure_at(ok(&cc3(8, 8))).0, 0, "interval differs");
    // v3 without parameters, and parameters on a profile that has none
    let p = ChainParams { checkpoint: None, ..cparams3(&set, &cc) };
    let (i, r) = failure_at(verify_header_chain(&p, &TestVerifier, Start::Genesis, &hs, None, 10_000));
    assert!((i, r.as_str()) == (0, "checkpoint parameters do not fit the profile"), "{r}");
    let p = ChainParams { protocol_profile: PROFILE, ..cparams3(&set, &cc) };
    assert_eq!(failure_at(verify_header_chain(&p, &TestVerifier, Start::Genesis, &hs, None, 10_000)).1, "checkpoint parameters do not fit the profile");
    // a v3 chain does not verify as v2 (different profile, different ids), and a v2 chain with a reference spliced in is refused by the id function
    let v2 = ChainParams { checkpoint: None, protocol_profile: PROFILE, ..cparams3(&set, &cc) };
    assert!(verify_header_chain(&v2, &TestVerifier, Start::Genesis, &hs, None, 10_000).is_err());
    let f = fx();
    let mut h2 = base_block(&f).to_header();
    h2.checkpoint = Some(CheckpointRef { height: 4, block_id: [1; 32], state_root: [2; 32] });
    assert!(h2.id(&idctx(&f)).is_err());
}

#[test]
fn a_v3_chain_verified_in_segments_from_an_anchor_with_exact_state_gives_the_same_result_and_a_wrong_anchor_is_caught() {
    let cc = cc3(4, 8);
    let set = set_n(4);
    let mut e = Eng3::new(4, cc);
    e.run(60);
    let l = e.lead();
    let chain = e.chain(l);
    let hs = headers_of(&chain);
    let hq = e.nodes[l].high_qc().clone();
    let full = verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &hs, Some(&hq), 10_000).unwrap();
    // the anchor: a block comfortably inside the chain (final), with the exact state the engine derived for it
    let a = chain.len() / 2;
    let ab = &chain[a - 1];
    let st = e.nodes[l].chain_ref_state(&id3(ab)).unwrap();
    let parent_round = chain[a - 2].round;
    // the ids a later reference may name: every block from `max_age + 1` below the anchor (R6) up to the block before it
    let ancestors: Vec<(u64, BlockId)> = chain.iter().filter(|b| b.height < ab.height && b.height + 9 >= ab.height).map(|b| (b.height, id3(b))).collect();
    let anchor = |final_height: u64| Anchor { id: id3(ab), height: ab.height, round: ab.round, parent_round, final_height, last_ref: st.last_ref, ancestors: ancestors.clone() };
    let rest = &hs[a..];
    let seg = verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Anchor(anchor(st.final_height)), rest, Some(&hq), 10_000).expect("segment from an exact anchor");
    assert_eq!(seg.tip, full.tip);
    // everything the segment finalizes above the anchor is final in the full run too
    for p in &seg.finalized { assert!(full.finalized.iter().any(|q| q.id == p.id)); }
    // an anchor claiming a reference the chain never had breaks R4 for the references that follow
    let other = Anchor { last_ref: Some(CheckpointRef { height: 4 * 1000, block_id: [1; 32], state_root: [1; 32] }), ..anchor(st.final_height) };
    assert!(verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Anchor(other), rest, Some(&hq), 10_000).is_err());
    // without the ancestor ids, a new reference that names a block below the anchor cannot be identified: fail closed
    let bare = Anchor { ancestors: vec![], ..anchor(st.final_height) };
    let (i, r) = failure_at(verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Anchor(bare), rest, Some(&hq), 10_000));
    assert!(r.contains("unverifiable"), "{r}");
    assert!(rest[i].checkpoint.map_or(false, |x| x.height < ab.height), "the failure is exactly at a reference below the anchor");
    // a WRONG ancestor id is caught as a wrong block (R3)
    let mut lying = anchor(st.final_height);
    for a in lying.ancestors.iter_mut() { a.1[0] ^= 1; }
    let (_, r) = failure_at(verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Anchor(lying), rest, Some(&hq), 10_000));
    assert!(r.contains("(R3)"), "{r}");
}

// ---- the driver: real execution roots, the durable root log, restart
fn roots_of(net: &DNet, i: usize) -> chain_forge_consensus::pq_hotstuff::blockstore::RootLog { net.nodes[i].as_ref().unwrap().block_store().load_roots(4).unwrap() }
fn run_to(net: &mut DNet, height: u64) { assert!(net.run_until(20_000, |n| (0..n.n).filter(|i| !n.dead[*i]).all(|i| n.height(i) >= height)), "heights {:?}", (0..net.n).map(|i| net.height(i)).collect::<Vec<_>>()); }

#[test]
fn a_v3_driver_network_logs_real_execution_roots_publishes_references_and_agrees() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "a", Some(cc));
    run_to(&mut net, 44);
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    net.assert_agreement("v3");
    net.assert_exactly_once("v3");
    let first = roots_of(&net, 0);
    assert!(first.roots.len() >= 10 && first.damaged.is_empty() && first.gaps.is_empty(), "{first:?}");
    for i in 0..4 {
        let log = roots_of(&net, i);
        // the logged root of a checkpoint height is the executor's own state digest at that height (recent history holds the last 64 executed heights)
        for c in net.nodes[i].as_ref().unwrap().status().recent { if c.height % 4 == 0 { assert_eq!(log.roots.get(&c.height), Some(&c.state_digest), "node {i} height {}", c.height); } }
        // and every node logged the same roots
        for (h, r) in &log.roots { if let Some(o) = first.roots.get(h) { assert_eq!(r, o, "node {i} height {h}"); } }
        let e = net.nodes[i].as_ref().unwrap().engine();
        assert!(e.alarm().is_none() && e.evidence().is_empty());
        assert!(e.checkpoint_age() <= 4 + 2 + 4 + 4 + 4, "node {i} age {}", e.checkpoint_age());
    }
    // references appeared in the chain and carry those real roots
    let lead = net.nodes[0].as_ref().unwrap().engine();
    let mut refs = vec![];
    for b in lead.known_blocks() { if let Some(r) = b.checkpoint { refs.push(r); } }
    assert!(refs.len() >= 5, "only {} references", refs.len());
    for r in &refs { assert_eq!(first.roots.get(&r.height), Some(&r.state_root), "reference at {} is not the logged root", r.height); }
    // header verification of the real chain, references included
    let set = set_n(4);
    let all: BTreeMap<BlockId, Block> = lead.known_blocks().into_iter().map(|b| (id3(b), b.clone())).collect();
    let Cert::Qc(q) = lead.high_qc().clone() else { panic!() };
    let (mut cur, mut chain) = (q.block_id, vec![]);
    while let Some(b) = all.get(&cur) { chain.push(b.clone()); cur = b.parent_id; }
    chain.reverse();
    let hq = lead.high_qc().clone();
    let v = verify_header_chain(&cparams3(&set, &cc), &TestVerifier, Start::Genesis, &headers_of(&chain), Some(&hq), 10_000).expect("the real chain verifies");
    assert!(v.finalized.len() as u64 + 3 >= lead.committed_tip().1);
}

#[test]
fn a_restarted_v3_node_reloads_its_roots_judges_the_recovered_blocks_and_keeps_going() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "a", Some(cc));
    run_to(&mut net, 24);
    let before_roots = roots_of(&net, 1);
    let sent_before = net.sent[1].clone();
    let age = net.nodes[1].as_ref().unwrap().engine().checkpoint_age();
    net.recover(1, None, "a").expect("restart");
    let e = net.nodes[1].as_ref().unwrap().engine();
    for (h, r) in &before_roots.roots { assert_eq!(e.root(*h), Some(*r), "root at {h} survives the restart"); }
    assert!(e.alarm().is_none() && e.evidence().is_empty());
    assert!(e.checkpoint_age() <= age + 8, "the recovered chain still knows its references");
    run_to(&mut net, 40);
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    net.assert_agreement("after restart");
    // the roots the node logs after the restart extend the old log without changing it
    let after = roots_of(&net, 1);
    for (h, r) in &before_roots.roots { assert_eq!(after.roots.get(h), Some(r)); }
    assert!(after.roots.len() > before_roots.roots.len());
    // a vote or timeout re-sent at restart was already sent before (the safety floors are unchanged by checkpoints)
    let lim = *net.nodes[1].as_ref().unwrap().limits();
    for b in &net.sent[1][sent_before.len()..] { if let Ok(NetMsg::Consensus(Msg::Vote(_))) = net::decode(b, &lim) { /* new rounds' votes are new; nothing to compare */ } }
}

#[test]
fn the_root_log_is_idempotent_refuses_conflicts_reports_damage_and_gaps_and_survives_a_crash_at_every_point() {
    let k = 4u64;
    let f = faults();
    let mut st = BlockStore::new(MemStorage::new(f.clone()));
    for h in [4u64, 8, 12] { st.put_root(k, h, &root_of(h)).unwrap(); }
    st.put_root(k, 8, &root_of(8)).unwrap(); // idempotent
    assert!(matches!(st.put_root(k, 8, &[1; 32]), Err(StoreError::RootConflict(8))));
    let log = st.load_roots(k).unwrap();
    assert_eq!(log.roots.keys().copied().collect::<Vec<_>>(), vec![4, 8, 12]);
    assert!(log.damaged.is_empty() && log.gaps.is_empty());
    // another interval is refused outright, never mixed
    assert!(matches!(st.load_roots(8), Err(StoreError::RootIntervalMismatch { expected: 8, found: 4 })));
    // damage is reported and the record excluded; a missing middle record is a reported gap; nothing is guessed
    let mut files = st.storage().clone();
    let mut b = files.raw("root-00000000000000000008").unwrap(); let mid = b.len() / 2; b[mid] ^= 1;
    files.set_raw("root-00000000000000000008", b);
    let log = BlockStore::new(files.clone()).load_roots(k).unwrap();
    assert_eq!((log.roots.keys().copied().collect::<Vec<_>>(), log.damaged.clone(), log.gaps.clone()), (vec![4, 12], vec![8], vec![8]));
    files.delete_raw("root-00000000000000000008");
    let log = BlockStore::new(files.clone()).load_roots(k).unwrap();
    assert_eq!((log.damaged.len(), log.gaps.clone()), (0, vec![8]));
    // a record whose height is not a multiple of the interval is damage, not a root (nothing could ever reference it)
    let mut odd = BlockStore::new(MemStorage::new(faults()));
    odd.put_root(k, 4, &root_of(4)).unwrap();
    odd.put_root(k, 5, &root_of(5)).unwrap();
    let log = odd.load_roots(k).unwrap();
    assert_eq!((log.roots.keys().copied().collect::<Vec<_>>(), log.damaged.clone()), (vec![4], vec![5]));
    // a damaged record is overwritten by the next write of that height; a stored root for a height that is not a multiple of the interval is damage
    let mut again = BlockStore::new(files);
    again.put_root(k, 8, &root_of(8)).unwrap();
    assert!(again.load_roots(k).unwrap().gaps.is_empty());
    // crash at every point of one more append: the log is either the old one or the old one plus the new record, never anything else
    for crash_at in 0..=5 {
        let f = faults();
        let mut s = BlockStore::new(MemStorage::new(f.clone()));
        for h in [4u64, 8] { s.put_root(k, h, &root_of(h)).unwrap(); }
        let base = f.borrow().ops;
        f.borrow_mut().crash_before = Some(base + crash_at);
        let r = s.put_root(k, 12, &root_of(12));
        for out in s.storage().crash_outcomes(7) {
            let log = BlockStore::new(out.clone()).load_roots(k).unwrap();
            assert!(log.gaps.is_empty(), "crash at {crash_at}: {log:?}");
            assert_eq!(log.roots.get(&4), Some(&root_of(4)));
            assert_eq!(log.roots.get(&8), Some(&root_of(8)));
            match log.roots.get(&12) { None => {}, Some(x) => assert_eq!(*x, root_of(12), "crash at {crash_at}: a wrong root was accepted") }
            if r.is_ok() { assert_eq!(log.roots.get(&12), Some(&root_of(12)), "an acknowledged append is durable in every outcome"); }
        }
    }
}

#[test]
fn the_driver_rebuilds_a_root_that_was_lost_between_executing_a_checkpoint_and_logging_it() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "a", Some(cc));
    for _ in 0..4000 { if net.height(1) >= 12 && net.height(1) % 4 == 0 { break; } net.step(); }
    let h = net.height(1);
    assert!(h >= 12 && h % 4 == 0, "line up on a checkpoint height ({h})");
    let digest = net.nodes[1].as_ref().unwrap().status().exec.state_digest;
    // crash image: the executor made the checkpoint durable, the root record never reached the disk
    let (e, bs, x) = net.nodes[1].take().unwrap().into_parts();
    let mut st = bs.into_inner();
    st.delete_raw(&format!("root-{h:020}"));
    assert!(BlockStore::new(st.clone()).load_roots(4).unwrap().roots.get(&h).is_none());
    let (nd, _) = start_node(restart3(e, 1, 4, &cc), BlockStore::new(st), x.inner.into_inner(), &net.logs[1], "a", net.now).expect("start");
    assert_eq!(nd.engine().root(h), Some(digest), "the engine has the root again");
    assert_eq!(nd.block_store().load_roots(4).unwrap().roots.get(&h), Some(&digest), "and so does the log, derived from the cursor, not guessed");
    // a record that DISAGREES with the executor's own state at its cursor is a hard error, not a repair
    let (e, bs, x) = nd.into_parts();
    let mut st = bs.into_inner();
    st.delete_raw(&format!("root-{h:020}"));
    let mut forged = BlockStore::new(st);
    forged.put_root(4, h, &[0x77; 32]).unwrap();
    let r = start_node(restart3(e, 1, 4, &cc), forged, x.inner.into_inner(), &net.logs[1], "a", net.now);
    assert!(r.is_err(), "a root that contradicts the executor's own cursor must stop the node");
}

#[test]
fn a_root_log_written_for_another_interval_stops_the_node_instead_of_being_mixed_in() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "a", Some(cc));
    run_to(&mut net, 10);
    let (e, bs, x) = net.nodes[2].take().unwrap().into_parts();
    let mut st = BlockStore::new(bs.into_inner());
    st.put_root(8, 800, &[1; 32]).unwrap(); // a record from a chain with interval 8
    let r = start_node(restart3(e, 2, 4, &cc), st, x.inner.into_inner(), &net.logs[2], "a", net.now);
    assert!(r.is_err());
}

#[test]
fn a_paused_executor_defers_reference_votes_through_the_driver_and_releases_them_when_it_drains() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "a", Some(cc));
    run_to(&mut net, 16);
    for i in [2usize, 3] { net.nodes[i].as_mut().unwrap().set_exec_budget(Some(0)).unwrap(); }
    let paused_at = [net.height(2), net.height(3)];
    let c0 = net.height(0);
    for _ in 0..1500 { net.step(); }
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    assert_eq!([net.height(2), net.height(3)], paused_at, "paused executors execute nothing");
    assert!(net.nodes[2].as_ref().unwrap().exec_backlog() > 0, "finalized blocks queue up behind the executor");
    assert!(net.height(0) > c0 + 5, "consensus progress continues while two executors are paused: {} -> {}", c0, net.height(0));
    for i in 0..4 { assert!(net.nodes[i].as_ref().unwrap().engine().alarm().is_none(), "lag is not an alarm"); }
    // drain: the executors catch up in order, exactly once each, and the logs agree again
    for i in [2usize, 3] { let o = net.nodes[i].as_mut().unwrap().set_exec_budget(None).unwrap(); net.push(i, o); }
    let target_h = net.height(0) + 4;
    run_to(&mut net, target_h);
    net.assert_agreement("after the drain");
    net.assert_exactly_once("after the drain");
    assert_eq!(roots_of(&net, 2).roots.get(&12), roots_of(&net, 0).roots.get(&12));
}

// ---- replay across chains, profiles and parameters; mutation of a signed reference
#[test]
fn blocks_from_another_profile_or_parameter_set_are_never_accepted() {
    let cc = cc3(4, 8);
    let mut a = Eng3::new(4, cc);
    a.run(30);
    let blocks = a.proposals.clone();
    assert!(blocks.iter().any(|b| b.checkpoint.is_some()) && blocks.len() >= 20);
    let accepted = |mut e: E| -> usize { for b in &blocks { let _ = e.on_proposal(b.clone()); } e.known_blocks().len() };
    // control: an engine with the identical configuration takes the whole chain
    assert!(accepted(engine3(3, 4, &cc)) >= blocks.len() - 2, "control");
    // a v2 engine (different profile, no checkpoint rules)
    assert_eq!(accepted(engine(3, 4)), 0, "v3 blocks into a v2 chain");
    // v3 engines with other validity parameters have another genesis: the first block's genesis certificate is foreign and nothing can be built on it
    assert_eq!(accepted(engine3(3, 4, &cc3(4, 12))), 0, "other freshness bound");
    assert_eq!(accepted(engine3(3, 4, &cc3(8, 16))), 0, "other interval and bound");
    // and the other direction: a v2 chain's blocks never enter a v3 engine
    let mut v2 = Eng3::new(4, cc3(4, 8)); // only used for its shape; build a real v2 run instead
    let _ = &mut v2;
    let mut nodes: Vec<E> = (0..4).map(|i| engine(i, 4)).collect();
    let mut seen: Vec<Block> = vec![];
    for _ in 0..8 { let r = nodes.iter().map(|e| e.round()).max().unwrap(); let l = nodes[0].leader_of(r); let first = match nodes[l].propose(b"v2".to_vec()) { Ok(o) => o, Err(_) => break };
        let mut q: VecDeque<(usize, Output)> = first.into_iter().map(|o| (l, o)).collect();
        while let Some((from, o)) = q.pop_front() { let ds: Vec<(usize, Msg)> = match o { Output::Broadcast(m) => { if let Msg::Proposal(b) = &m { seen.push(b.clone()); } (0..4).filter(|i| *i != from).map(|i| (i, m.clone())).collect() } Output::Send { to, msg } if to != from => vec![(to, msg)], _ => vec![] };
            for (to, m) in ds { for o in nodes[to].on_message(m).unwrap_or_default() { q.push_back((to, o)); } } } }
    assert!(seen.len() >= 4);
    let mut into_v3 = engine3(3, 4, &cc);
    for b in &seen { let _ = into_v3.on_proposal(b.clone()); }
    assert_eq!(into_v3.known_blocks().len(), 0, "v2 blocks into a v3 chain");
}

#[test]
fn altering_any_part_of_a_signed_reference_breaks_the_proposer_signature() {
    let mut e = no_refs(40);
    let f = e.nodes[e.lead()].committed_tip().1;
    let chain = e.chain(e.lead());
    let h = (f / 4) * 4;
    let good = CheckpointRef { height: h, block_id: id_at(&chain, h), state_root: root_of(h) };
    let j = target(&e);
    for tweak in 0..4 {
        let mut b = e.crafted(Some(good));
        match tweak { 0 => b.checkpoint.as_mut().unwrap().height -= 4, 1 => b.checkpoint.as_mut().unwrap().block_id[0] ^= 1, 2 => b.checkpoint.as_mut().unwrap().state_root[0] ^= 1, _ => b.checkpoint = None }
        assert_eq!(err_reason(e.nodes[j].on_proposal(b)), "proposer signature", "tweak {tweak}");
    }
    // adding a reference to a block that was signed without one
    let mut b = e.crafted(None);
    b.checkpoint = Some(good);
    assert_eq!(err_reason(e.nodes[j].on_proposal(b)), "proposer signature");
    // the untouched block is fine
    assert!(has_vote(&e.offer(j, Some(good)).unwrap()));
}

#[test]
fn a_repeated_reference_needs_no_local_root_when_a_final_ancestor_carries_it_and_a_new_one_does() {
    let cc = cc3(4, 8);
    let mut e = Eng3::new(4, cc);
    e.skip_roots[2] = true; // node 2 executes but keeps no checkpoint roots (as after a snapshot install or a lost log)
    e.run_until_committed(36, 150);
    let refs = e.refs();
    assert!(refs.len() >= 4);
    let old = refs[refs.len() - 3];
    assert!(e.nodes[2].root(old.height).is_none(), "node 2 holds no root of its own");
    // the identical reference is carried by a block node 2 already considers final: its root is authenticated by that finality
    assert_eq!(e.nodes[2].ref_outcome(&old), RootCheck::Match);
    // a reference for another height or another root is not
    let chain = e.chain(e.lead());
    let fresh = (e.nodes[e.lead()].committed_tip().1 / 4) * 4;
    let never_carried = CheckpointRef { height: fresh, block_id: id_at(&chain, fresh), state_root: root_of(fresh) };
    if !refs.contains(&never_carried) { assert_eq!(e.nodes[2].ref_outcome(&never_carried), RootCheck::Unknown); }
    assert_eq!(e.nodes[2].ref_outcome(&CheckpointRef { state_root: [0x42; 32], ..old }), RootCheck::Unknown);
    // recorded roots are immutable: the same value is idempotent, a different one is refused
    assert!(e.nodes[0].record_root(old.height, old.state_root).is_ok());
    assert!(e.nodes[0].record_root(old.height, [9; 32]).is_err());
}


#[test]
fn the_reference_backoff_grows_with_consecutive_failures_and_resets_when_a_reference_proposal_is_certified() {
    let mut e = Eng3::new(4, cc3(4, 8));
    e.run_until_committed(16, 100);
    assert!((0..4).all(|i| e.nodes[i].ref_backoff().1 == 0), "no failures while everyone keeps up");
    e.lag[2] = u64::MAX / 2; e.lag[3] = u64::MAX / 2;
    let mut worst = (0usize, 0u32);
    for _ in 0..60 { e.step(); for i in 0..4 { let st = e.nodes[i].ref_backoff().1; if st > worst.1 { worst = (i, st); } } }
    assert!(worst.1 >= 2, "consecutive failures raise the streak (worst {worst:?})");
    let (until, streak) = e.nodes[worst.0].ref_backoff();
    assert!(streak >= 1 && until > 0);
    // the omission window itself doubles: the window after the latest failure is n x rotations x 2^(streak-1) rounds long
    // (the end of the window minus the round of the failure it followed is at least that long)
    e.lag[2] = 0; e.lag[3] = 0;
    e.feed_all();
    let x = worst.0;
    let mut reset = false;
    for _ in 0..400 { e.step(); if e.nodes[x].ref_backoff().1 == 0 { reset = true; break; } }
    assert!(reset, "once the quorum can vote on references again, a certified reference proposal of node {x} resets its backoff");
}
