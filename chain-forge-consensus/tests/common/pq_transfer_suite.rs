// ============================================================================================================================
// S-1: isolated sans-IO snapshot-transfer requester and provider (in-memory transport, malicious-provider simulator). DISABLED: nothing in a node calls this, the
// network decoder still rejects kinds 7 to 14, installation over the network and pruning stay off. The applications here are the DEVNET-INTERIM hash chain of
// opaque payloads (not Qattice state). Policy under test: genesis-anchored authentication only; ANY peer may serve; NO provider-agreement threshold; the seed
// evidence is durable BEFORE the application generation is published.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::recovery::transfer::{Authenticator, EvidenceSink, InstallSink, Out, Phase as TPhase, Provider, ProviderStore, Requester, RequesterLimits, TransferConfigError};
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
use std::cell::RefCell as TRefCell;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode { Honest, BlackHole, ForgedHeaders, FlippedChunk, WrongState, HugeManifest, NoReplyToChunks }

/// What every simulated peer can read: the donor's chain and snapshots, built from a real driver network.
struct Donor { headers: Vec<PayloadFreeBlock>, ids: Vec<BlockId>, hq: Cert, snaps: BTreeMap<[u8; 32], (Manifest, Vec<Vec<u8>>)>, by_ref: BTreeMap<u64, [u8; 32]>, refs: Vec<CheckpointRef>, genesis_id: BlockId }
struct Peer { d: Arc<Donor>, mode: Mode }

impl ProviderStore for Peer {
    fn headers_after(&self, after: &BlockId, max: u32) -> HeaderBody {
        let d = &self.d;
        let start = if *after == d.genesis_id { 0 } else { match d.ids.iter().position(|i| i == after) { Some(p) => p + 1, None => return HeaderBody::NotFound } };
        let end = (start + max as usize).min(d.headers.len());
        if start >= d.headers.len() { return HeaderBody::AtTip { tip_height: d.headers.last().map_or(0, |h| h.height) }; }
        let mut headers = d.headers[start..end].to_vec();
        if self.mode == Mode::ForgedHeaders { let m = headers.len() / 2; headers[m].payload_hash[0] ^= 1; }
        HeaderBody::Ok { headers, final_qc: if end == d.headers.len() { Some(d.hq.clone()) } else { None }, tip_height: d.headers.last().map_or(0, |h| h.height) }
    }
    fn manifest(&self, cref: &CheckpointRef) -> Option<Manifest> {
        let d = &self.d;
        match self.mode {
            Mode::HugeManifest => { let (m, _) = d.snaps.get(d.by_ref.get(&cref.height)?)?; let mut h = m.clone(); h.chunk_size = 262_144; h.chunk_count = 800; h.total_bytes = 262_144 * 800; h.chunk_hashes = vec![[0; 32]; 800]; h.snapshot_id = h.compute_id(&GENESIS_HASH, cref); Some(h) }
            Mode::WrongState => {
                // a self-consistent manifest, with a correct id for the authenticated reference, over the state of an EARLIER height
                let lower = d.refs.iter().find(|r| r.height < cref.height).copied()?;
                let (m, chunks) = d.snaps.get(d.by_ref.get(&lower.height)?)?;
                let _ = chunks; let mut w = m.clone(); w.snapshot_id = w.compute_id(&GENESIS_HASH, cref); Some(w)
            }
            _ => Some(d.snaps.get(d.by_ref.get(&cref.height)?)?.0.clone()),
        }
    }
    fn chunk(&self, sid: &[u8; 32], index: u32) -> Option<Vec<u8>> {
        if self.mode == Mode::NoReplyToChunks { return None; }
        let d = &self.d;
        let found = d.snaps.get(sid).or_else(|| if self.mode == Mode::WrongState { d.snaps.values().find(|(m, _)| m.compute_id(&GENESIS_HASH, d.refs.last().unwrap()) == *sid || true) } else { None });
        let (_, chunks) = if self.mode == Mode::WrongState { d.snaps.get(d.by_ref.get(&d.refs.iter().find(|r| r.height < d.refs.last().unwrap().height)?.height)?)? } else { found? };
        let mut c = chunks.get(index as usize)?.clone();
        if self.mode == Mode::FlippedChunk { c[0] ^= 1; }
        Some(c)
    }
}

struct TAuth { e: E, set: EpochSet }
impl Authenticator for TAuth {
    fn authenticate(&self, ev: &SeedEvidence) -> Result<CheckpointSeed, String> { self.e.authenticate_evidence(ev).map_err(|e| e.to_string()) }
    fn header_id(&self, h: &PayloadFreeBlock) -> Option<BlockId> { h.id(&idctx3(&self.set)).ok() }
}
#[derive(Default)]
struct RecEv { saved: Rc<TRefCell<Vec<SeedEvidence>>>, fail: bool }
impl EvidenceSink for RecEv {
    fn persist(&mut self, ev: &SeedEvidence) -> Result<(), String> { if self.fail { return Err("disk full".into()); } self.saved.borrow_mut().push(ev.clone()); Ok(()) }
}
type Inst = Installer<MemTreeFs, InterimShadow>;

/// Built once per test process (a real driver network is slow in a debug build) and shared read-only by every test.
fn donor() -> Arc<Donor> { static D: OnceLock<Arc<Donor>> = OnceLock::new(); D.get_or_init(|| donor_net().1).clone() }
fn donor_net() -> (DNet, Arc<Donor>) {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "T", Some(cc.clone()));
    run_to(&mut net, 36);
    let d0 = net.nodes[0].as_ref().unwrap();
    let chain = drv_chain(d0);
    let set = set_n(4);
    let headers = headers_of(&chain);
    let ids: Vec<BlockId> = headers.iter().map(|h| h.id(&idctx3(&set)).unwrap()).collect();
    let (_, _) = evidence_from(d0, 0);
    let mut refs: Vec<CheckpointRef> = vec![];
    for b in &chain { if let Some(r) = b.checkpoint { if refs.last() != Some(&r) { refs.push(r); } } }
    let hq = d0.engine().high_qc().clone();
    let mut snaps = BTreeMap::new(); let mut by_ref = BTreeMap::new();
    // snapshots of every reference the donor could have retained (the interim application state at that height)
    for r in &refs {
        let app = snapshot_app(d0, r.height);
        let bytes = app.raw("app-state").unwrap();
        let (m, chunks) = manifest_for(&bytes, 64, r);
        by_ref.insert(r.height, m.snapshot_id); snaps.insert(m.snapshot_id, (m, chunks));
    }
   
    let genesis_id = d0.engine().genesis_id();
    (net, Arc::new(Donor { headers, ids, hq, snaps, by_ref, refs, genesis_id }))
}
fn tlim() -> RequesterLimits { RequesterLimits { headers_per_request: 16, max_accumulated_headers: 10_000, max_staging_bytes: 1 << 20, max_outstanding: 4, per_peer_outstanding: 2, request_timeout_ms: 200, overall_timeout_ms: 120_000 } }
fn serve_cfg() -> ServeConfig { ServeConfig { limit: net::MAX_MESSAGE_SIZE, burst: 2 * net::MAX_MESSAGE_SIZE, refill_per_s: net::MAX_MESSAGE_SIZE / 2, aggregate_per_s: net::MAX_MESSAGE_SIZE * 8, max_concurrent: 16, per_peer_outstanding: 8, min_spacing_ms: 0, chunk_size: 64 } }
fn provider(d: &Arc<Donor>, mode: Mode, now: u64) -> Provider<Peer> { Provider::new(Peer { d: d.clone(), mode }, ServeGate::new(serve_cfg(), now).unwrap(), rl()) }

enum Node { Serve(Provider<Peer>), BlackHole }
struct Rig { req: Requester<TAuth, Inst, RecEv>, peers: Vec<Node>, now: u64, saved: Rc<TRefCell<Vec<SeedEvidence>>>, max_out: usize, sent: Vec<(usize, RecoveryMsg)>, per_peer_max: usize }
fn rig_with(d: &Arc<Donor>, modes: &[Mode], lim: RequesterLimits, fail_evidence: bool) -> Rig {
    let cc = cc3(4, 8);
    let e = engine3(0, 4, &cc);
    let gid = e.genesis_id();
    let saved: Rc<TRefCell<Vec<SeedEvidence>>> = Default::default();
    let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs);
    let mut inst: Inst = Installer::new(fs, interim(), GENESIS_HASH, rl(), Box::new(|c: &Cert| if matches!(c, Cert::Qc(_)) { Ok(()) } else { Err("not a QC".into()) })).unwrap();
    inst.start().unwrap();
    let mut req = Requester::new(TAuth { e, set: set_n(4) }, inst, RecEv { saved: saved.clone(), fail: fail_evidence }, gid, GENESIS_HASH, rl(), lim, 0).expect("limits");
    let mut peers = vec![];
    for (i, m) in modes.iter().enumerate() { req.add_peer(i); peers.push(if *m == Mode::BlackHole { Node::BlackHole } else { Node::Serve(provider(d, *m, 1)) }); }
    Rig { req, peers, now: 1, saved, max_out: 0, sent: vec![], per_peer_max: 0 }
}
fn rig(d: &Arc<Donor>, modes: &[Mode]) -> Rig { rig_with(d, modes, tlim(), false) }

impl Rig {
    /// Deliver every request through the real codec to the peer it names and every reply back, until nothing is left to send.
    fn settle(&mut self, mut outs: Vec<Out>) {
        let mut q: VecDeque<Out> = outs.drain(..).collect();
        let mut guard = 0;
        while let Some(o) = q.pop_front() {
            guard += 1; assert!(guard < 3_000, "message storm: phase {:?} stats {:?} last {:?}", self.req.phase(), self.req.stats, self.sent.last());
            self.max_out = self.max_out.max(self.req.outstanding());
            self.per_peer_max = self.per_peer_max.max(self.req.outstanding_for(o.peer));
            let bytes = rcodec::encode(&o.msg).expect("encode"); let m = rcodec::decode(&bytes, &rl()).expect("decode");
            self.sent.push((o.peer, m.clone()));
            let reply = match &mut self.peers[o.peer] { Node::BlackHole => None, Node::Serve(p) => p.handle(o.peer, &m, self.now) };
            if let Some(r) = reply {
                let b = rcodec::encode(&r).expect("encode reply"); assert!(b.len() as u64 <= rl().max_len(r.kind()).unwrap(), "a provider reply the peer's decoder would refuse");
                // bytes the decoder refuses never reach the requester (the network layer drops them), so they are simply not delivered
                if let Ok(r) = rcodec::decode(&b, &rl()) { q.extend(self.req.on_message(o.peer, &r, self.now)); }
            }
        }
    }
    fn run(&mut self, max_ticks: usize) {
        let first = self.req.start(self.now); self.settle(first);
        for _ in 0..max_ticks {
            if self.req.is_finished() { break; }
            self.now += 50;
            let outs = self.req.on_tick(self.now); self.settle(outs);
        }
    }
    fn done(&self) -> Option<InstallRecord> { if let TPhase::Done(r) = self.req.phase() { Some(r.clone()) } else { None } }
}

// ------------------------------------------------------------------------------------------------------------------------------ tests
#[test]
fn an_honest_provider_serves_a_transfer_that_installs_the_authenticated_snapshot_with_durable_evidence() {
    let d = donor();
    let mut r = rig(&d, &[Mode::Honest]);
    r.run(2_000);
    let rec = r.done().unwrap_or_else(|| panic!("not done: {:?} {:?}", r.req.phase(), r.req.stats));
    assert_eq!(rec.generation, 1);
    let saved = r.saved.borrow();
    assert_eq!(saved.len(), 1, "the evidence is persisted exactly once");
    assert_eq!(saved[0].cref, rec.cref, "the evidence describes the installed checkpoint");
    assert_eq!(rec.cref, *d.refs.iter().rev().find(|c| c.height <= d.headers.last().unwrap().height).unwrap(), "the highest authenticated reference is chosen");
    let e = engine3(0, 4, &cc3(4, 8));
    assert!(e.authenticate_evidence(&saved[0]).is_ok(), "the persisted evidence re-authenticates from the node's own genesis");
    assert_eq!(r.req.outstanding(), 0, "no request slot is left behind");
    assert_eq!(r.req.stats.chunks_rejected + r.req.stats.headers_rejected + r.req.stats.manifests_rejected, 0);
}

#[test]
fn there_is_no_provider_agreement_threshold_one_honest_peer_among_liars_and_silence_is_enough() {
    let d = donor();
    for modes in [
        vec![Mode::BlackHole, Mode::ForgedHeaders, Mode::Honest],
        vec![Mode::Honest, Mode::BlackHole, Mode::BlackHole],
        vec![Mode::ForgedHeaders, Mode::HugeManifest, Mode::FlippedChunk, Mode::WrongState, Mode::Honest],
    ] {
        let mut r = rig(&d, &modes);
        r.run(6_000);
        assert!(r.done().is_some(), "{modes:?}: {:?} {:?}", r.req.phase(), r.req.stats);
        assert_eq!(r.saved.borrow().len(), 1, "{modes:?}");
    }
    // and a LONE provider is enough: nobody has to agree with it
    let mut r = rig(&d, &[Mode::Honest]); r.run(2_000); assert!(r.done().is_some());
}

#[test]
fn forged_headers_never_authenticate_never_become_evidence_and_the_next_provider_is_used() {
    let d = donor();
    let mut r = rig(&d, &[Mode::ForgedHeaders, Mode::Honest]);
    r.run(6_000);
    assert!(r.done().is_some(), "{:?} {:?}", r.req.phase(), r.req.stats);
    assert!(r.req.stats.headers_rejected >= 1, "the forgery was refused");
    let honest_chain: Vec<[u8; 32]> = d.headers.iter().map(|h| h.payload_hash).collect();
    for ev in r.saved.borrow().iter() { assert!(ev.headers.iter().zip(honest_chain.iter()).all(|(h, p)| h.payload_hash == *p), "no forged header reached the evidence"); }
    // only forgers: nothing installs, nothing is persisted, no generation exists
    let mut r = rig(&d, &[Mode::ForgedHeaders, Mode::ForgedHeaders]);
    r.run(3_000);
    assert!(r.done().is_none() && r.saved.borrow().is_empty());
    assert!(r.req.sink().pointer().is_none());
}

#[test]
fn a_chain_with_no_checkpoint_yet_is_not_the_provider_s_fault() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "Y", Some(cc));
    run_to(&mut net, 3);
    let d0 = net.nodes[0].as_ref().unwrap();
    let chain = drv_chain(d0); let set = set_n(4);
    assert!(chain.iter().all(|b| b.checkpoint.is_none()), "the fixture chain is too young for a reference");
    let headers = headers_of(&chain);
    let ids = headers.iter().map(|h| h.id(&idctx3(&set)).unwrap()).collect();
    let d = Arc::new(Donor { headers, ids, hq: d0.engine().high_qc().clone(), snaps: BTreeMap::new(), by_ref: BTreeMap::new(), refs: vec![], genesis_id: d0.engine().genesis_id() });
    let mut r = rig(&d, &[Mode::Honest]);
    r.run(300);
    assert!(r.done().is_none());
    assert!(r.req.stats.no_checkpoint_yet >= 1);
    assert_eq!(r.req.stats.peers_suppressed, 0, "an honest peer on a young chain is not blamed");
}

#[test]
fn a_flipped_chunk_is_refused_by_the_manifest_hash_and_the_chunk_is_fetched_from_another_provider() {
    let d = donor();
    let mut r = rig(&d, &[Mode::FlippedChunk, Mode::Honest]);
    r.run(8_000);
    assert!(r.done().is_some(), "{:?} {:?}", r.req.phase(), r.req.stats);
    assert!(r.req.stats.chunks_rejected >= 1);
    // a lone flipping provider: no chunk is ever accepted, nothing is published
    let mut r = rig(&d, &[Mode::FlippedChunk]);
    r.run(3_000);
    assert!(r.done().is_none() && r.saved.borrow().is_empty() && r.req.sink().pointer().is_none());
}

#[test]
fn a_snapshot_that_does_not_measure_to_the_authenticated_root_is_discarded_unpublished_and_its_id_is_not_trusted_again() {
    let d = donor();
    // the lying provider is first in line and answers everything consistently with a correct snapshot id
    let mut r = rig(&d, &[Mode::WrongState, Mode::Honest]);
    r.run(10_000);
    assert!(r.done().is_some(), "{:?} {:?}", r.req.phase(), r.req.stats);
    assert_eq!(r.req.stats.snapshots_rejected, 1, "the wrong state was measured and refused exactly once: its snapshot id is not trusted again");
    assert_eq!(r.saved.borrow().len(), 1, "evidence was persisted only for the install that measured correctly");
    // with no honest provider the lie never installs
    let mut r = rig(&d, &[Mode::WrongState]);
    r.run(3_000);
    assert!(r.done().is_none() && r.saved.borrow().is_empty() && r.req.sink().pointer().is_none(), "nothing published, nothing persisted");
}

#[test]
fn evidence_that_cannot_be_made_durable_stops_the_transfer_with_nothing_published_and_no_provider_blamed() {
    let d = donor();
    let mut r = rig_with(&d, &[Mode::Honest], tlim(), true);
    r.run(2_000);
    assert!(matches!(r.req.phase(), TPhase::Failed(m) if m.contains("durable")), "{:?}", r.req.phase());
    assert!(r.req.sink().pointer().is_none(), "no application generation was published without evidence");
    assert!(r.req.sink().fs.raw(&gen_dir(1)).is_none() && r.req.sink().fs.files_under("generations").is_empty());
    assert_eq!(r.req.stats.peers_suppressed, 0);
}

#[test]
fn a_huge_manifest_is_refused_against_the_local_staging_budget_without_blaming_and_an_honest_one_still_installs() {
    let d = donor();
    let mut r = rig(&d, &[Mode::HugeManifest, Mode::Honest]);
    r.run(6_000);
    assert!(r.done().is_some(), "{:?} {:?}", r.req.phase(), r.req.stats);
    assert!(r.req.stats.manifests_rejected >= 1);
    let mut small = tlim(); small.max_staging_bytes = 16; // below any real snapshot
    let mut r = rig_with(&d, &[Mode::Honest], small, false);
    r.run(500);
    assert!(r.done().is_none() && r.req.sink().pointer().is_none() && r.saved.borrow().is_empty());
}

#[test]
fn outstanding_requests_never_exceed_the_caps_and_every_slot_is_released_even_with_silent_providers() {
    let d = donor();
    for modes in [vec![Mode::Honest], vec![Mode::Honest, Mode::Honest, Mode::Honest], vec![Mode::NoReplyToChunks, Mode::Honest], vec![Mode::BlackHole, Mode::Honest]] {
        let mut lim = tlim(); lim.max_outstanding = 2; lim.per_peer_outstanding = 1;
        let mut r = rig_with(&d, &modes, lim, false);
        r.run(20_000);
        assert!(r.done().is_some(), "{modes:?}: {:?} {:?}", r.req.phase(), r.req.stats);
        assert!(r.max_out <= 2, "{modes:?}: {} outstanding", r.max_out);
        assert!(r.per_peer_max <= 1, "{modes:?}: {} outstanding to one peer", r.per_peer_max);
        assert_eq!(r.req.outstanding(), 0, "{modes:?}: slots left behind");
    }
}

#[test]
fn unsolicited_late_duplicate_and_wrong_peer_responses_change_nothing() {
    let d = donor();
    let mut r = rig(&d, &[Mode::Honest, Mode::Honest]);
    let first = r.req.start(r.now);
    let Some(Out { peer, msg: RecoveryMsg::HeaderReq { request_id, after, .. } }) = first.first().cloned() else { panic!("a header request first") };
    let other = 1 - peer;
    let honest = Peer { d: d.clone(), mode: Mode::Honest };
    let page = honest.headers_after(&after, 4);
    let resp = RecoveryMsg::HeaderResp { request_id, after, body: page.clone() };
    // from the wrong peer, with an id nobody issued, with the wrong selector, and a chunk nobody asked for
    assert!(r.req.on_message(other, &resp, r.now).is_empty());
    assert!(r.req.on_message(peer, &RecoveryMsg::HeaderResp { request_id: request_id + 77, after, body: page.clone() }, r.now).is_empty());
    let wrong_sel = RecoveryMsg::HeaderResp { request_id, after: [9; 32], body: page.clone() };
    let _ = r.req.on_message(peer, &wrong_sel, r.now);
    assert!(r.req.on_message(peer, &RecoveryMsg::ChunkResp { request_id: 5, snapshot_id: [1; 32], index: 0, body: ChunkBody::Ok(vec![0; 64]) }, r.now).is_empty());
    assert_eq!(*r.req.phase(), TPhase::Headers);
    assert!(r.req.stats.dropped_unsolicited >= 2);
    // the genuine reply after all of that still works once; a replay of it is dropped as late/unsolicited
    let _ = r.req.on_message(peer, &resp, r.now);
    let before = r.req.stats;
    assert!(r.req.on_message(peer, &resp, r.now).is_empty());
    assert!(r.req.stats.dropped_unsolicited + r.req.stats.dropped_late > before.dropped_unsolicited + before.dropped_late);
}

#[test]
fn the_accumulated_header_bound_is_enforced_and_never_exceeded() {
    let d = donor();
    let mut lim = tlim(); lim.max_accumulated_headers = 6; lim.headers_per_request = 4;
    let mut r = rig_with(&d, &[Mode::Honest], lim, false);
    r.run(500);
    assert!(r.done().is_none() && r.saved.borrow().is_empty() && r.req.sink().pointer().is_none(), "a chain longer than the local bound cannot be installed");
    assert!(r.req.stats.headers_rejected >= 1);
}

#[test]
fn unsupported_limits_are_refused_locally_before_any_network_use() {
        let c = rl();
    let mut l = tlim(); l.max_outstanding = 0; assert_eq!(l.validate(&c), Err(TransferConfigError::Zero));
    let mut l = tlim(); l.per_peer_outstanding = l.max_outstanding + 1; assert!(matches!(l.validate(&c), Err(TransferConfigError::PerPeerAboveTotal { .. })));
    let mut l = tlim(); l.headers_per_request = c.max_headers + 1; assert!(matches!(l.validate(&c), Err(TransferConfigError::HeadersAboveCodec { .. })));
    // a page that cannot fit the transport limit
    let tiny = CodecLimits { transport: 4_096, ..c };
    assert_eq!(tlim().validate(&tiny), Err(TransferConfigError::HeadersDoNotFit));
    assert!(tlim().validate(&c).is_ok());
}

#[test]
fn a_provider_degrades_oversized_answers_to_advice_never_sends_what_a_decoder_would_refuse_and_answers_no_responses() {
    let d = donor();
    let tiny = CodecLimits { transport: 6_000, ..rl() };
    let cfg = ServeConfig { limit: 6_000, burst: 12_000, refill_per_s: 6_000, aggregate_per_s: 60_000, ..serve_cfg() };
    let mut p = Provider::new(Peer { d: d.clone(), mode: Mode::Honest }, ServeGate::new(cfg, 1).unwrap(), tiny);
    // a page of 40 headers cannot fit 6 000 bytes: the answer is advice that fits, not the page
    let g = d.genesis_id;
    let r = p.handle(1, &RecoveryMsg::HeaderReq { request_id: 1, after: g, max_headers: 40 }, 10).unwrap();
    let b = rcodec::encode(&r).unwrap(); assert!(b.len() as u64 <= 6_000, "{} bytes", b.len());
    assert!(!matches!(r, RecoveryMsg::HeaderResp { body: HeaderBody::Ok { .. }, .. }));
    assert!(p.stats.too_large >= 1);
    // responses are never answered
    assert!(p.handle(1, &RecoveryMsg::ChunkResp { request_id: 2, snapshot_id: [0; 32], index: 0, body: ChunkBody::NotFound }, 11).is_none());
    // a flood from one peer is told to back off, not served unboundedly
    let mut busy = 0;
    for i in 0..5_000u64 { if let Some(RecoveryMsg::ChunkResp { body: ChunkBody::Busy { .. }, .. }) = p.handle(2, &RecoveryMsg::ChunkReq { request_id: i, snapshot_id: [0; 32], index: 0 }, 12) { busy += 1; } }
    assert!(busy > 0, "a flood is answered with BUSY");
}

#[test]
fn nothing_newer_than_the_local_state_means_no_manifest_is_ever_requested_and_nobody_is_blamed() {
    let d = donor();
    let top = d.refs.last().unwrap().height;
    let cc = cc3(4, 8);
    let e = engine3(0, 4, &cc);
    let gid = e.genesis_id();
    let saved: Rc<TRefCell<Vec<SeedEvidence>>> = Default::default();
    let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs);
    let mut inst: Inst = Installer::new(fs, interim(), GENESIS_HASH, rl(), Box::new(|_c: &Cert| Ok(()))).unwrap();
    inst.start().unwrap();
    let req = Requester::new(TAuth { e, set: set_n(4) }, inst, RecEv { saved: saved.clone(), fail: false }, gid, GENESIS_HASH, rl(), tlim(), top).unwrap();
    let mut r = Rig { req, peers: vec![Node::Serve(provider(&d, Mode::Honest, 1))], now: 1, saved, max_out: 0, sent: vec![], per_peer_max: 0 };
    r.req.add_peer(0);
    r.run(300);
    assert!(r.done().is_none() && r.saved.borrow().is_empty());
    assert!(!r.sent.iter().any(|(_, m)| matches!(m, RecoveryMsg::ManifestReq { .. } | RecoveryMsg::ChunkReq { .. })), "no manifest or chunk is requested for a checkpoint that is not forward");
    assert_eq!(r.req.stats.peers_suppressed, 0);
}

#[test]
fn an_honest_transfer_is_driven_by_messages_alone_a_released_slot_is_reused_at_once_without_a_timer() {
    let d = donor();
    let mut lim = tlim(); lim.max_outstanding = 2; lim.per_peer_outstanding = 1;
    let mut r = rig_with(&d, &[Mode::Honest, Mode::Honest], lim, false);
    let first = r.req.start(r.now); r.settle(first); // NO on_tick afterwards
    assert!(r.done().is_some(), "stalled without a timer: {:?} {:?} outstanding {}", r.req.phase(), r.req.stats, r.req.outstanding());
}
