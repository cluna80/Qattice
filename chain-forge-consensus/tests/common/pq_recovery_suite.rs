
// ============================================================================================================================
// Snapshot-recovery COMPONENTS (disabled, isolated): codecs for kinds 7 to 12, bounded request handling, and the staged, generation-bound installer.
// The interim application's state is a hash chain: these tests exercise codecs, bounds and storage ordering, NOT transaction state.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::recovery::codec::{self as rcodec, CheckpointRef, ChunkBody, CodecError, CodecLimits, HeaderBody, Manifest, ManifestBody, RecoveryMsg};
use chain_forge_consensus::pq_hotstuff::recovery::install::{gen_dir, record_path, InstallError, InstallProof, Installer, InterimShadow, QcCheck, ShadowApp, StartOutcome};
use chain_forge_consensus::pq_hotstuff::recovery::records::{AppPointer, Cursor, InstallRecord, Phase, RecoveryState};
use chain_forge_consensus::pq_hotstuff::recovery::requests::{advice_of, clamp_retry_after, outstanding_cap, Advice, ConfigError, Cooldown, Dropped, IssueError, RequestTable, Selector, ServeConfig, ServeGate, StallDetector, Suppression};
use chain_forge_consensus::pq_hotstuff::recovery::tree::{StdTreeFs, TreeFs};
use tree_doubles::*;

mod alloc_probe {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    thread_local! { static MAX: Cell<usize> = const { Cell::new(0) }; }
    pub struct Probe;
    fn note(n: usize) { MAX.with(|m| if n > m.get() { m.set(n) }); }
    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 { note(l.size()); System.alloc(l) }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) { System.dealloc(p, l) }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 { note(n); System.realloc(p, l, n) }
        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 { note(l.size()); System.alloc_zeroed(l) }
    }
    pub fn reset() { MAX.with(|m| m.set(0)); }
    pub fn peak() -> usize { MAX.with(|m| m.get()) }
}
#[global_allocator]
static PROBE: alloc_probe::Probe = alloc_probe::Probe;

fn rl() -> CodecLimits { CodecLimits { transport: net::MAX_MESSAGE_SIZE, n: 4, max_headers: 64, max_chunk_size: 262_144, max_chunk_count: 65_536, max_snapshot_bytes: 256 << 20 } }
fn cref(h: u64, tag: u8) -> CheckpointRef { CheckpointRef { height: h, block_id: [tag; 32], state_root: [tag.wrapping_add(1); 32] } }
fn manifest_for(data: &[u8], chunk_size: u32, c: &CheckpointRef) -> (Manifest, Vec<Vec<u8>>) {
    let chunks: Vec<Vec<u8>> = data.chunks(chunk_size as usize).map(|x| x.to_vec()).collect();
    let mut m = Manifest { format_version: 1, snapshot_id: [0; 32], total_bytes: data.len() as u64, chunk_size, chunk_count: chunks.len() as u32, chunk_hashes: chunks.iter().enumerate().map(|(i, c)| rcodec::chunk_hash(i as u32, c)).collect() };
    m.snapshot_id = m.compute_id(&GENESIS_HASH, c);
    (m, chunks)
}

// ---- E: codecs
fn one_of_each(hs: &[PayloadFreeBlock]) -> Vec<RecoveryMsg> {
    let c = cref(40, 7);
    let (m, chunks) = manifest_for(&[5u8; 300], 64, &c);
    let sid = m.snapshot_id;
    let f = fx();
    let fq = Cert::Qc(qc_for(&f, 9, [4; 32], [3; 32], 8, &[0, 1, 2]));
    vec![
        RecoveryMsg::HeaderReq { request_id: 1, after: [2; 32], max_headers: 8 },
        RecoveryMsg::HeaderResp { request_id: 2, after: [2; 32], body: HeaderBody::Ok { headers: hs[..3].to_vec(), final_qc: Some(fq), tip_height: 99 } },
        RecoveryMsg::HeaderResp { request_id: 2, after: [2; 32], body: HeaderBody::Ok { headers: hs[..1].to_vec(), final_qc: None, tip_height: 1 } },
        RecoveryMsg::HeaderResp { request_id: 3, after: [2; 32], body: HeaderBody::NotFound },
        RecoveryMsg::HeaderResp { request_id: 4, after: [2; 32], body: HeaderBody::TooLarge { needed_bytes: 123_456, next_height: 77 } },
        RecoveryMsg::HeaderResp { request_id: 5, after: [2; 32], body: HeaderBody::Busy { retry_after_ms: 250 } },
        RecoveryMsg::HeaderResp { request_id: 6, after: [2; 32], body: HeaderBody::Unavailable },
        RecoveryMsg::HeaderResp { request_id: 7, after: [2; 32], body: HeaderBody::AtTip { tip_height: 500 } },
        RecoveryMsg::ManifestReq { request_id: 8, cref: c },
        RecoveryMsg::ManifestResp { request_id: 9, cref: c, body: ManifestBody::Ok(m) },
        RecoveryMsg::ManifestResp { request_id: 10, cref: c, body: ManifestBody::NotFound },
        RecoveryMsg::ManifestResp { request_id: 11, cref: c, body: ManifestBody::TooLarge { needed_bytes: 9_999 } },
        RecoveryMsg::ManifestResp { request_id: 12, cref: c, body: ManifestBody::Busy { retry_after_ms: 1 } },
        RecoveryMsg::ManifestResp { request_id: 13, cref: c, body: ManifestBody::Unavailable },
        RecoveryMsg::ChunkReq { request_id: 14, snapshot_id: sid, index: 3 },
        RecoveryMsg::ChunkResp { request_id: 15, snapshot_id: sid, index: 3, body: ChunkBody::Ok(chunks[0].clone()) },
        RecoveryMsg::ChunkResp { request_id: 16, snapshot_id: sid, index: 3, body: ChunkBody::NotFound },
        RecoveryMsg::ChunkResp { request_id: 17, snapshot_id: sid, index: 3, body: ChunkBody::Busy { retry_after_ms: 60_000 } },
        RecoveryMsg::ChunkResp { request_id: 18, snapshot_id: sid, index: 3, body: ChunkBody::Unavailable },
    ]
}

#[test]
fn recovery_messages_round_trip_re_encode_identically_and_reject_every_truncation_and_trailing_byte() {
    let (_net, bs, _) = tc_chain();
    let hs = headers_of(&bs);
    let lim = rl();
    for m in one_of_each(&hs) {
        let e = rcodec::encode(&m).unwrap();
        assert_eq!(rcodec::decode(&e, &lim).unwrap(), m);
        assert_eq!(rcodec::encode(&rcodec::decode(&e, &lim).unwrap()).unwrap(), e, "canonical");
        for cut in (0..e.len()).step_by(61).chain([e.len() - 1]) { assert!(rcodec::decode(&e[..cut], &lim).is_err(), "kind {} truncated at {cut}", m.kind()); }
        let mut t = e.clone(); t.push(0); assert!(rcodec::decode(&t, &lim).is_err(), "kind {} trailing byte", m.kind());
    }
}

fn raw(kind: u8, body: &[u8]) -> Vec<u8> { let mut v = net::TAG_NET.to_vec(); v.extend_from_slice(&1u16.to_be_bytes()); v.push(kind); v.extend_from_slice(body); v }

#[test]
fn invalid_recovery_fields_are_rejected_and_hostile_lengths_allocate_nothing_large() {
    let lim = rl();
    let rid = 7u64.to_be_bytes();
    let hdr_resp = |status: u8, rest: &[u8]| { let mut b = rid.to_vec(); b.push(status); b.extend_from_slice(&[2u8; 32]); b.extend_from_slice(rest); raw(8, &b) };
    // OK with no headers, an unknown status, a count above the cap
    assert!(matches!(rcodec::decode(&hdr_resp(0, &0u32.to_be_bytes()), &lim), Err(CodecError::Invalid(_))));
    assert!(matches!(rcodec::decode(&hdr_resp(9, &[]), &lim), Err(CodecError::Malformed(_))));
    assert!(matches!(rcodec::decode(&hdr_resp(0, &65u32.to_be_bytes()), &lim), Err(CodecError::Invalid(_))));
    // max_headers 0 and above the cap in a request
    for bad in [0u32, 65, u32::MAX] { let mut b = rid.to_vec(); b.extend_from_slice(&[2u8; 32]); b.extend_from_slice(&bad.to_be_bytes()); assert!(rcodec::decode(&raw(7, &b), &lim).is_err()); }
    // statuses that do not exist for a kind
    let c = cref(40, 7);
    let mut b = rid.to_vec(); b.push(5); b.extend_from_slice(&c.encode()); assert!(matches!(rcodec::decode(&raw(10, &b), &lim), Err(CodecError::Malformed(_))), "AT_TIP for a manifest");
    for st in [2u8, 5] { let mut b = rid.to_vec(); b.push(st); b.extend_from_slice(&[3u8; 32]); b.extend_from_slice(&0u32.to_be_bytes()); assert!(matches!(rcodec::decode(&raw(12, &b), &lim), Err(CodecError::Malformed(_))), "status {st} for a chunk"); }
    // chunk lengths: zero and above the cap
    for n in [0u32, 262_145] { let mut b = rid.to_vec(); b.push(0); b.extend_from_slice(&[3u8; 32]); b.extend_from_slice(&0u32.to_be_bytes()); b.extend_from_slice(&n.to_be_bytes()); assert!(matches!(rcodec::decode(&raw(12, &b), &lim), Err(CodecError::Invalid(_)))); }
    // manifest structure: bad counts and sizes and totals
    let man = |version: u16, total: u64, size: u32, count: u32, hashes: usize| {
        let mut b = rid.to_vec(); b.push(0); b.extend_from_slice(&c.encode());
        b.extend_from_slice(&version.to_be_bytes()); b.extend_from_slice(&[9u8; 32]); b.extend_from_slice(&total.to_be_bytes()); b.extend_from_slice(&size.to_be_bytes()); b.extend_from_slice(&count.to_be_bytes());
        b.extend_from_slice(&vec![1u8; 32 * hashes]); raw(10, &b)
    };
    assert!(rcodec::decode(&man(1, 100, 64, 2, 2), &lim).is_ok());
    for (total, size, count, hashes) in [(100, 64, 0, 0), (100, 64, 65_537, 0), (100, 0, 2, 2), (100, 262_145, 1, 1), (0, 64, 1, 1), (129, 64, 2, 2), (64, 64, 2, 2), ((256u64 << 20) + 1, 262_144, 1025, 1025)] {
        assert!(rcodec::decode(&man(1, total, size, count, hashes), &lim).is_err(), "total {total} size {size} count {count}");
    }
    // hostile lengths and counts in tiny inputs must be refused WITHOUT a large allocation
    let mut hostile: Vec<Vec<u8>> = vec![];
    hostile.push(hdr_resp(0, &u32::MAX.to_be_bytes()));
    hostile.push(hdr_resp(0, &[&64u32.to_be_bytes()[..], &u32::MAX.to_be_bytes()].concat()));
    hostile.push(hdr_resp(0, &[&1u32.to_be_bytes()[..], &(rl().header_max().unwrap() as u32).to_be_bytes()].concat()));
    hostile.push(hdr_resp(0, &[&1u32.to_be_bytes()[..], &0u32.to_be_bytes()].concat()));
    hostile.push(man(1, 100, 64, 65_536, 0));
    hostile.push({ let mut b = rid.to_vec(); b.push(0); b.extend_from_slice(&[3u8; 32]); b.extend_from_slice(&0u32.to_be_bytes()); b.extend_from_slice(&262_144u32.to_be_bytes()); raw(12, &b) });
    for h in &hostile {
        alloc_probe::reset();
        let r = rcodec::decode(h, &lim);
        assert!(r.is_err());
        assert!(alloc_probe::peak() < 64 * 1024, "decoding a {}-byte hostile message allocated {} bytes at once", h.len(), alloc_probe::peak());
    }
    // a header length just above the per-header maximum is refused as TOO LARGE (the bound, not a parse failure), even with all its bytes present
    let hmax = lim.header_max().unwrap() as usize;
    for over in [hmax + 1, hmax + 4_096] {
        let body = [&1u32.to_be_bytes()[..], &(over as u32).to_be_bytes(), &vec![0u8; over]].concat();
        assert!(matches!(rcodec::decode(&hdr_resp(0, &body), &lim), Err(CodecError::TooLarge { len, max }) if len == over as u64 && max == hmax as u64), "length {over}");
    }
    let body = [&1u32.to_be_bytes()[..], &u32::MAX.to_be_bytes()].concat();
    assert!(matches!(rcodec::decode(&hdr_resp(0, &body), &lim), Err(CodecError::TooLarge { .. })), "an absurd header length is refused by the bound before anything is read");
    // the encoder refuses what the decoder refuses
    assert!(matches!(rcodec::encode(&RecoveryMsg::HeaderResp { request_id: 1, after: [0; 32], body: HeaderBody::Ok { headers: vec![], final_qc: None, tip_height: 1 } }), Err(CodecError::Invalid(_))));
    // a whole-message length above the transport limit and above the kind's own maximum
    assert!(matches!(rcodec::decode(&vec![0u8; lim.transport as usize + 1], &lim), Err(CodecError::TooLarge { .. })));
    let mut big_req = raw(7, &[0u8; 44]); big_req.extend_from_slice(&[0u8; 100]);
    assert!(matches!(rcodec::decode(&big_req, &lim), Err(CodecError::TooLarge { .. })));
}

#[test]
fn reserved_and_unknown_kinds_are_unavailable_in_the_operational_decoder_and_in_the_recovery_decoder() {
    let m = mlim();
    for kind in 7u8..=14 {
        let bytes = raw(kind, &[0u8; 64]);
        assert!(matches!(net::decode(&bytes, &m), Err(net::NetError::Malformed("unknown kind"))), "netmsg::decode must reject kind {kind}");
    }
    for kind in [0u8, 1, 2, 3, 4, 5, 6, 13, 14, 15, 255] {
        assert!(matches!(rcodec::decode(&raw(kind, &[0u8; 64]), &rl()), Err(CodecError::UnknownKind(k)) if k == kind), "kind {kind}");
    }
    assert_eq!(rcodec::RESERVED_KINDS, [13, 14]);
}

fn synthetic_qc(n: usize, k: usize) -> Qc { Qc { epoch: 0, round: 5, block_id: [1; 32], parent_id: [2; 32], parent_round: 4, valset_hash: [3; 32], signers: (0..n).map(|i| i < k).collect(), sigs: vec![vec![7u8; MLDSA65_SIGNATURE_LEN]; k] } }
fn synthetic_tc(n: usize, k: usize, nested: Cert) -> Tc { Tc { epoch: 0, round: 9, valset_hash: [3; 32], signers: (0..n).map(|i| i < k).collect(), high_qc_rounds: vec![5; k], sigs: vec![vec![7u8; MLDSA65_SIGNATURE_LEN]; k], high_qc: nested } }

#[test]
fn recovery_message_sizes_equal_the_formulas_for_the_largest_message_of_each_kind_at_every_validator_count() {
    for n in [4usize, 31, 100, 1000] {
        let lim = CodecLimits { transport: 1 << 40, n, max_headers: 1, max_chunk_size: 262_144, max_chunk_count: 1024, max_snapshot_bytes: 256 << 20 };
        let (qc_max, tc_max, hdr_max) = (qc_max_formula(n), 72 + n.div_ceil(8) as u64 + 3323 * n as u64 + qc_max_formula(n), lim.header_max().unwrap());
        assert_eq!(hdr_max, 3410 + qc_max + 4 + tc_max, "n = {n}");
        // the largest header: a TC-bearing header at the maximum certificate size (every validator signing), plus an additional QC in the response
        let qc = synthetic_qc(n, n);
        let tc = synthetic_tc(n, n, Cert::Qc(synthetic_qc(n, n)));
        let h = PayloadFreeBlock { epoch: 0, round: 10, height: 5, parent_id: [2; 32], qc: Cert::Qc(qc.clone()), tc: Some(tc), payload_hash: [0; 32], proposer: 0, signature: vec![9u8; MLDSA65_SIGNATURE_LEN] };
        assert_eq!(encode_header(&h).len() as u64, hdr_max, "n = {n}: header");
        let m = RecoveryMsg::HeaderResp { request_id: 1, after: [0; 32], body: HeaderBody::Ok { headers: vec![h], final_qc: Some(Cert::Qc(qc)), tip_height: 9 } };
        let e = rcodec::encode(&m).unwrap();
        let min = 12 + 8 + 1 + 32 + 4 + (4 + hdr_max) + 1 + (4 + qc_max) + 8;
        assert_eq!(e.len() as u64, min, "n = {n}: header response (one TC-bearing header + an extra QC) equals HDR_RESP_MIN = HDR_MAX + QC_MAX + 74");
        assert_eq!(min, hdr_max + qc_max + 74);
        assert_eq!(lim.max_len(rcodec::KIND_HEADER_RESP), Some(min), "max_len agrees");
        assert_eq!(rcodec::decode(&e, &lim).unwrap(), m, "n = {n}: the largest legal response decodes");
        match n { 4 => assert_eq!(min, 57_056), 31 => assert_eq!(min, 415_304), 100 => assert_eq!(min, 1_330_832), _ => { assert_eq!(min, 13_272_480); assert!(min > net::MAX_MESSAGE_SIZE, "1,000 validators need more than 8 MiB"); } }
    }
    // manifest with 1,024 chunks and a 256 KiB chunk response
    let lim = rl();
    let c = cref(40, 7);
    let mut m = Manifest { format_version: 1, snapshot_id: [0; 32], total_bytes: 1024 * 262_144, chunk_size: 262_144, chunk_count: 1024, chunk_hashes: vec![[1; 32]; 1024] };
    m.snapshot_id = m.compute_id(&GENESIS_HASH, &c);
    assert_eq!(rcodec::encode(&RecoveryMsg::ManifestResp { request_id: 1, cref: c, body: ManifestBody::Ok(m) }).unwrap().len(), 143 + 32 * 1024);
    let e = rcodec::encode(&RecoveryMsg::ChunkResp { request_id: 1, snapshot_id: [1; 32], index: 0, body: ChunkBody::Ok(vec![0u8; 262_144]) }).unwrap();
    assert_eq!(e.len(), 61 + 262_144);
    assert!(rcodec::decode(&e, &lim).is_ok());
}
fn qc_max_formula(n: usize) -> u64 { 140 + n.div_ceil(8) as u64 + 3315 * n as u64 }

#[test]
fn snapshot_ids_are_content_addressed_and_every_manifest_constraint_is_enforced() {
    let c = cref(40, 7);
    let (m, chunks) = manifest_for(&[5u8; 300], 64, &c);
    assert_eq!(chunks.len(), 5);
    assert_eq!(m.chunk_len(0), Some(64));
    assert_eq!(m.chunk_len(4), Some(44), "the last chunk holds the remainder");
    assert_eq!(m.chunk_len(5), None);
    assert!(m.validate(&rl()).is_ok());
    // every input of the id matters
    let id = m.compute_id(&GENESIS_HASH, &c);
    assert_ne!(id, m.compute_id(&[8; 32], &c));
    assert_ne!(id, m.compute_id(&GENESIS_HASH, &CheckpointRef { height: 41, ..c }));
    assert_ne!(id, m.compute_id(&GENESIS_HASH, &CheckpointRef { block_id: [9; 32], ..c }));
    assert_ne!(id, m.compute_id(&GENESIS_HASH, &CheckpointRef { state_root: [9; 32], ..c }));
    for tweak in 0..5 {
        let mut x = m.clone();
        match tweak { 0 => x.format_version = 2, 1 => x.total_bytes += 1, 2 => x.chunk_size += 1, 3 => x.chunk_count += 1, _ => x.chunk_hashes[2][0] ^= 1 }
        assert_ne!(x.compute_id(&GENESIS_HASH, &c), id, "tweak {tweak}");
    }
    // a chunk hash binds its index and its bytes
    assert_ne!(rcodec::chunk_hash(0, &chunks[0]), rcodec::chunk_hash(1, &chunks[0]));
    assert_ne!(rcodec::chunk_hash(0, &chunks[0]), rcodec::chunk_hash(0, &chunks[1][..63]));
    // constraint violations
    let bad = |f: &dyn Fn(&mut Manifest)| { let mut x = m.clone(); f(&mut x); x.validate(&rl()).is_err() };
    assert!(bad(&|x| x.chunk_count = 0));
    assert!(bad(&|x| x.chunk_hashes.pop().map(|_| ()).unwrap_or(())));
    assert!(bad(&|x| x.chunk_size = 0));
    assert!(bad(&|x| x.chunk_size = 262_145));
    assert!(bad(&|x| x.total_bytes = 64 * 4));
    assert!(bad(&|x| x.total_bytes = 64 * 5 + 1));
    assert!(bad(&|x| x.total_bytes = 0));
    assert!(bad(&|x| x.total_bytes = (256 << 20) + 1));
    assert_eq!(CheckpointRef::decode(&c.encode()).unwrap(), c);
    assert!(CheckpointRef::decode(&c.encode()[..71]).is_err());
}

// ---- C, B, O: bounded request handling
fn hresp(id: u64, after: BlockId, body: HeaderBody) -> RecoveryMsg { RecoveryMsg::HeaderResp { request_id: id, after, body } }

#[test]
fn responses_are_accepted_only_when_peer_kind_request_id_and_selector_all_match() {
    let mut t = RequestTable::new(8, 1_000, 30_000);
    let sel = Selector::After([2; 32]);
    let id = t.issue(1, sel, 0).unwrap();
    let ok = hresp(id, [2; 32], HeaderBody::AtTip { tip_height: 5 });
    assert_eq!(t.accept(2, &ok, 10), Err(Dropped::Unsolicited), "wrong peer");
    assert_eq!(t.accept(1, &hresp(id + 1, [2; 32], HeaderBody::AtTip { tip_height: 5 }), 10), Err(Dropped::Unsolicited), "wrong request id");
    let other_kind = RecoveryMsg::ManifestResp { request_id: id, cref: cref(1, 1), body: ManifestBody::NotFound };
    assert_eq!(t.accept(1, &other_kind, 10), Err(Dropped::Unsolicited), "wrong kind");
    assert_eq!(t.accept(1, &hresp(id, [3; 32], HeaderBody::AtTip { tip_height: 5 }), 10), Err(Dropped::SelectorMismatch), "wrong echoed selector");
    assert_eq!(t.accept(1, &RecoveryMsg::HeaderReq { request_id: id, after: [2; 32], max_headers: 1 }, 10), Err(Dropped::NotAResponse));
    assert_eq!(t.len(), 1, "none of the bad responses consumed the entry");
    assert_eq!(t.accept(1, &ok, 10).map(|p| p.request_id), Ok(id));
    assert_eq!(t.accept(1, &ok, 11), Err(Dropped::Unsolicited), "a duplicate is dropped");
    assert!(t.is_empty());
    // chunk and manifest selectors
    let (c, sid) = (cref(40, 7), [5u8; 32]);
    let a = t.issue(1, Selector::Ref(c), 0).unwrap();
    let b = t.issue(1, Selector::Chunk(sid, 3), 0).unwrap();
    assert_eq!(t.accept(1, &RecoveryMsg::ManifestResp { request_id: a, cref: cref(41, 7), body: ManifestBody::NotFound }, 1), Err(Dropped::SelectorMismatch));
    assert_eq!(t.accept(1, &RecoveryMsg::ChunkResp { request_id: b, snapshot_id: sid, index: 4, body: ChunkBody::NotFound }, 1), Err(Dropped::SelectorMismatch));
    assert_eq!(t.accept(1, &RecoveryMsg::ChunkResp { request_id: b, snapshot_id: [6; 32], index: 3, body: ChunkBody::NotFound }, 1), Err(Dropped::SelectorMismatch));
    assert!(t.accept(1, &RecoveryMsg::ChunkResp { request_id: b, snapshot_id: sid, index: 3, body: ChunkBody::NotFound }, 1).is_ok());
    assert!(t.accept(1, &RecoveryMsg::ManifestResp { request_id: a, cref: c, body: ManifestBody::NotFound }, 1).is_ok());
    assert!(t.stats.selector_mismatch >= 3 && t.stats.unsolicited >= 4);
}

#[test]
fn a_late_response_is_dropped_the_table_is_bounded_and_request_ids_are_never_reused() {
    let mut t = RequestTable::new(3, 10, 1_000);
    let sels = [Selector::After([1; 32]), Selector::Ref(cref(1, 1)), Selector::Chunk([2; 32], 0)];
    let ids: Vec<u64> = sels.iter().map(|s| t.issue(1, *s, 0).unwrap()).collect();
    assert_eq!(ids, vec![10, 11, 12]);
    assert_eq!(t.issue(2, Selector::After([9; 32]), 0), Err(IssueError::GlobalCap));
    assert_eq!(t.accept(1, &hresp(10, [1; 32], HeaderBody::NotFound), 1_001), Err(Dropped::Late));
    assert_eq!(t.len(), 2, "a late response removes its entry");
    let dead = t.expire(2_000);
    assert_eq!(dead.len(), 2);
    assert!(t.is_empty());
    let more = t.issue(1, Selector::After([1; 32]), 3_000).unwrap();
    assert!(more > 12, "ids continue upward and are never reused");
    // exhaustion is an error, not a wrap
    let mut e = RequestTable::new(2, u64::MAX, 1_000);
    assert_eq!(e.issue(1, Selector::After([1; 32]), 0), Err(IssueError::IdExhausted));
}

#[test]
fn per_peer_and_global_outstanding_caps_hold() {
    let mut t = RequestTable::new(16, 0, 30_000);
    t.issue(1, Selector::After([1; 32]), 0).unwrap();
    assert_eq!(t.issue(1, Selector::After([2; 32]), 0), Err(IssueError::PeerCap), "one header request per peer");
    t.issue(1, Selector::Ref(cref(1, 1)), 0).unwrap();
    assert_eq!(t.issue(1, Selector::Ref(cref(2, 1)), 0), Err(IssueError::PeerCap), "one manifest request per peer");
    for i in 0..4 { t.issue(1, Selector::Chunk([1; 32], i), 0).unwrap(); }
    assert_eq!(t.issue(1, Selector::Chunk([1; 32], 4), 0), Err(IssueError::PeerCap), "four chunk requests per peer");
    t.issue(2, Selector::After([1; 32]), 0).unwrap();
    assert!(t.len() <= 16);
    // the memory budget: outstanding_cap = min(16, memory / limit), and 0 refuses
    assert_eq!(outstanding_cap(64 << 20, 8 << 20), Ok(8));
    assert_eq!(outstanding_cap(1 << 40, 8 << 20), Ok(16));
    assert_eq!(outstanding_cap(4 << 20, 8 << 20), Err(ConfigError::NoOutstandingBudget));
    assert_eq!(outstanding_cap(1, 0), Err(ConfigError::Zero));
}

#[test]
fn peer_advice_never_counts_as_invalidity_and_suppression_is_temporary() {
    // TOO_LARGE and BUSY are only advice
    let tl = hresp(1, [1; 32], HeaderBody::TooLarge { needed_bytes: u64::MAX, next_height: 9 });
    let tlm = RecoveryMsg::ManifestResp { request_id: 1, cref: cref(1, 1), body: ManifestBody::TooLarge { needed_bytes: 0 } };
    assert_eq!(advice_of(&tl), Advice::TooLarge);
    assert_eq!(advice_of(&tlm), Advice::TooLarge);
    assert_eq!(advice_of(&hresp(1, [1; 32], HeaderBody::Busy { retry_after_ms: 5 })), Advice::Busy { retry_after_ms: 5 });
    assert_eq!(advice_of(&hresp(1, [1; 32], HeaderBody::NotFound)), Advice::None);
    assert_eq!(clamp_retry_after(0), 100);
    assert_eq!(clamp_retry_after(u32::MAX), 60_000);
    assert_eq!(clamp_retry_after(2_500), 2_500);
    // cool-down per (peer, selector): 1 s doubling to 5 min, cleared by service; other selectors and peers unaffected
    let mut cd = Cooldown::default();
    let sel = Selector::After([1; 32]);
    let mut now = 0u64;
    let mut waits = vec![];
    for _ in 0..12 { let until = cd.note_unserved(1, sel, now); waits.push(until - now); assert!(!cd.ready(1, &sel, now)); now = until; assert!(cd.ready(1, &sel, now)); }
    assert_eq!(&waits[..4], &[1_000, 2_000, 4_000, 8_000]);
    assert_eq!(*waits.last().unwrap(), 300_000, "capped at five minutes");
    assert!(cd.ready(2, &sel, 0) && cd.ready(1, &Selector::After([2; 32]), 0));
    cd.note_served(1, sel);
    assert!(cd.ready(1, &sel, 0));
    // an advertised oversize NEVER suppresses a peer: the suppression only records locally verified invalidity, and nothing here records advice
    let sup = Suppression::default();
    assert!(!sup.is_suppressed(1, 0));
    // temporary suppression: 3 invalid in 5 minutes -> 10 minutes, doubling, capped at 1 hour, forgotten after 1 hour quiet
    let mut sup = Suppression::default();
    for t in [0u64, 1_000] { sup.record_invalid(1, t); }
    assert!(!sup.is_suppressed(1, 2_000), "two strikes are not enough");
    sup.record_invalid(1, 2_000);
    assert!(sup.is_suppressed(1, 2_001) && sup.is_suppressed(1, 600_000) && !sup.is_suppressed(1, 602_001), "ten minutes, then released");
    assert!(!sup.is_suppressed(2, 2_001), "other peers unaffected");
    let mut now = 700_000u64;
    let mut durs = vec![];
    for _ in 0..8 { for _ in 0..3 { sup.record_invalid(1, now); now += 1_000; } let mut d = 0; while sup.is_suppressed(1, now + d) { d += 10_000; } durs.push(d); now += d + 1_000; }
    assert_eq!(&durs[..3], &[1_200_000, 2_400_000, 3_600_000], "doubling from the base: {durs:?}");
    assert!(durs.iter().all(|d| *d <= 3_610_000), "never above one hour: {durs:?}");
    assert_eq!(durs[3], 600_000, "after serving a full hour with no incident the peer is forgotten and starts from the base again: {durs:?}");
    // strikes older than 5 minutes do not accumulate
    let mut s2 = Suppression::default();
    for t in [0u64, 400_000, 800_000] { s2.record_invalid(3, t); }
    assert!(!s2.is_suppressed(3, 800_001));
    // after an hour without incident a peer starts again from the base duration
    let mut s3 = Suppression::default();
    for t in [0u64, 1, 2] { s3.record_invalid(4, t); }
    let long_quiet = 10_000_000u64;
    for t in [long_quiet, long_quiet + 1, long_quiet + 2] { s3.record_invalid(4, t); }
    assert!(s3.is_suppressed(4, long_quiet + 3) && !s3.is_suppressed(4, long_quiet + 700_000), "back to the ten-minute base");
}

#[test]
fn a_stall_is_diagnosed_without_changing_anything_when_three_peers_fail_the_same_request_for_ten_minutes() {
    let mut s = StallDetector::new(3, 600_000);
    let sel = Selector::Ref(cref(40, 7));
    for (p, t) in [(1usize, 0u64), (2, 1_000), (3, 2_000)] { s.note_unserved(p, sel, t); }
    assert!(s.stalled(599_999).is_empty(), "not yet ten minutes");
    assert!(s.stalled(600_001).is_empty() || s.stalled(600_001) == vec![sel] && false, "two peers have crossed ten minutes, the third has not");
    assert_eq!(s.stalled(602_001), vec![sel]);
    s.note_served(&sel);
    assert!(s.stalled(10_000_000).is_empty(), "service clears it");
    let mut two = StallDetector::new(3, 10);
    two.note_unserved(1, sel, 0); two.note_unserved(2, sel, 0); two.note_unserved(2, sel, 5);
    assert!(two.stalled(1_000).is_empty(), "only distinct peers count");
}

fn sc(limit: u64) -> ServeConfig { ServeConfig { limit, burst: 2 * limit, refill_per_s: limit / 4 + 1, aggregate_per_s: 4 * limit, max_concurrent: 8, per_peer_outstanding: 4, min_spacing_ms: 100, chunk_size: 262_144 } }

#[test]
fn serve_configuration_invariants_are_checked() {
    let l = 8u64 << 20;
    assert!(sc(l).validate().is_ok());
    assert_eq!(ServeConfig { burst: 2 * l - 1, ..sc(l) }.validate(), Err(ConfigError::BurstBelowTwiceLimit { burst: 2 * l - 1, limit: l }));
    assert!(matches!(ServeConfig { refill_per_s: l / 4 - 1, ..sc(l) }.validate(), Err(ConfigError::RefillTooSlow { .. })));
    assert!(ServeConfig { refill_per_s: l / 4, ..sc(l) }.validate().is_ok(), "exactly a quarter per second is allowed");
    assert_eq!(ServeConfig { aggregate_per_s: l / 4, ..sc(l) }.validate(), Err(ConfigError::AggregateBelowRefill));
    for z in [ServeConfig { limit: 0, ..sc(l) }, ServeConfig { max_concurrent: 0, ..sc(l) }, ServeConfig { per_peer_outstanding: 0, ..sc(l) }, ServeConfig { chunk_size: 0, ..sc(l) }] { assert_eq!(z.validate(), Err(ConfigError::Zero)); }
    assert_eq!(ServeConfig { burst: u64::MAX, limit: u64::MAX, ..sc(l) }.validate(), Err(ConfigError::Overflow));
    assert!(ServeGate::new(ServeConfig { burst: l, ..sc(l) }, 0).is_err(), "the gate refuses an invalid configuration");
    // reservations per request kind
    let c = sc(l);
    assert_eq!(c.reservation(rcodec::KIND_HEADER_REQ), l);
    assert_eq!(c.reservation(rcodec::KIND_CHUNK_REQ), 61 + 262_144);
    assert_eq!(c.reservation(rcodec::KIND_MANIFEST_REQ), 143 + 32 * 65_536);
    assert_eq!(sc(100_000).reservation(rcodec::KIND_MANIFEST_REQ), 100_000, "never above the transport limit");
}

#[test]
fn a_maximum_size_response_is_admissible_reservations_are_refunded_and_busy_hints_are_exact() {
    // 1,000 validators at maximum certificates: the transport limit must be at least 13,272,480
    let l = 13_272_480u64;
    let cfg = sc(l);
    cfg.validate().unwrap();
    assert!(cfg.burst >= 26_544_960 && cfg.refill_per_s * 4 >= l);
    let mut g = ServeGate::new(cfg, 0).unwrap();
    // from a full bucket the maximum response is admitted, and the reservation is refunded down to what was really sent
    let t = g.admit(1, rcodec::KIND_HEADER_REQ, 0).expect("a full bucket admits a maximum response");
    assert_eq!(t.reserved(), l);
    g.finish(t, 50_000);
    // a second maximum response from the same peer is only pre-funded for the remainder: spacing first
    assert_eq!(g.admit(1, rcodec::KIND_HEADER_REQ, 0), Err(chain_forge_consensus::pq_hotstuff::recovery::requests::Busy { retry_after_ms: 100 }));
    let t = g.admit(1, rcodec::KIND_HEADER_REQ, 100).expect("burst is twice the limit and the first was refunded");
    // that one is NOT refunded (maximum size sent): the bucket now holds about 2L - L - 50 KB
    g.finish(t, l);
    let busy = g.admit(1, rcodec::KIND_HEADER_REQ, 200).and_then(|t| { g.finish(t, l); g.admit(1, rcodec::KIND_HEADER_REQ, 300) });
    let b = busy.expect_err("the bucket is empty after three maximum responses");
    // exact hint: milli-byte deficit / refill, to the millisecond
    let expect = {
        // tokens: 2L - 50_000 - ... recompute independently with u128
        let refill = u128::from(cfg.refill_per_s);
        let cap: u128 = u128::from(cfg.burst) * 1000;
        let mut tokens: u128 = cap;
        let spend = |tokens: &mut u128, cost: u64| *tokens -= u128::from(cost) * 1000;
        spend(&mut tokens, l); tokens += u128::from(l - 50_000) * 1000;           // first, refunded to 50_000
        tokens = (tokens + refill * 100).min(cap); spend(&mut tokens, l);          // second at t = 100, fully used (the bucket never exceeds its burst)
        tokens = (tokens + refill * 100).min(cap); spend(&mut tokens, l);          // third at t = 200, fully used
        tokens = (tokens + refill * 100).min(cap);                                 // t = 300
        let need = u128::from(l) * 1000;
        assert!(need > tokens);
        ((need - tokens).div_ceil(refill)) as u64
    };
    assert_eq!(u64::from(b.retry_after_ms), expect, "retry_after_ms is the exact time to the reservation");
    assert!(expect <= 4_000, "a maximum response is admitted within four seconds even from an empty bucket: {expect}");
}

#[test]
fn concurrency_per_peer_outstanding_and_spacing_are_enforced_with_busy_never_silence() {
    let l = 1u64 << 20;
    let cfg = ServeConfig { burst: 64 * l, aggregate_per_s: 64 * l, refill_per_s: 64 * l, ..sc(l) };
    let mut g = ServeGate::new(cfg, 0).unwrap();
    // per-peer outstanding cap of four (spacing 0 for this part)
    let mut g0 = ServeGate::new(ServeConfig { min_spacing_ms: 0, ..cfg }, 0).unwrap();
    let ts: Vec<_> = (0..4).map(|_| g0.admit(1, rcodec::KIND_CHUNK_REQ, 0).unwrap()).collect();
    assert!(g0.admit(1, rcodec::KIND_CHUNK_REQ, 0).is_err(), "a fifth outstanding request from one peer is BUSY");
    for t in ts { g0.finish(t, 100); }
    assert!(g0.admit(1, rcodec::KIND_CHUNK_REQ, 0).is_ok());
    // global concurrency of eight across peers
    let mut g1 = ServeGate::new(ServeConfig { min_spacing_ms: 0, ..cfg }, 0).unwrap();
    let held: Vec<_> = (0..8).map(|p| g1.admit(p, rcodec::KIND_CHUNK_REQ, 0).unwrap()).collect();
    assert_eq!(g1.concurrent(), 8);
    assert!(g1.admit(9, rcodec::KIND_CHUNK_REQ, 0).is_err(), "the ninth concurrent serve is BUSY");
    for t in held { g1.finish(t, 1); }
    assert_eq!(g1.concurrent(), 0);
    // spacing: 100 ms between requests served per peer
    let t = g.admit(1, rcodec::KIND_CHUNK_REQ, 1_000).unwrap();
    g.finish(t, 1);
    assert_eq!(g.admit(1, rcodec::KIND_CHUNK_REQ, 1_050).unwrap_err().retry_after_ms, 50);
    assert!(g.admit(1, rcodec::KIND_CHUNK_REQ, 1_100).is_ok());
    assert!(g.admit(2, rcodec::KIND_CHUNK_REQ, 1_050).is_ok(), "other peers have their own spacing");
}

#[test]
fn the_aggregate_bucket_bounds_total_serving_across_peers() {
    let l = 1u64 << 20;
    let cfg = ServeConfig { burst: 2 * l, refill_per_s: l, aggregate_per_s: l, max_concurrent: 64, per_peer_outstanding: 4, min_spacing_ms: 0, chunk_size: 262_144, limit: l };
    let mut g = ServeGate::new(cfg, 0).unwrap();
    // the aggregate bucket holds 2L: two maximum responses to different peers, then the third peer is BUSY although its own bucket is full
    let a = g.admit(1, rcodec::KIND_HEADER_REQ, 0).unwrap();
    let b = g.admit(2, rcodec::KIND_HEADER_REQ, 0).unwrap();
    let busy = g.admit(3, rcodec::KIND_HEADER_REQ, 0).unwrap_err();
    assert_eq!(u64::from(busy.retry_after_ms), 1000, "L bytes at L bytes/s");
    g.finish(a, l); g.finish(b, l);
    assert!(g.admit(3, rcodec::KIND_HEADER_REQ, 1000).is_ok());
}

// ---- I: staged, generation-bound installation
fn qc_checker() -> QcCheck {
    let f = fx();
    Box::new(move |c: &Cert| {
        let ctx = VerifyCtx { chain_id: CHAIN, set: &f.set, valset_hash: f.vh, genesis: &f.genesis, verifier: &TestVerifier };
        verify_cert(&ctx, c).map_err(|e| e.to_string())
    })
}
fn proof_at(c: &CheckpointRef, salt: u8) -> InstallProof {
    let f = fx();
    let round = 50 + c.height;
    let tip_id = [0xA0u8.wrapping_add(salt); 32];
    let qc = Cert::Qc(qc_for(&f, round, tip_id, [0xB0; 32], round - 1, &[0, 1, 2]));
    InstallProof {
        carrier: ChainPoint { id: [0xC0; 32], height: c.height + 2, round: round - 2, payload_hash: [1; 32] },
        tip: ChainPoint { id: tip_id, height: c.height + 4, round, payload_hash: [2; 32] },
        high_qc: qc,
    }
}
fn interim_snapshot(upto: u64, tag: u8) -> (Vec<u8>, Cursor) {
    let mut a = InterimApp::open(mem(), GENESIS_HASH).unwrap();
    for h in 1..=upto { a.apply(&Committed { id: [tag.wrapping_add(h as u8); 32], round: h, height: h, payload: vec![tag; 8] }).unwrap(); }
    let c = a.cursor();
    (a.storage().raw("app-state").unwrap(), Cursor { height: c.height, block_id: c.block_id, state_root: c.state_digest })
}
fn ref_of(c: &Cursor) -> CheckpointRef { CheckpointRef { height: c.height, block_id: c.block_id, state_root: c.state_root } }

type IInst<A> = Installer<MemTreeFs, A>;
fn mk<A: ShadowApp>(fs: MemTreeFs, app: A) -> IInst<A> { Installer::new(fs, app, GENESIS_HASH, rl(), qc_checker()).expect("installer") }
fn interim() -> InterimShadow { InterimShadow { genesis_hash: GENESIS_HASH } }
fn extras(fs: &mut MemTreeFs) {
    // files that belong to the node, not to the installer: they must never be touched
    fs.set_raw("safety/pq_hotstuff_safety.state", vec![1, 2, 3, 4]);
    fs.set_raw("safety/pq_hotstuff_safety.init", vec![5, 6]);
    fs.set_raw("blocks/blk-aa", vec![7; 40]);
    fs.set_raw("app/app-state", vec![9; 155]);
    fs.set_raw("app/gen-1", vec![1]);
    fs.set_raw("generations-notes.txt", b"mine".to_vec());
    fs.set_raw("install-record.txt", b"mine".to_vec());
}
fn extras_view(fs: &MemTreeFs) -> BTreeMap<String, Vec<u8>> {
    ["safety", "blocks", "app"].iter().flat_map(|d| fs.files_under(d)).chain(["generations-notes.txt", "install-record.txt"].iter().filter_map(|p| fs.raw(p).map(|b| (p.to_string(), b)))).collect()
}
fn fresh_inst() -> IInst<InterimShadow> { let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs); let mut i = mk(fs, interim()); i.start().unwrap(); i }
fn install_interim<F: TreeFs, A: ShadowApp>(i: &mut Installer<F, A>, upto: u64, tag: u8, current: u64) -> Result<(InstallRecord, Cursor), InstallError> {
    let (bytes, cur) = interim_snapshot(upto, tag);
    let c = ref_of(&cur);
    let (m, chunks) = manifest_for(&bytes, 64, &c);
    i.begin(c, m, current)?;
    for (n, ch) in chunks.iter().enumerate() { i.put_chunk(n as u32, ch)?; }
    Ok((i.finish(proof_at(&c, tag))?, cur))
}

#[test]
fn one_snapshot_installs_publishes_state_and_cursor_together_and_leaves_the_node_s_own_files_alone() {
    let mut i = fresh_inst();
    let before = extras_view(&i.fs);
    let (rec, cur) = install_interim(&mut i, 40, 1, 0).unwrap();
    assert_eq!((rec.generation, i.generation()), (1, 1));
    assert_eq!(rec.cref, ref_of(&cur));
    let p = AppPointer::decode(&i.fs.raw("app-current").unwrap()).unwrap();
    assert_eq!((p.generation, p.cursor, p.record_digest), (1, cur, rec.digest()), "the pointer publishes the cursor and names the record");
    assert_eq!(RecoveryState::decode(&i.fs.raw("recovery.state").unwrap()).unwrap().phase, Phase::Published);
    assert!(interim().measure(&i.fs, &gen_dir(1)).unwrap() == cur, "the live tree measures to the authenticated cursor");
    i.complete_seed().unwrap();
    assert_eq!(RecoveryState::decode(&i.fs.raw("recovery.state").unwrap()).unwrap(), RecoveryState::idle(1));
    assert!(i.fs.list("staging").unwrap().is_empty(), "staging is cleaned");
    assert_eq!(i.fs.list("generations").unwrap(), vec!["gen-00000000000000000001".to_string()]);
    assert_eq!(extras_view(&i.fs), before, "safety, blocks, the operational app directory and look-alike names are byte-identical");
    // a restart finds it Idle at generation 1
    let fs = i.into_fs();
    let mut j = mk(fs, interim());
    assert_eq!(j.start().unwrap(), StartOutcome::Idle { generation: 1 });
    assert_eq!(extras_view(&j.fs), before);
}

#[test]
fn two_successive_installs_each_bind_their_own_generation_and_the_second_replaces_the_first() {
    let mut i = fresh_inst();
    let before = extras_view(&i.fs);
    let (r1, c1) = install_interim(&mut i, 40, 1, 0).unwrap();
    i.complete_seed().unwrap();
    let rec1_bytes = r1.encode();
    // the executor ran on from the first snapshot to height 55, then the second snapshot (height 80) arrives
    let (r2, c2) = install_interim(&mut i, 80, 2, 55).unwrap();
    assert_eq!((r1.generation, r2.generation), (1, 2));
    assert_ne!(r1.digest(), r2.digest());
    assert!(c2.height > c1.height);
    let p = AppPointer::decode(&i.fs.raw("app-current").unwrap()).unwrap();
    assert_eq!((p.generation, p.cursor, p.record_digest), (2, c2, r2.digest()));
    assert_eq!(i.fs.list("generations").unwrap().len(), 2, "until the engine is seeded both generations exist");
    i.complete_seed().unwrap();
    assert_eq!(i.fs.list("generations").unwrap(), vec!["gen-00000000000000000002".to_string()], "the first generation is gone after the second is seeded");
    assert!(i.fs.raw(&record_path(1)).is_none() && i.fs.raw(&record_path(2)).is_some(), "the first record is replaced by the second");
    assert_eq!(interim().measure(&i.fs, &gen_dir(2)).unwrap(), c2);
    assert_eq!(extras_view(&i.fs), before);
    // a restart sees generation 2
    let mut j = mk(i.into_fs(), interim());
    assert_eq!(j.start().unwrap(), StartOutcome::Idle { generation: 2 });
    // the first generation's record cannot stand in for the second's, even though it is perfectly well formed
    let mut stale = j.fs.clone();
    stale.faults = tfaults();
    stale.set_raw(&record_path(2), rec1_bytes);
    let mut k = mk(stale, interim());
    match k.start() { Err(InstallError::Refuse(m)) => assert!(m.contains("generation 1") && m.contains("generation 2"), "{m}"), other => panic!("a stale record was accepted: {other:?}") }
}

#[test]
fn two_successive_installs_on_a_real_directory_leave_a_state_the_interim_executor_can_open_and_continue_from() {
    let root = std::env::temp_dir().join(format!("cf-pq-install-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut i = Installer::new(StdTreeFs::new(&root).unwrap(), interim(), GENESIS_HASH, rl(), qc_checker()).unwrap();
    assert_eq!(i.start().unwrap(), StartOutcome::Idle { generation: 0 });
    let (_, c1) = install_interim(&mut i, 40, 1, 0).unwrap();
    i.complete_seed().unwrap();
    let (r2, c2) = install_interim(&mut i, 80, 2, 55).unwrap();
    i.complete_seed().unwrap();
    assert_eq!(r2.generation, 2);
    // the installed directory IS an interim-application state directory: open it with the real executor and execute the next block
    let dir = root.join("generations").join("gen-00000000000000000002");
    let mut app = InterimApp::open(FsStorage::new(&dir).unwrap(), GENESIS_HASH).unwrap();
    assert_eq!((app.cursor().height, app.cursor().block_id, app.cursor().state_digest), (c2.height, c2.block_id, c2.state_root));
    let next = app.apply(&Committed { id: [0xEE; 32], round: 81, height: c2.height + 1, payload: b"after the snapshot".to_vec() }).unwrap();
    assert_eq!(next.height, c2.height + 1);
    assert!(c2.height > c1.height);
    // and a fresh process over the same directory recovers to Idle(2)
    let mut again = Installer::new(StdTreeFs::new(&root).unwrap(), interim(), GENESIS_HASH, rl(), qc_checker()).unwrap();
    assert_eq!(again.start().unwrap(), StartOutcome::Idle { generation: 2 });
    let _ = std::fs::remove_dir_all(&root);
}

fn two_installs() -> (MemTreeFs, InstallRecord, InstallRecord) {
    let mut i = fresh_inst();
    let (r1, _) = install_interim(&mut i, 40, 1, 0).unwrap();
    i.complete_seed().unwrap();
    let (r2, _) = install_interim(&mut i, 80, 2, 55).unwrap();
    i.complete_seed().unwrap();
    (i.into_fs(), r1, r2)
}
fn started(fs: MemTreeFs) -> Result<StartOutcome, InstallError> { let mut fs = fs; fs.faults = tfaults(); mk(fs, interim()).start() }
fn refused(fs: &MemTreeFs, what: &str) -> String {
    let before = fs.snapshot();
    let r = { let mut f = fs.clone(); f.faults = tfaults(); let mut i = mk(f, interim()); let r = i.start(); (r, i.into_fs().snapshot()) };
    match r.0 { Err(InstallError::Refuse(m)) => { assert_eq!(r.1, before, "{what}: a refusal must change and delete nothing"); m } other => panic!("{what}: expected a refusal, got {other:?}") }
}

#[test]
fn stale_forged_or_mismatched_records_and_pointers_are_refused_and_nothing_is_deleted() {
    let (good, r1, r2) = two_installs();
    assert!(matches!(started(good.clone()), Ok(StartOutcome::Idle { generation: 2 })));
    let ptr2 = AppPointer::decode(&good.raw("app-current").unwrap()).unwrap();
    let set = |fs: &MemTreeFs, p: &str, b: Vec<u8>| { let mut f = fs.clone(); f.faults = tfaults(); f.set_raw(p, b); f };
    // a well-formed record of another generation in this generation's place
    assert!(refused(&set(&good, &record_path(2), r1.encode()), "stale record").contains("generation 1"));
    // the old pointer with the old record gone
    let old_ptr = AppPointer { generation: 1, cursor: Cursor { height: r1.cref.height, block_id: r1.cref.block_id, state_root: r1.cref.state_root }, record_digest: r1.digest() };
    assert!(refused(&set(&good, "app-current", old_ptr.encode()), "old pointer").contains("generation 1"));
    // a record changed in a way its integrity tag does not notice (the attacker recomputes the tag): the pointer's digest no longer matches
    let mut tampered = r2.clone(); tampered.tip.height += 1;
    { let m = refused(&set(&good, &record_path(2), tampered.encode()), "tampered record, old digest"); assert!(m.contains("does not name this install record"), "{m}"); }
    // an attacker with write access who ALSO fixes the pointer's digest: the certificate is re-verified cryptographically
    let mut forged = r2.clone();
    if let Cert::Qc(q) = &mut forged.high_qc { q.sigs[0][5] ^= 1; }
    let fixed = AppPointer { record_digest: forged.digest(), ..ptr2 };
    let fs = set(&set(&good, &record_path(2), forged.encode()), "app-current", fixed.encode());
    assert!(refused(&fs, "forged certificate").contains("certificate"));
    // a valid QC that certifies some other block than the record's tip
    let f = fx();
    let mut other = r2.clone();
    other.high_qc = Cert::Qc(qc_for(&f, other.tip.round, [0x55; 32], [0x56; 32], other.tip.round - 1, &[0, 1, 2]));
    let fs = set(&set(&good, &record_path(2), other.encode()), "app-current", AppPointer { record_digest: other.digest(), ..ptr2 }.encode());
    assert!(refused(&fs, "certificate for another block").contains("does not certify the tip"));
    // a pointer whose cursor disagrees with the record's reference
    let skew = AppPointer { cursor: Cursor { state_root: [0x77; 32], ..ptr2.cursor }, ..ptr2 };
    assert!(refused(&set(&good, "app-current", skew.encode()), "skewed cursor").contains("cursor differs"));
    // the generation directory is missing
    let mut nodir = good.clone(); nodir.faults = tfaults(); nodir.delete_raw(&gen_dir(2));
    assert!(refused(&nodir, "missing directory").contains("missing"));
    // damaged bytes anywhere (integrity tag)
    for p in ["recovery.state", "app-current", &record_path(2)] {
        let mut b = good.raw(p).unwrap(); let mid = b.len() / 2; b[mid] ^= 1;
        refused(&set(&good, p, b), &format!("damaged {p}"));
        let b = good.raw(p).unwrap(); refused(&set(&good, p, b[..b.len() - 1].to_vec()), &format!("truncated {p}"));
    }
    // recovery.state inconsistent with the pointer
    let st = |phase: Phase, generation: u64| RecoveryState { phase, generation, cref: r2.cref, snapshot_id: [0; 32] }.encode();
    refused(&set(&good, "recovery.state", RecoveryState::idle(1).encode()), "idle at the old generation");
    refused(&set(&good, "recovery.state", st(Phase::Staging, 5)), "staging far ahead");
    refused(&set(&good, "recovery.state", st(Phase::Staging, 2)), "staging the published generation");
    let mut nostate = good.clone(); nostate.faults = tfaults(); nostate.delete_raw("recovery.state");
    assert!(refused(&nostate, "pointer without state").contains("without recovery.state"));
    // Published at the pointer's generation is the legitimate "engine not seeded yet" state
    match started(set(&good, "recovery.state", st(Phase::Published, 2))) { Ok(StartOutcome::NeedsSeed { record }) => assert_eq!(record.generation, 2), other => panic!("{other:?}") }
}

#[test]
fn installs_go_forward_only_and_a_bad_manifest_or_chunk_is_rejected_before_anything_is_published() {
    let mut i = fresh_inst();
    let (bytes, cur) = interim_snapshot(40, 1);
    let c = ref_of(&cur);
    let (m, chunks) = manifest_for(&bytes, 64, &c);
    // not forward: the executor is already at or above the reference
    for current in [40u64, 41, 1_000] { assert!(matches!(i.begin(c, m.clone(), current), Err(InstallError::Rejected(r)) if r.contains("not forward")), "current {current}"); }
    // a snapshot id that does not match the manifest and reference
    let mut bad_id = m.clone(); bad_id.snapshot_id[0] ^= 1;
    assert!(matches!(i.begin(c, bad_id, 0), Err(InstallError::Rejected(r)) if r.contains("snapshot id"))); 
    let other_ref = CheckpointRef { state_root: [0x42; 32], ..c };
    assert!(matches!(i.begin(other_ref, m.clone(), 0), Err(InstallError::Rejected(_))), "a manifest id is bound to its reference");
    let mut bad_hash = m.clone(); bad_hash.chunk_hashes[1][0] ^= 1;
    assert!(matches!(i.begin(c, bad_hash, 0), Err(InstallError::Rejected(_))), "the id covers the chunk hashes");
    let mut bad_shape = m.clone(); bad_shape.chunk_count = 0;
    assert!(matches!(i.begin(c, bad_shape, 0), Err(InstallError::Rejected(_))));
    assert!(i.fs.raw("recovery.state").is_none(), "nothing was written by any rejected begin");
    // put_chunk and finish before begin
    assert!(matches!(i.put_chunk(0, &chunks[0]), Err(InstallError::Rejected(_))));
    // a good begin, then bad chunks
    i.begin(c, m.clone(), 0).unwrap();
    assert!(matches!(i.begin(c, m.clone(), 0), Err(InstallError::Rejected(r)) if r.contains("in progress")));
    assert!(matches!(i.put_chunk(99, &chunks[0]), Err(InstallError::Rejected(_))), "index out of range");
    assert!(matches!(i.put_chunk(0, &chunks[0][..63]), Err(InstallError::Rejected(r)) if r.contains("length")));
    let mut wrong = chunks[0].clone(); wrong[0] ^= 1;
    assert!(matches!(i.put_chunk(0, &wrong), Err(InstallError::Rejected(r)) if r.contains("hash")));
    assert!(matches!(i.put_chunk(1, &chunks[0]), Err(InstallError::Rejected(r)) if r.contains("hash")), "a valid chunk at the wrong index");
    i.put_chunk(0, &chunks[0]).unwrap();
    assert!(matches!(i.put_chunk(0, &chunks[0]), Err(InstallError::Rejected(r)) if r.contains("duplicate")));
    assert!(matches!(i.finish(proof_at(&c, 1)), Err(InstallError::Rejected(r)) if r.contains("not all chunks")), "finish needs every chunk");
    i.abort().unwrap();
    assert_eq!(RecoveryState::decode(&i.fs.raw("recovery.state").unwrap()).unwrap(), RecoveryState::idle(0));
    assert!(i.fs.list("staging").unwrap().is_empty() && i.fs.raw("app-current").is_none());
    // after a completed install, the same reference is no longer forward
    let (_, cur2) = install_interim(&mut i, 40, 1, 0).unwrap();
    i.complete_seed().unwrap();
    let (m2, _) = manifest_for(&interim_snapshot(40, 1).0, 64, &ref_of(&cur2));
    assert!(matches!(i.begin(ref_of(&cur2), m2, 0), Err(InstallError::Rejected(r)) if r.contains("not forward")), "not above the installed cursor even if the caller's height is stale");
}

#[test]
fn a_staged_state_that_does_not_match_the_authenticated_reference_publishes_nothing() {
    let mut i = fresh_inst();
    let (r1, c1) = install_interim(&mut i, 40, 1, 0).unwrap();
    i.complete_seed().unwrap();
    let live_before = i.fs.files_under("generations");
    let ptr_before = i.fs.raw("app-current").unwrap();
    // chunks that satisfy their own manifest, but the data is a DIFFERENT chain than the authenticated reference claims
    let (bytes_b, cur_b) = interim_snapshot(80, 2);
    let claimed = CheckpointRef { height: cur_b.height, block_id: cur_b.block_id, state_root: [0x99; 32] };
    let (m, chunks) = manifest_for(&bytes_b, 64, &claimed);
    i.begin(claimed, m, 55).unwrap();
    for (n, c) in chunks.iter().enumerate() { i.put_chunk(n as u32, c).unwrap(); }
    match i.finish(proof_at(&claimed, 2)) { Err(InstallError::Aborted(m)) => assert!(m.contains("does not match the authenticated reference"), "{m}"), other => panic!("{other:?}") }
    assert_eq!(i.fs.files_under("generations"), live_before, "the live generation is untouched");
    assert_eq!(i.fs.raw("app-current").unwrap(), ptr_before, "the pointer is untouched");
    assert!(i.fs.raw(&record_path(2)).is_none() && i.fs.list("staging").unwrap().is_empty());
    assert_eq!(RecoveryState::decode(&i.fs.raw("recovery.state").unwrap()).unwrap(), RecoveryState::idle(1));
    assert_eq!(i.generation(), 1);
    // the claimed height differs from the data's height
    let (bytes_c, cur_c) = interim_snapshot(60, 3);
    let wrong_height = CheckpointRef { height: cur_c.height + 1, ..ref_of(&cur_c) };
    let (m, chunks) = manifest_for(&bytes_c, 64, &wrong_height);
    i.begin(wrong_height, m, 55).unwrap();
    for (n, c) in chunks.iter().enumerate() { i.put_chunk(n as u32, c).unwrap(); }
    assert!(matches!(i.finish(proof_at(&wrong_height, 3)), Err(InstallError::Aborted(_))));
    // a snapshot that is not an application state at all
    let junk = vec![0xABu8; 200];
    let jref = CheckpointRef { height: 70, block_id: [1; 32], state_root: [2; 32] };
    let (m, chunks) = manifest_for(&junk, 64, &jref);
    i.begin(jref, m, 55).unwrap();
    for (n, c) in chunks.iter().enumerate() { i.put_chunk(n as u32, c).unwrap(); }
    match i.finish(proof_at(&jref, 4)) { Err(InstallError::Aborted(m)) => assert!(m.contains("measure"), "{m}"), other => panic!("{other:?}") }
    // after all that, the honest snapshot still installs, as generation 2
    let (r2, _) = install_interim(&mut i, 80, 2, 55).unwrap();
    assert_eq!(r2.generation, 2);
    let _ = (r1, c1);
}

#[test]
fn an_invalid_proof_aborts_the_install_before_the_shadow_state_is_built() {
    let (bytes, cur) = interim_snapshot(40, 1);
    let c = ref_of(&cur);
    let (m, chunks) = manifest_for(&bytes, 64, &c);
    let f = fx();
    let cases: Vec<(&str, Box<dyn Fn(&mut InstallProof)>)> = vec![
        ("forged certificate", Box::new(|p| if let Cert::Qc(q) = &mut p.high_qc { q.sigs[1][9] ^= 1; })),
        ("certificate for another block", Box::new(move |p| p.high_qc = Cert::Qc(qc_for(&f, p.tip.round, [0x66; 32], [0x67; 32], p.tip.round - 1, &[0, 1, 2])))),
        ("the genesis certificate", Box::new(|p| p.high_qc = Cert::Genesis(fx().genesis))),
        ("tip below the carrier", Box::new(|p| p.tip.height = p.carrier.height - 1)),
        ("carrier below the reference", Box::new(move |p| p.carrier.height = c.height - 1)),
    ];
    for (label, tweak) in cases {
        let mut i = fresh_inst();
        i.begin(c, m.clone(), 0).unwrap();
        for (n, ch) in chunks.iter().enumerate() { i.put_chunk(n as u32, ch).unwrap(); }
        let mut p = proof_at(&c, 1);
        tweak(&mut p);
        assert!(matches!(i.finish(p), Err(InstallError::Aborted(_))), "{label}");
        assert!(i.fs.raw("app-current").is_none() && i.fs.list("generations").unwrap().is_empty() && i.fs.list("staging").unwrap().is_empty(), "{label}: nothing remains");
    }
}

// ---- a multi-file, nested test application (to exercise the flush barrier over subdirectories)
fn tree_root(files: &BTreeMap<String, Vec<u8>>) -> [u8; 32] {
    let mut parts = vec![];
    for (p, d) in files { parts.extend_from_slice(&(p.len() as u32).to_be_bytes()); parts.extend_from_slice(p.as_bytes()); parts.extend_from_slice(&rcodec::sha3(&[d])); }
    rcodec::sha3(&[b"TREE", &parts])
}
fn serialize_tree(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut o = vec![];
    for (p, d) in files { o.extend_from_slice(&(p.len() as u16).to_be_bytes()); o.extend_from_slice(p.as_bytes()); o.extend_from_slice(&(d.len() as u32).to_be_bytes()); o.extend_from_slice(d); }
    o
}
fn parse_tree(mut b: &[u8]) -> Option<BTreeMap<String, Vec<u8>>> {
    let mut m = BTreeMap::new();
    while !b.is_empty() {
        let pl = u16::from_be_bytes(b.get(..2)?.try_into().ok()?) as usize; b = &b[2..];
        let p = String::from_utf8(b.get(..pl)?.to_vec()).ok()?; b = &b[pl..];
        let dl = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize; b = &b[4..];
        m.insert(p, b.get(..dl)?.to_vec()); b = &b[dl..];
    }
    Some(m)
}
fn walk_files(fs: &dyn TreeFs, dir: &str, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
    for n in fs.list(dir).unwrap() {
        let p = format!("{dir}/{n}");
        let rel = if prefix.is_empty() { n.clone() } else { format!("{prefix}/{n}") };
        if fs.is_dir(&p) { walk_files(fs, &p, &rel, out); } else { out.insert(rel, fs.read(&p).unwrap().unwrap()); }
    }
}
#[derive(Clone)]
struct TreeShadow;
impl ShadowApp for TreeShadow {
    fn assemble(&self, fs: &mut dyn TreeFs, chunks_dir: &str, manifest: &Manifest, out_dir: &str) -> Result<(), String> {
        let mut all = vec![];
        for i in 0..manifest.chunk_count { all.extend_from_slice(&fs.read(&format!("{chunks_dir}/chunk-{i:05}")).map_err(|e| e.0)?.ok_or("missing chunk")?); }
        let files = parse_tree(&all).ok_or("bad tree")?;
        fs.mkdir_all(out_dir).map_err(|e| e.0)?;
        for (p, d) in files {
            let full = format!("{out_dir}/{p}");
            fs.mkdir_all(chain_forge_consensus::pq_hotstuff::recovery::tree::parent_of(&full)).map_err(|e| e.0)?;
            fs.write_file(&full, &d).map_err(|e| e.0)?;
        }
        Ok(())
    }
    fn measure(&self, fs: &dyn TreeFs, state_dir: &str) -> Result<Cursor, String> {
        let mut files = BTreeMap::new();
        walk_files(fs, state_dir, "", &mut files);
        let c = files.get("meta/cursor").ok_or("no cursor")?;
        if c.len() != 40 { return Err("cursor length".into()); }
        Ok(Cursor { height: u64::from_be_bytes(c[..8].try_into().unwrap()), block_id: c[8..].try_into().unwrap(), state_root: tree_root(&files) })
    }
}
fn tree_files(height: u64, tag: u8) -> (BTreeMap<String, Vec<u8>>, Cursor) {
    let mut f = BTreeMap::new();
    let mut cur = height.to_be_bytes().to_vec(); cur.extend_from_slice(&[tag; 32]);
    f.insert("meta/cursor".to_string(), cur);
    f.insert("index".to_string(), vec![tag; 70]);
    f.insert("data/a".to_string(), vec![tag.wrapping_add(1); 90]);
    f.insert("data/sub/b".to_string(), vec![tag.wrapping_add(2); 130]);
    f.insert("data/sub/deep/c".to_string(), vec![tag.wrapping_add(3); 50]);
    f.insert("data/sub/deep/d".to_string(), vec![tag.wrapping_add(4); 10]);
    let root = tree_root(&f);
    (f, Cursor { height, block_id: [tag; 32], state_root: root })
}
fn install_tree<F: TreeFs, A: ShadowApp>(i: &mut Installer<F, A>, height: u64, tag: u8, current: u64) -> Result<(InstallRecord, Cursor), InstallError> {
    let (files, cur) = tree_files(height, tag);
    let c = ref_of(&cur);
    let (m, chunks) = manifest_for(&serialize_tree(&files), 100, &c);
    i.begin(c, m, current)?;
    for (n, ch) in chunks.iter().enumerate() { i.put_chunk(n as u32, ch)?; }
    Ok((i.finish(proof_at(&c, tag))?, cur))
}

#[test]
fn the_flush_barrier_covers_every_file_and_every_directory_of_the_shadow_tree() {
    // a clean run, to learn the tree's paths and the staging identifier
    let mut probe = mk(MemTreeFs::new(tfaults()), TreeShadow);
    probe.start().unwrap();
    let (files, cur) = tree_files(500, 1);
    let c = ref_of(&cur);
    let (m, _) = manifest_for(&serialize_tree(&files), 100, &c);
    let stage = format!("staging/{}", m.snapshot_id.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let state = format!("{stage}/state");
    let mut targets: Vec<String> = files.keys().map(|p| format!("{state}/{p}")).collect();
    targets.extend(["", "meta", "data", "data/sub", "data/sub/deep"].iter().map(|d| if d.is_empty() { state.clone() } else { format!("{state}/{d}") }));
    assert!(targets.len() >= 11);
    for t in &targets {
        let mut fs = MemTreeFs::new(tfaults());
        extras(&mut fs);
        fs.faults.borrow_mut().fail_sync.insert(t.clone());
        let mut i = mk(fs, TreeShadow);
        i.start().unwrap();
        // the failing fsync of a CHUNK file or of the staging directory while chunks arrive is a different (earlier) failure; only barrier paths are expected here
        let r = install_tree(&mut i, 500, 1, 0);
        match r {
            Err(InstallError::Aborted(msg)) => assert!(msg.contains("flush"), "{t}: {msg}"),
            other => panic!("a failing fsync of {t} must abort the install, got {other:?}"),
        }
        assert!(i.fs.raw("app-current").is_none() && i.fs.raw(&record_path(1)).is_none(), "{t}: no pointer or record");
        assert!(i.fs.list("generations").unwrap().is_empty(), "{t}: no live generation");
        assert!(i.fs.list("staging").unwrap().is_empty(), "{t}: staging cleaned");
        assert_eq!(RecoveryState::decode(&i.fs.raw("recovery.state").unwrap()).unwrap(), RecoveryState::idle(0), "{t}");
    }
    // the staging directory and its parent are also synced while chunks arrive (and by begin), so their failure surfaces EARLIER, as an I/O error from
    // begin or put_chunk: still fail closed, with no record and no pointer
    for t in [stage.clone(), "staging".to_string()] {
        let fs = MemTreeFs::new(tfaults());
        let mut i = mk(fs, TreeShadow);
        i.start().unwrap();
        i.fs.faults.borrow_mut().fail_sync.insert(t.clone());
        assert!(matches!(install_tree(&mut i, 500, 1, 0), Err(InstallError::Fs(_))), "{t}");
        assert!(i.fs.raw("app-current").is_none() && i.fs.raw(&record_path(1)).is_none() && i.fs.list("generations").unwrap().is_empty(), "{t}");
    }
    // and without a fault the same install publishes
    let mut ok = mk(MemTreeFs::new(tfaults()), TreeShadow);
    ok.start().unwrap();
    let (rec, cur) = install_tree(&mut ok, 500, 1, 0).unwrap();
    assert_eq!(TreeShadow.measure(&ok.fs, &gen_dir(rec.generation)).unwrap(), cur);
}

// ---- the crash matrix
fn crash_matrix<A: ShadowApp + Clone>(label: &str, app: A, prep: &dyn Fn() -> MemTreeFs, prev_gen: u64, prev_cursor: Option<Cursor>, new_cursor: Cursor, run: &dyn Fn(&mut IInst<A>) -> Result<InstallRecord, InstallError>) {
    let unrelated = extras_view(&prep());
    let total = {
        let mut i = mk(prep(), app.clone()); i.start().unwrap();
        let base = i.fs.faults.borrow().ops;
        run(&mut i).unwrap(); i.complete_seed().unwrap();
        let t = i.fs.faults.borrow().ops - base;
        t
    };
    assert!(total > 25, "{label}: only {total} operations");
    let (mut idle_prev, mut needs_seed, mut done, mut crashed_runs, mut outcomes) = (0, 0, 0, 0, 0);
    for k in 0..=total {
        let mut i = mk(prep(), app.clone()); i.start().unwrap();
        let base = i.fs.faults.borrow().ops;
        i.fs.faults.borrow_mut().crash_before = Some(base + k);
        let r = run(&mut i).and_then(|_| i.complete_seed());
        if r.is_err() { crashed_runs += 1; }
        let fs = i.into_fs();
        for (j, out) in fs.crash_outcomes(12).into_iter().enumerate() {
            outcomes += 1;
            let ctx = format!("{label}: crash before op {k}, outcome {j}");
            let mut inst = mk(out, app.clone());
            let first = inst.start().unwrap_or_else(|e| panic!("{ctx}: a crash outcome of a correct install must recover, not refuse: {e}"));
            match &first {
                StartOutcome::Idle { generation } if *generation == prev_gen => {
                    idle_prev += 1;
                    assert_eq!(inst.pointer().map(|p| p.cursor), prev_cursor, "{ctx}: the previous cursor is intact");
                    if let Some(pc) = prev_cursor { assert_eq!(app.measure(&inst.fs, &gen_dir(prev_gen)).unwrap(), pc, "{ctx}: the previous live state is intact"); }
                    let gens: Vec<String> = inst.fs.list("generations").unwrap();
                    assert_eq!(gens.len(), usize::from(prev_gen > 0), "{ctx}: only the previous generation remains: {gens:?}");
                    assert!(inst.fs.list("staging").unwrap().is_empty(), "{ctx}: staging cleaned");
                    // liveness: the install can simply be run again
                    let mut again = mk(inst.fs.clone(), app.clone());
                    again.fs.faults = tfaults();
                    again.start().unwrap();
                    let rec = run(&mut again).unwrap_or_else(|e| panic!("{ctx}: re-running the install failed: {e}"));
                    assert_eq!(rec.generation, prev_gen + 1);
                    assert_eq!(app.measure(&again.fs, &gen_dir(prev_gen + 1)).unwrap(), new_cursor, "{ctx}");
                }
                StartOutcome::NeedsSeed { record } => {
                    needs_seed += 1;
                    assert_eq!(record.generation, prev_gen + 1, "{ctx}");
                    assert_eq!(record.cref, ref_of(&new_cursor), "{ctx}");
                    assert_eq!(app.measure(&inst.fs, &gen_dir(prev_gen + 1)).unwrap(), new_cursor, "{ctx}: the published tree is complete");
                    inst.complete_seed().unwrap();
                    assert_eq!(inst.fs.list("generations").unwrap().len(), 1, "{ctx}");
                }
                StartOutcome::Idle { generation } if *generation == prev_gen + 1 => {
                    done += 1;
                    assert_eq!(app.measure(&inst.fs, &gen_dir(*generation)).unwrap(), new_cursor, "{ctx}");
                }
                other => panic!("{ctx}: unexpected {other:?}"),
            }
            // restart again: stable, and the node's own files are untouched
            let second = inst.start().unwrap_or_else(|e| panic!("{ctx}: second start refused: {e}"));
            assert!(matches!(second, StartOutcome::Idle { .. }) || matches!(first, StartOutcome::NeedsSeed { .. }), "{ctx}");
            assert_eq!(extras_view(&inst.fs), unrelated, "{ctx}: the node's own files are byte-identical");
        }
    }
    assert!(crashed_runs >= total as i32 - 2 && idle_prev > 0 && needs_seed > 0 && done > 0, "{label}: crashed_runs {crashed_runs}/{total}, idle_prev {idle_prev}, needs_seed {needs_seed}, done {done}");
    assert!(outcomes > 2 * total, "{label}: only {outcomes} crash outcomes were examined for {total} crash points");
    println!("crash matrix [{label}]: {total} crash points, {outcomes} outcomes ({idle_prev} recovered to the previous generation, {needs_seed} to a published generation awaiting the engine, {done} to a completed install)");
}

#[test]
fn a_crash_at_any_point_of_the_first_install_recovers_to_the_old_state_or_a_complete_new_one() {
    let (_, cur) = interim_snapshot(40, 1);
    crash_matrix("first interim install", interim(), &|| { let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs); fs }, 0, None, cur, &|i| install_interim(i, 40, 1, 0).map(|r| r.0));
}

#[test]
fn a_crash_at_any_point_of_a_second_install_never_disturbs_the_first_generation_or_mixes_the_two() {
    let (_, c1) = interim_snapshot(40, 1);
    let (_, c2) = interim_snapshot(80, 2);
    let prep = || { let mut i = fresh_inst(); install_interim(&mut i, 40, 1, 0).unwrap(); i.complete_seed().unwrap(); i.into_fs() };
    crash_matrix("second interim install", interim(), &prep, 1, Some(c1), c2, &|i| install_interim(i, 80, 2, 55).map(|r| r.0));
}

#[test]
fn a_crash_at_any_point_of_a_nested_multi_file_install_never_publishes_a_torn_tree() {
    let (_, c1) = tree_files(500, 1);
    let (_, c2) = tree_files(900, 2);
    let prep = || { let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs); let mut i = mk(fs, TreeShadow); i.start().unwrap(); install_tree(&mut i, 500, 1, 0).unwrap(); i.complete_seed().unwrap(); i.into_fs() };
    crash_matrix("nested tree, second install", TreeShadow, &prep, 1, Some(c1), c2, &|i| install_tree(i, 900, 2, 600).map(|r| r.0));
    let prep0 = || { let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs); fs };
    crash_matrix("nested tree, first install", TreeShadow, &prep0, 0, None, c1, &|i| install_tree(i, 500, 1, 0).map(|r| r.0));
}

#[test]
fn installer_construction_refuses_a_split_filesystem_and_start_is_required_before_begin() {
    let mut fs = MemTreeFs::new(tfaults());
    fs.devices_differ = true;
    assert!(matches!(Installer::new(fs, interim(), GENESIS_HASH, rl(), qc_checker()), Err(InstallError::Refuse(m)) if m.contains("different filesystems")));
    let mut i = mk(MemTreeFs::new(tfaults()), interim());
    let (bytes, cur) = interim_snapshot(40, 1);
    let (m, _) = manifest_for(&bytes, 64, &ref_of(&cur));
    assert!(matches!(i.begin(ref_of(&cur), m, 0), Err(InstallError::Rejected(r)) if r.contains("start()")));
    // complete_seed and abort with nothing to do
    i.start().unwrap();
    assert!(matches!(i.complete_seed(), Err(InstallError::Rejected(_))));
    assert!(matches!(i.abort(), Err(InstallError::Rejected(_))));
}

#[test]
fn the_installer_never_touches_the_safety_store_and_garbage_collection_removes_only_its_own_names() {
    let mut fs = MemTreeFs::new(tfaults());
    extras(&mut fs);
    // look-alike names that are NOT the installer's: they must survive every garbage collection
    fs.set_raw("generations/notes.txt", b"keep".to_vec());
    fs.set_raw("generations/gen-1", b"keep".to_vec());
    fs.set_raw("generations/gen-0000000000000000000x", b"keep".to_vec());
    fs.set_raw("staging/README", b"keep".to_vec());
    fs.set_raw("staging/ABCDEF", b"keep".to_vec());
    fs.set_raw("install-record.7", b"keep".to_vec());
    fs.set_raw("recovery.state.bak", b"keep".to_vec());
    let safety: BTreeMap<String, Vec<u8>> = fs.files_under("safety");
    let mut i = mk(fs, interim());
    i.start().unwrap();
    install_interim(&mut i, 40, 1, 0).unwrap();
    i.complete_seed().unwrap();
    install_interim(&mut i, 80, 2, 55).unwrap();
    i.complete_seed().unwrap();
    for keep in ["generations/notes.txt", "generations/gen-1", "generations/gen-0000000000000000000x", "staging/README", "staging/ABCDEF", "install-record.7", "recovery.state.bak"] {
        assert_eq!(i.fs.raw(keep).as_deref(), Some(&b"keep"[..]), "{keep} was removed");
    }
    assert_eq!(i.fs.files_under("safety"), safety);
}

#[test]
fn a_refunded_reservation_is_visible_in_what_the_next_requests_can_use() {
    let l = 1u64 << 20;
    let cfg = ServeConfig { burst: 2 * l, refill_per_s: l, aggregate_per_s: 8 * l, max_concurrent: 8, per_peer_outstanding: 4, min_spacing_ms: 0, chunk_size: 262_144, limit: l };
    let mut g = ServeGate::new(cfg, 0).unwrap();
    let a = g.admit(1, rcodec::KIND_HEADER_REQ, 0).unwrap();
    g.finish(a, 50_000); // a response of 50,000 bytes was sent: l - 50,000 bytes are returned to the bucket
    let b = g.admit(1, rcodec::KIND_HEADER_REQ, 0).expect("with the refund the bucket still holds a full reservation");
    // 2L - 50,000 - L = L - 50,000 remain; a third full reservation waits exactly for the 50,000-byte shortfall: ceil(50,000 x 1000 / rate) ms
    let busy = g.admit(1, rcodec::KIND_HEADER_REQ, 0).unwrap_err();
    assert_eq!(u64::from(busy.retry_after_ms), (50_000u128 * 1000).div_ceil(u128::from(cfg.refill_per_s)) as u64);
    g.finish(b, l);
    // a refund never lifts the bucket above its burst (fresh gate: the aggregate bucket is shared by all peers)
    let mut g = ServeGate::new(cfg, 0).unwrap();
    let c = g.admit(2, rcodec::KIND_HEADER_REQ, 0).unwrap();
    g.finish(c, 0);
    let d = g.admit(2, rcodec::KIND_HEADER_REQ, 0).unwrap();
    let e = g.admit(2, rcodec::KIND_HEADER_REQ, 0).unwrap();
    assert!(g.admit(2, rcodec::KIND_HEADER_REQ, 0).is_err(), "at most 2L is ever available to one peer");
    g.finish(d, 0); g.finish(e, 0);
}

#[test]
fn a_published_tree_is_re_measured_after_a_crash_window_and_refused_if_it_was_damaged() {
    let (good, _r1, r2) = two_installs();
    let set = |fs: &MemTreeFs, p: &str, b: Vec<u8>| { let mut f = fs.clone(); f.faults = tfaults(); f.set_raw(p, b); f };
    let in_phase = |fs: &MemTreeFs, phase: Phase| set(fs, "recovery.state", RecoveryState { phase, generation: 2, cref: r2.cref, snapshot_id: [0; 32] }.encode());
    // an intact tree: the engine still has to be seeded
    for phase in [Phase::Published, Phase::Verified] { assert!(matches!(started(in_phase(&good, phase)), Ok(StartOutcome::NeedsSeed { .. }))); }
    // the same state with the live application record damaged (valid names, wrong content): refused, nothing deleted
    let live = format!("{}/app-state", gen_dir(2));
    let mut bad = good.raw(&live).unwrap(); bad[40] ^= 1;
    for phase in [Phase::Published, Phase::Verified] {
        let m = refused(&set(&in_phase(&good, phase), &live, bad.clone()), "damaged live tree after a crash window");
        assert!(m.contains("published state"), "{m}");
    }
    let mut missing = in_phase(&good, Phase::Published); missing.delete_raw(&live);
    assert!(refused(&missing, "missing live file").contains("published state"));
    // while Idle, the tree is not re-measured (that cost is paid only after an interrupted install)
    assert!(matches!(started(set(&good, &live, bad)), Ok(StartOutcome::Idle { generation: 2 })));
}

#[test]
fn the_staging_phase_is_recorded_and_a_restart_in_it_discards_the_attempt() {
    let mut i = fresh_inst();
    install_interim(&mut i, 40, 1, 0).unwrap();
    i.complete_seed().unwrap();
    let (bytes, cur) = interim_snapshot(80, 2);
    let c = ref_of(&cur);
    let (m, chunks) = manifest_for(&bytes, 64, &c);
    i.begin(c, m.clone(), 55).unwrap();
    let st = RecoveryState::decode(&i.fs.raw("recovery.state").unwrap()).unwrap();
    assert_eq!((st.phase, st.generation, st.cref, st.snapshot_id), (Phase::Staging, 2, c, m.snapshot_id), "begin records the generation being installed");
    i.put_chunk(0, &chunks[0]).unwrap();
    // a restart in the middle: the attempt is discarded, generation 1 stays live, and the state returns to Idle(1)
    let mut fs = i.into_fs();
    fs.faults = tfaults();
    let mut j = mk(fs, interim());
    assert_eq!(j.start().unwrap(), StartOutcome::Idle { generation: 1 });
    assert_eq!(RecoveryState::decode(&j.fs.raw("recovery.state").unwrap()).unwrap(), RecoveryState::idle(1));
    assert!(j.fs.list("staging").unwrap().is_empty());
    assert_eq!(j.fs.list("generations").unwrap(), vec!["gen-00000000000000000001".to_string()]);
    // and the same install can then be run again from the start
    let (r, _) = install_interim(&mut j, 80, 2, 55).unwrap();
    assert_eq!(r.generation, 2);
}

#[test]
fn local_records_reject_a_wrong_type_version_trailing_bytes_and_a_wrong_integrity_tag() {
    let (_fs, _r1, r2) = two_installs();
    let ptr = AppPointer { generation: 2, cursor: Cursor { height: r2.cref.height, block_id: r2.cref.block_id, state_root: r2.cref.state_root }, record_digest: r2.digest() };
    let st = RecoveryState { phase: Phase::Published, generation: 2, cref: r2.cref, snapshot_id: [4; 32] };
    let reseal = |bytes: &[u8], edit: &dyn Fn(&mut Vec<u8>)| { let mut body = bytes[..bytes.len() - 32].to_vec(); edit(&mut body); let tag = rcodec::sha3(&[b"CFH1|local-tag|", &body]); body.extend_from_slice(&tag); body };
    let tag_len = |b: &[u8]| b.iter().position(|c| *c == b'|').map(|p| b[p + 1..].iter().position(|c| *c == b'|').unwrap() + p + 2).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![("recovery.state", st.encode()), ("install record", r2.encode()), ("app pointer", ptr.encode())];
    for (name, good) in &cases {
        // the unmodified bytes decode, every other record type refuses them (the tag text differs although the integrity tag is valid)
        let ok = |b: &[u8]| match *name { "recovery.state" => RecoveryState::decode(b).is_ok(), "install record" => InstallRecord::decode(b).is_ok(), _ => AppPointer::decode(b).is_ok() };
        assert!(ok(good), "{name}");
        // a wrong version, with a VALID integrity tag
        let n = tag_len(good);
        assert!(!ok(&reseal(good, &|b| { b[n] = 0; b[n + 1] = 2; })), "{name}: version");
        // a trailing byte inside the sealed body, with a valid integrity tag
        assert!(!ok(&reseal(good, &|b| b.push(0))), "{name}: trailing byte");
        // a flipped byte without re-sealing
        let mut flip = good.clone(); let mid = flip.len() / 2; flip[mid] ^= 1;
        assert!(!ok(&flip), "{name}: integrity tag");
        // truncations
        for cut in [0usize, 1, 20, good.len() - 33, good.len() - 1] { assert!(!ok(&good[..cut]), "{name}: cut {cut}"); }
    }
    // type confusion: well-formed, validly tagged bytes of one record type are refused by the other types
    assert!(RecoveryState::decode(&cases[1].1).is_err() && RecoveryState::decode(&cases[2].1).is_err());
    assert!(InstallRecord::decode(&cases[0].1).is_err() && InstallRecord::decode(&cases[2].1).is_err());
    assert!(AppPointer::decode(&cases[0].1).is_err() && AppPointer::decode(&cases[1].1).is_err());
    // a validly sealed body with the wrong tag text for its own type
    let relabel = reseal(&cases[2].1, &|b| { let n = tag_len(b); b[..n].copy_from_slice(&cases[0].1[..n.min(cases[0].1.len())]); });
    assert!(AppPointer::decode(&relabel).is_err());
}
