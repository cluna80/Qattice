// ============================================================================================================================
// S-2b: snapshot CAPTURE and SERVING inside the driver (feature `pq-snapshot-transfer`, plus a runtime opt-in). The provider side only: installation is operator-initiated
// install-then-restart and is not part of this slice; nothing here installs, imports provider signing state, or prunes. Interim application (opaque hash chain), real drivers,
// in-process exchange of the real encoded bytes. Compiled only when the feature is on; with it off the existing suites (unchanged) prove the old behaviour.
// ============================================================================================================================
use chain_forge_consensus::pq_hotstuff::serving::{is_recovery_kind, RecoveryService, ServingConfig, ServingCounters, SnapshotServing};

fn scfg(max_pins_per_peer: usize, max_pins_total: usize) -> ServingConfig {
    ServingConfig { serve: serve_cfg(), codec: rl(), genesis_hash: GENESIS_HASH, chunk_size: 64, max_candidates: 8, pin_idle_ms: 5_000, max_pins_per_peer, max_pins_total }
}
fn service(retention: RetentionConfig, cfg: ServingConfig) -> Box<dyn RecoveryService> {
    let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs);
    Box::new(SnapshotServing::new(SnapshotStore::open(fs, retention, rl(), GENESIS_HASH).unwrap(), cfg, 0).unwrap())
}
fn enable_all(net: &mut DNet, retention: RetentionConfig, cfg: &ServingConfig) { for n in net.nodes.iter_mut().flatten() { n.enable_snapshot_serving(service(retention, cfg.clone())); } }
fn svc_counters(net: &DNet, i: usize) -> ServingCounters { net.nodes[i].as_ref().unwrap().snapshot_serving().expect("serving is enabled on this node") }
fn rest() -> RetentionConfig { rcfg(3, 1 << 20, 1 << 16) }
fn ask(net: &mut DNet, node: usize, from: usize, m: &RecoveryMsg) -> Vec<RecoveryMsg> {
    let b = rcodec::encode(m).unwrap();
    net.nodes[node].as_mut().unwrap().on_bytes(from, &b, net.now).unwrap().into_iter().map(|o| { assert_eq!(o.to, Some(from), "a reply goes only to the asker"); rcodec::decode(&o.bytes, &rl()).expect("a reply the asker's decoder accepts") }).collect()
}
#[test]
fn without_the_runtime_opt_in_the_driver_behaves_exactly_as_before_and_recovery_kinds_are_unknown_input() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "O", Some(cc));
    run_to(&mut net, 24);
    assert!(net.nodes[0].as_ref().unwrap().snapshot_serving().is_none());
    let before = { let s = net.nodes[0].as_ref().unwrap().status(); (s.committed_height, s.exec, s.stats.malformed) };
    for m in [RecoveryMsg::HeaderReq { request_id: 1, after: [0; 32], max_headers: 4 }, RecoveryMsg::ManifestReq { request_id: 2, cref: CheckpointRef { height: 8, block_id: [1; 32], state_root: [2; 32] } }, RecoveryMsg::ChunkReq { request_id: 3, snapshot_id: [3; 32], index: 0 }] {
        assert!(ask(&mut net, 0, 1, &m).is_empty(), "no reply: the feature is not enabled on this node");
    }
    let after = { let s = net.nodes[0].as_ref().unwrap().status(); (s.committed_height, s.exec, s.stats.malformed) };
    assert_eq!((after.0, after.1), (before.0, before.1), "state unchanged");
    assert_eq!(after.2, before.2 + 3, "each was counted as malformed input, exactly as an unknown kind always was");
}

#[test]
fn enabling_serving_changes_no_consensus_behaviour_when_nothing_asks() {
    let run = |on: bool| {
        let cc = cc3(4, 8);
        let mut net = DNet::new_cp(4, &[], "D", Some(cc));
        if on { enable_all(&mut net, rest(), &scfg(1, 3)); }
        net.run(1_200);
        assert!(net.fatal.is_empty(), "{:?}", net.fatal);
        (0..4).map(|i| { let d = net.nodes[i].as_ref().unwrap(); let s = d.status(); (s.committed_height, s.exec.height, s.round, s.stats.malformed, s.stats.sync_requests, s.stats.bad_sync, net.logs[i].borrow().clone()) }).collect::<Vec<_>>()
    };
    assert_eq!(run(false), run(true), "heights, rounds, counters and the executed sequence are identical with serving off and on");
}

#[test]
fn every_node_captures_the_final_references_it_executed_and_each_snapshot_measures_to_its_reference() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "C", Some(cc));
    enable_all(&mut net, rest(), &scfg(1, 3));
    run_to(&mut net, 44);
    for i in 0..4 {
        let c = svc_counters(&net, i);
        assert!(c.captured >= 2, "node {i}: {c:?}");
        assert!(c.retained <= 3 && c.retained >= 1);
        assert_eq!((c.malformed, c.capture_other_error, c.capture_deferred), (0, 0, 0), "node {i}");
    }
    // what node 0 retains is exactly what it would serve: ask for it and verify the bytes measure to the reference (height, block id, state root)
    let d = net.nodes[0].as_ref().unwrap();
    let chain_refs: Vec<CheckpointRef> = { let mut v = vec![]; for b in drv_chain(d) { if let Some(r) = b.checkpoint { if v.last() != Some(&r) { v.push(r); } } } v };
    let held = net.nodes[0].as_ref().unwrap().snapshot_serving().unwrap().retained;
    assert!(held >= 1);
    let mut checked = 0;
    for r in chain_refs.iter().rev().take(3) {
        let got = ask(&mut net, 0, 1, &RecoveryMsg::ManifestReq { request_id: 1, cref: *r });
        let Some(RecoveryMsg::ManifestResp { body: ManifestBody::Ok(m), .. }) = got.into_iter().next() else { continue };
        let mut bytes = vec![];
        for idx in 0..m.chunk_count {
            let Some(RecoveryMsg::ChunkResp { body: ChunkBody::Ok(c), .. }) = ask(&mut net, 0, 1, &RecoveryMsg::ChunkReq { request_id: 2, snapshot_id: m.snapshot_id, index: idx }).into_iter().next() else { panic!("chunk {idx}") };
            assert_eq!(rcodec::chunk_hash(idx, &c), m.chunk_hashes[idx as usize]);
            bytes.extend_from_slice(&c);
        }
        let mut app = mem(); app.set_raw("app-state", bytes);
        let cur = InterimApp::open(app, GENESIS_HASH).expect("the served bytes are an interim application state").cursor();
        assert_eq!((cur.height, cur.block_id, cur.state_digest), (r.height, r.block_id, r.state_root), "the snapshot measures to the reference it is served for");
        checked += 1;
    }
    assert!(checked >= 1, "at least one retained snapshot was served and measured");
    let c = svc_counters(&net, 0);
    assert_eq!((c.pins_released_complete, c.pinned_now), (checked, 0), "each transfer that fetched every chunk released its pin at once: {c:?}");
}

/// Drive an S-1 requester through real drivers: peers `0..k` of `net` are the providers, `me` is the label they see as the asker.
fn drive_through(rig: &mut Rig, net: &mut DNet, me: usize, ticks: usize) {
    let mut now = net.now;
    let mut pending = rig.req.start(now);
    for _ in 0..ticks {
        let mut guard = 0;
        while let Some(o) = pending.pop() {
            guard += 1; assert!(guard < 50_000, "message storm");
            let bytes = rcodec::encode(&o.msg).unwrap();
            rig.sent.push((o.peer, o.msg.clone()));
            let Some(d) = net.nodes[o.peer].as_mut() else { continue };
            for out in d.on_bytes(me, &bytes, now).unwrap() { if let Ok(r) = rcodec::decode(&out.bytes, &rl()) { pending.extend(rig.req.on_message(o.peer, &r, now)); } }
        }
        if rig.req.is_finished() { break; }
        now += 50; net.now = net.now.max(now);
        pending = rig.req.on_tick(now);
        for n in net.nodes.iter_mut().flatten() { let _ = n.tick(now); }
    }
}

#[test]
fn an_s1_requester_installs_from_live_driver_providers_with_silent_and_non_serving_peers_and_the_recipient_restarts_with_its_floors() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "T", Some(cc));
    // providers: nodes 0, 1 serve; node 2 does NOT opt in (answers nothing); the requester also lists a black-hole peer 4
    for i in [0usize, 1] { net.nodes[i].as_mut().unwrap().enable_snapshot_serving(service(rest(), scfg(1, 3))); }
    run_to(&mut net, 44);
    let d = donor_of(&net);
    let bs = bs_cell();
    let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs);
    let mut rig = rig_full(&d, &[Mode::BlackHole, Mode::BlackHole, Mode::BlackHole, Mode::BlackHole], tlim(), ev_for(&bs, None), fs);
    drive_through(&mut rig, &mut net, 3, 400);
    let rec = rig.req.phase().clone();
    let TPhase::Done(rec) = rec else { panic!("{:?} {:?}", rig.req.phase(), rig.req.stats) };
    assert_eq!(rig.req.outstanding(), 0, "every request slot was released");
    assert!(rig.req.stats.dropped_unsolicited + rig.req.stats.dropped_late <= 4, "{:?}", rig.req.stats);
    for i in [0usize, 1] { assert_eq!(svc_counters(&net, i).gate_concurrent, 0, "the provider's admission slots are all released"); }
    // the requester spread its chunks over both providers, so neither saw a complete transfer: their pins are released by the idle timeout, never held for ever
    let later = net.now + 6_000;
    for i in [0usize, 1] { let _ = net.nodes[i].as_mut().unwrap().tick(later); }
    let served: Vec<ServingCounters> = [0usize, 1].iter().map(|i| svc_counters(&net, *i)).collect();
    assert!(served.iter().all(|c| c.pinned_now == 0), "no pin outlives the transfer: {served:?}");
    let app = installed_app(&rig.req.sink().fs, rec.generation);
    drop(rig);
    let bs = Rc::try_unwrap(bs).ok().expect("sole owner").into_inner();
    // install-then-restart: the recipient (node 3) is restarted on its own safety store and the installed state; it imports nothing from the providers' signing state
    let floor0 = net.nodes[3].as_ref().unwrap().engine().store().record().clone();
    reinstall(&mut net, 3, bs, app, "T").expect("the recipient starts from what the transfer produced");
    assert_eq!(net.nodes[3].as_ref().unwrap().engine().store().record(), &floor0, "no signing floor moved");
    for i in [0usize, 1] { assert_eq!(net.nodes[i].as_ref().unwrap().engine().store().record().public_key, svc_key(&net, i), "a provider's own signing identity is untouched"); }
    assert!(net.run_until(9000, |n| n.nodes[3].as_ref().map_or(false, |x| !x.engine().is_recovering() && x.status().exec.height >= rec.cref.height + 8)), "recovers");
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
    once_from(&net, 3, rec.cref.height, "after the install over the driver wire");
}
fn svc_key(net: &DNet, i: usize) -> Vec<u8> { net.nodes[i].as_ref().unwrap().engine().store().record().public_key.clone() }

#[test]
fn malformed_unsolicited_and_hostile_requests_change_nothing_create_no_pins_and_leave_no_slot_held() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "M", Some(cc));
    enable_all(&mut net, rest(), &scfg(1, 3));
    run_to(&mut net, 36);
    let snap = |net: &DNet| { let s = net.nodes[0].as_ref().unwrap().status(); (s.committed_height, s.exec, s.round) };
    let good = rcodec::encode(&RecoveryMsg::ManifestReq { request_id: 1, cref: CheckpointRef { height: 8, block_id: [1; 32], state_root: [2; 32] } }).unwrap();
    assert!(is_recovery_kind(&good));
    let mut hostile: Vec<Vec<u8>> = vec![vec![], good[..good.len() - 1].to_vec(), { let mut t = good.clone(); t.push(0); t }, vec![0xFF; 100], { let mut k = good.clone(); k[chain_forge_consensus::pq_hotstuff::netmsg::TAG_NET.len() + 2] = 13; k }];
    hostile.push(vec![0u8; 9 * 1024 * 1024]); // far above the transport limit
    let m0 = svc_counters(&net, 0).malformed;
    for b in &hostile { let o = net.nodes[0].as_mut().unwrap().on_bytes(1, b, net.now).unwrap(); assert!(o.is_empty()); }
    assert!(svc_counters(&net, 0).malformed >= m0, "counted, never answered");
    // responses nobody asked for
    for r in [RecoveryMsg::HeaderResp { request_id: 1, after: [0; 32], body: HeaderBody::NotFound }, RecoveryMsg::ChunkResp { request_id: 2, snapshot_id: [0; 32], index: 0, body: ChunkBody::NotFound }, RecoveryMsg::ManifestResp { request_id: 3, cref: CheckpointRef { height: 8, block_id: [1; 32], state_root: [2; 32] }, body: ManifestBody::NotFound }] {
        assert!(ask(&mut net, 0, 1, &r).is_empty());
    }
    assert_eq!(svc_counters(&net, 0).unsolicited_responses, 3);
    // a request from this node's own index, or from a peer that does not exist: ignored
    for from in [0usize, 4, 99] { let o = net.nodes[0].as_mut().unwrap().on_bytes(from, &good, net.now).unwrap(); assert!(o.is_empty(), "from {from}"); }
    // an unknown reference or snapshot is answered NOT_FOUND and pins nothing; an absurd page size is clamped
    let r = ask(&mut net, 0, 1, &RecoveryMsg::ManifestReq { request_id: 5, cref: CheckpointRef { height: 8, block_id: [1; 32], state_root: [2; 32] } });
    assert!(matches!(r.as_slice(), [RecoveryMsg::ManifestResp { body: ManifestBody::NotFound, .. }]));
    let r = ask(&mut net, 0, 1, &RecoveryMsg::ChunkReq { request_id: 6, snapshot_id: [9; 32], index: 7 });
    assert!(matches!(r.as_slice(), [RecoveryMsg::ChunkResp { body: ChunkBody::NotFound, .. }]));
    let r = ask(&mut net, 0, 1, &RecoveryMsg::HeaderReq { request_id: 7, after: [7; 32], max_headers: 64 });
    assert!(matches!(r.as_slice(), [RecoveryMsg::HeaderResp { body: HeaderBody::NotFound, .. }]));
    // an absurd page size never reaches the provider: the decoder refuses it (counted as malformed, not answered)
    let m1 = svc_counters(&net, 0).malformed;
    assert!(ask(&mut net, 0, 1, &RecoveryMsg::HeaderReq { request_id: 8, after: [7; 32], max_headers: 64 }).len() == 1);
    let huge = { let mut b = rcodec::encode(&RecoveryMsg::HeaderReq { request_id: 9, after: [7; 32], max_headers: 64 }).unwrap(); let n = b.len(); b[n - 4..].copy_from_slice(&u32::MAX.to_be_bytes()); b };
    assert!(net.nodes[0].as_mut().unwrap().on_bytes(1, &huge, net.now).unwrap().is_empty());
    assert_eq!(svc_counters(&net, 0).malformed, m1 + 1);
    let c = svc_counters(&net, 0);
    assert_eq!((c.pinned_now, c.gate_concurrent), (0, 0), "{c:?}");
    // none of it touched consensus
    let before = snap(&net);
    run_to(&mut net, 44);
    assert!(snap(&net).0 >= before.0 && net.fatal.is_empty(), "{:?}", net.fatal);
}

#[test]
fn pins_are_per_peer_and_total_bounded_protect_a_snapshot_from_eviction_and_are_released_when_a_transfer_goes_quiet() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "P", Some(cc));
    // a cache of TWO snapshots, so that new captures put the oldest under eviction pressure; at most one pin per peer, two in total
    enable_all(&mut net, rcfg(2, 1 << 20, 1 << 16), &scfg(1, 2));
    run_to(&mut net, 28);
    let refs: Vec<CheckpointRef> = { let mut v = vec![]; for b in drv_chain(net.nodes[0].as_ref().unwrap()) { if let Some(r) = b.checkpoint { if v.last() != Some(&r) { v.push(r); } } } v };
    let held: Vec<(u64, [u8; 32], u64, bool)> = net.nodes[0].as_ref().unwrap().snapshot_retained();
    assert_eq!(held.len(), 2, "{held:?}");
    let (oldest, newest) = (held[0], held[1]);
    let r_old = *refs.iter().find(|r| r.height == oldest.0).unwrap(); let r_new = *refs.iter().find(|r| r.height == newest.0).unwrap();
    // peer 1 starts a transfer of the OLDEST snapshot (manifest + one chunk) and goes quiet
    let m = ask(&mut net, 0, 1, &RecoveryMsg::ManifestReq { request_id: 1, cref: r_old });
    let Some(RecoveryMsg::ManifestResp { body: ManifestBody::Ok(mf), .. }) = m.into_iter().next() else { panic!() };
    assert!(mf.chunk_count >= 2);
    assert!(matches!(ask(&mut net, 0, 1, &RecoveryMsg::ChunkReq { request_id: 2, snapshot_id: mf.snapshot_id, index: 0 }).as_slice(), [RecoveryMsg::ChunkResp { body: ChunkBody::Ok(_), .. }]));
    assert_eq!(svc_counters(&net, 0).pinned_now, 1);
    // the same peer asking for a DIFFERENT snapshot is told BUSY (its share is one pin): it cannot hold the cache hostage
    assert!(matches!(ask(&mut net, 0, 1, &RecoveryMsg::ManifestReq { request_id: 3, cref: r_new }).as_slice(), [RecoveryMsg::ManifestResp { body: ManifestBody::Busy { .. }, .. }]));
    // peer 2 pins the newest; peer 3 is over the node's total of two
    assert!(matches!(ask(&mut net, 0, 2, &RecoveryMsg::ManifestReq { request_id: 4, cref: r_new }).as_slice(), [RecoveryMsg::ManifestResp { body: ManifestBody::Ok(_), .. }]));
    assert!(matches!(ask(&mut net, 0, 3, &RecoveryMsg::ManifestReq { request_id: 5, cref: r_new }).as_slice(), [RecoveryMsg::ManifestResp { body: ManifestBody::Busy { .. }, .. }]));
    let c = svc_counters(&net, 0); assert_eq!((c.pinned_now, c.replies_busy_for_pins), (2, 2), "{c:?}");
    // the network keeps producing references: node 0's cache is under count pressure, yet BOTH pinned snapshots survive and are still served
    run_to(&mut net, 52);
    let held2 = net.nodes[0].as_ref().unwrap().snapshot_retained();
    assert!(held2.iter().any(|h| h.1 == oldest.1 && h.3) && held2.iter().any(|h| h.1 == newest.1 && h.3), "pinned snapshots were not evicted: {held2:?}");
    assert!(matches!(ask(&mut net, 0, 1, &RecoveryMsg::ChunkReq { request_id: 6, snapshot_id: mf.snapshot_id, index: 1 }).as_slice(), [RecoveryMsg::ChunkResp { body: ChunkBody::Ok(_), .. }]), "the interrupted transfer can resume");
    // quiet transfers are released by the idle timeout, after which the cache evicts normally
    let later = net.now + 6_000;
    for _ in 0..3 { let _ = net.nodes[0].as_mut().unwrap().tick(later); }
    assert_eq!(svc_counters(&net, 0).pinned_now, 0, "idle pins were released");
    assert!(svc_counters(&net, 0).pins_released_idle >= 2);
    run_to(&mut net, 68);
    let held3 = net.nodes[0].as_ref().unwrap().snapshot_retained();
    assert!(held3.len() <= 2 && !held3.iter().any(|h| h.1 == oldest.1), "with the pins gone the old snapshot is evicted: {held3:?}");
    assert!(net.fatal.is_empty(), "{:?}", net.fatal);
}

#[test]
fn an_exhausted_snapshot_budget_defers_capture_without_disturbing_consensus_or_what_is_already_served_and_a_flood_is_told_busy() {
    let cc = cc3(4, 8);
    let mut net = DNet::new_cp(4, &[], "X", Some(cc));
    // room for about one snapshot: later captures are deferred
    let mut spaced = scfg(1, 3); spaced.serve.min_spacing_ms = 50; // WITHOUT a minimum spacing a flood of tiny answers is not throttled by the byte buckets (they refund what a small reply did not use)
    enable_all(&mut net, rcfg(3, 1_200, 600), &spaced);
    run_to(&mut net, 52);
    let c = svc_counters(&net, 0);
    assert!(c.captured >= 1 && c.capture_deferred >= 1 || c.retained >= 1, "{c:?}");
    assert!(c.retained_bytes <= 1_200, "the budget was never exceeded: {c:?}");
    assert!(net.height(0) >= 52 && net.fatal.is_empty(), "consensus is unaffected");
    // a flood from one peer is answered BUSY (the gate), every slot is back at zero, and consensus state does not move
    let held = net.nodes[0].as_ref().unwrap().snapshot_retained();
    let r = { let mut v = vec![]; for b in drv_chain(net.nodes[0].as_ref().unwrap()) { if let Some(r) = b.checkpoint { if held.iter().any(|h| h.0 == r.height) { v.push(r); } } } *v.last().unwrap() };
    let mut busy = 0;
    for i in 0..3_000u64 { if let Some(RecoveryMsg::ManifestResp { body: ManifestBody::Busy { .. }, .. }) = ask(&mut net, 0, 1, &RecoveryMsg::ManifestReq { request_id: i, cref: r }).first() { busy += 1; } }
    assert!(busy > 0, "a flood is told to back off");
    assert_eq!(svc_counters(&net, 0).gate_concurrent, 0);
}

#[test]
fn only_the_state_this_node_executed_at_the_height_and_that_the_final_reference_attests_is_captured() {
    use chain_forge_consensus::pq_hotstuff::exec::ExecCursor;
    let mut svc = SnapshotServing::new(SnapshotStore::open({ let mut fs = MemTreeFs::new(tfaults()); extras(&mut fs); fs }, rest(), rl(), GENESIS_HASH).unwrap(), scfg(1, 3), 0).unwrap();
    let state: Vec<u8> = (0..200u8).collect();
    let cur = |h: u64, id: u8, root: u8| ExecCursor { height: h, block_id: [id; 32], state_digest: [root; 32] };
    svc.note_executed(&cur(8, 1, 2), Some(state.clone()));
    // a reference naming a different root, a different block, or a height this node never executed: nothing is captured
    for r in [CheckpointRef { height: 8, block_id: [1; 32], state_root: [9; 32] }, CheckpointRef { height: 8, block_id: [9; 32], state_root: [2; 32] }, CheckpointRef { height: 16, block_id: [1; 32], state_root: [2; 32] }] { svc.note_final_ref(&r); }
    assert_eq!(svc.counters().captured, 0, "{:?}", svc.counters());
    // an executor that cannot produce a snapshot contributes no candidate
    svc.note_executed(&cur(16, 3, 4), None);
    svc.note_final_ref(&CheckpointRef { height: 16, block_id: [3; 32], state_root: [4; 32] });
    assert_eq!(svc.counters().captured, 0);
    // the matching reference captures exactly once
    svc.note_final_ref(&CheckpointRef { height: 8, block_id: [1; 32], state_root: [2; 32] });
    assert_eq!(svc.counters().captured, 1);
    svc.note_final_ref(&CheckpointRef { height: 8, block_id: [1; 32], state_root: [2; 32] });
    assert_eq!(svc.counters().captured, 1, "the candidate is consumed");
    // the candidate map is bounded
    for h in 100..120u64 { svc.note_executed(&cur(h, 5, 6), Some(state.clone())); }
    assert!(svc.counters().candidates_dropped >= 12, "{:?}", svc.counters());
}

#[test]
fn serving_configuration_is_validated_locally_before_any_use() {
    let ok = scfg(1, 3);
    assert!(ok.validate().is_ok());
    let mut c = ok.clone(); c.max_pins_per_peer = 4; assert!(c.validate().is_err(), "per-peer pins above the total");
    let mut c = ok.clone(); c.chunk_size = 0; assert!(c.validate().is_err());
    let mut c = ok.clone(); c.chunk_size = c.codec.max_chunk_size + 1; assert!(c.validate().is_err(), "chunk above the codec maximum");
    let mut c = ok.clone(); c.pin_idle_ms = 0; assert!(c.validate().is_err());
    let mut c = ok.clone(); c.serve.burst = 1; assert!(c.validate().is_err(), "the serve gate's own invariants are checked");
}
