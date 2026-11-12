//! Gate B — B1: TCP epoch-boundary test with isolated seal checks (QAT-07).
//!
//! Two OS threads simulate two OS processes communicating over a loopback TCP socket.
//! The sender uses real FIPS 204 ML-DSA-65 keys, FsStorage, and FsCounter. The receiver
//! logs every frame tagged by (epoch, round) and verifies signatures with Fips204Verifier.
//!
//! Covers all 7 steps from gate-b-scope.md § B1:
//!   Step 1: sign epoch=0 round=5 → receiver logs (0,5). OK.
//!   Step 2: write_seal(0, 5). Seal durable. Epoch record still at 0.
//!   Step 3: attempt epoch=0 round=6 → SealViolation; no (0,6) frame on wire.
//!   Step 4: attempt epoch=1 round=0 before advance → RoundBelowEpochMinimum; no frame.
//!   Step 5: advance_epoch_record(1, set_hash, cert_hash). Epoch record at 1.
//!   Step 6: attempt epoch=0 round=7 → EpochRegression; no (0,7) frame.
//!   Step 7: sign epoch=1 round=1 → succeeds; receiver logs (1,1) with real ML-DSA-65 sig.
//!
//! Run (Windows, real ML-DSA-65):
//!   cargo test -p chain-forge-consensus --features gate-b-harness \
//!     --test gate_b_tcp_epoch_boundary -- --nocapture
#![cfg(feature = "gate-b-harness")]

#[path = "common/pq_safety_doubles.rs"]
mod doubles;

use chain_forge_consensus::pq_hotstuff::safety::{
    ConsensusSigner, ConsensusVerifier,
    CounterBinding, Fips204Signer, Fips204Verifier, FsCounter, FsStorage,
    FreshInit, ParticipationEvidence, SafetyStore, SignError,
};
use chain_forge_consensus::pq_hotstuff::wire::{AlgId, SignatureEnvelope, VoteMessage};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const PROFILE: &str = "qattice-pq-hotstuff-2-v2";
const CHAIN: &str = "qattice-pqhs2-dev-gate-b-tcp";
const SEAL_ROUND: u64 = 5;
const EPOCH_Z: u64 = 4;

type FsStore = SafetyStore<FsStorage, FsCounter>;

fn tmp_dir(label: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gate_b_tcp_{}_{}", label, std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn new_signer() -> (Fips204Signer, Vec<u8>) {
    let s = Fips204Signer::generate().expect("keygen");
    let pk = s.public_key().to_vec();
    (s, pk)
}

fn binding(pk: &[u8]) -> CounterBinding {
    CounterBinding { public_key: pk.to_vec(), instance_id: [0x0B; 16] }
}

fn init_store(dir: &Path, pk: &[u8]) -> FsStore {
    let st = FsStorage::new(dir).unwrap();
    let ctr = FsCounter::create(dir.join("counter.bin"), binding(pk)).unwrap();
    SafetyStore::initialize_fresh(
        st, ctr,
        &FreshInit { protocol_profile: PROFILE, chain_id: CHAIN, public_key: pk, instance_id: [0x0B; 16], epoch: 0 },
        &ParticipationEvidence::default(),
    ).expect("initialize_fresh")
}

fn vote_msg(epoch: u64, round: u64) -> VoteMessage {
    VoteMessage {
        alg_id: AlgId::MLDSA65_FIPS204,
        chain_id: CHAIN.into(),
        epoch,
        round,
        block_id: [0xAA; 32],
        parent_id: [0xBB; 32],
        parent_round: round.saturating_sub(1),
    }
}

fn sha3_32(d: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    Sha3_256::digest(d).into()
}

/// A wire frame: 4-byte length prefix + payload.
fn send_frame(stream: &mut TcpStream, payload: &[u8]) {
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

fn recv_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() { return None; }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    if stream.read_exact(&mut buf).is_err() { return None; }
    Some(buf)
}

/// A received frame decoded to (epoch, round, signature).
#[derive(Debug, Clone)]
struct ReceivedVote { epoch: u64, round: u64, sig_len: usize, sig_valid: bool }

fn decode_and_verify(payload: &[u8], pk: &[u8]) -> ReceivedVote {
    // Payload: 8-byte epoch || 8-byte round || 4-byte msg_len || msg_bytes || signature.
    if payload.len() < 20 { return ReceivedVote { epoch: 0, round: 0, sig_len: 0, sig_valid: false }; }
    let epoch = u64::from_be_bytes(payload[..8].try_into().unwrap());
    let round = u64::from_be_bytes(payload[8..16].try_into().unwrap());
    let msg_len = u32::from_be_bytes(payload[16..20].try_into().unwrap()) as usize;
    if payload.len() < 20 + msg_len { return ReceivedVote { epoch, round, sig_len: 0, sig_valid: false }; }
    let msg_bytes = &payload[20..20 + msg_len];
    let sig_bytes = &payload[20 + msg_len..];
    let verifier = Fips204Verifier;
    use chain_forge_consensus::pq_hotstuff::safety::CTX_VOTE;
    let sig_valid = verifier.verify(pk, CTX_VOTE, msg_bytes, sig_bytes);
    ReceivedVote { epoch, round, sig_len: sig_bytes.len(), sig_valid }
}

fn encode_frame(epoch: u64, round: u64, msg_bytes: &[u8], envelope: &SignatureEnvelope) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(&round.to_be_bytes());
    v.extend_from_slice(&(msg_bytes.len() as u32).to_be_bytes());
    v.extend_from_slice(msg_bytes);
    v.extend_from_slice(&envelope.signature);
    v
}

/// Shared log of received votes.
type VoteLog = Arc<Mutex<Vec<ReceivedVote>>>;

#[test]
fn b1_tcp_epoch_boundary_all_steps() {
    let dir = tmp_dir("b1");
    let (mut signer, pk) = new_signer();
    let pk_arc = Arc::new(pk.clone());

    // Start receiver on a loopback port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    println!("[B1] receiver listening on {addr}");

    let log: VoteLog = Arc::new(Mutex::new(Vec::new()));
    let log_recv = log.clone();
    let pk_recv = pk_arc.clone();

    let recv_thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Set a generous read timeout so the test doesn't hang.
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        loop {
            match recv_frame(&mut stream) {
                None => break,
                Some(payload) => {
                    let vote = decode_and_verify(&payload, &pk_recv);
                    println!("[receiver] got frame epoch={} round={} sig_len={} valid={}",
                        vote.epoch, vote.round, vote.sig_len, vote.sig_valid);
                    log_recv.lock().unwrap().push(vote);
                }
            }
        }
        println!("[receiver] done");
    });

    // Connect sender.
    let mut stream = TcpStream::connect(addr).unwrap();
    let mut store = init_store(&dir, &pk);

    // ── Step 1: sign epoch=0 round=5; send frame ─────────────────────────────
    println!("[B1] Step 1: sign (0,5)");
    let signed = store.sign_vote(&vote_msg(0, SEAL_ROUND), EPOCH_Z, &mut signer).unwrap();
    let frame = encode_frame(0, SEAL_ROUND, &signed.message, &signed.envelope);
    send_frame(&mut stream, &frame);
    println!("[B1] Step 1: frame (0,{SEAL_ROUND}) sent");

    // ── Step 2: write_seal(0, SEAL_ROUND) ────────────────────────────────────
    println!("[B1] Step 2: write_seal(0, {SEAL_ROUND})");
    store.write_seal(0, SEAL_ROUND).expect("write_seal");

    // ── Step 3: attempt epoch=0 round=6 → SealViolation; no frame sent ───────
    println!("[B1] Step 3: attempt sign (0,{})", SEAL_ROUND + 1);
    let err3 = store.sign_vote(&vote_msg(0, SEAL_ROUND + 1), SEAL_ROUND, &mut signer).unwrap_err();
    assert!(
        matches!(err3, SignError::SealViolation { .. }),
        "Step 3: expected SealViolation, got: {err3}"
    );
    println!("[B1] Step 3: SealViolation confirmed: {err3}");
    // No frame sent.

    // ── Step 4: epoch=1 round=0 → RoundBelowEpochMinimum (store-level gate) ──
    // The store checks round == 0 && epoch > 0 before entering the new-epoch branch,
    // so this error fires without advancing in-memory epoch state. ProofNotDurable
    // (block epoch+1 signing until advance_epoch_record) is an engine-layer gate;
    // in this direct-store test we verify the store's own round-floor invariant.
    println!("[B1] Step 4: attempt sign (1,0) before advance");
    let err4 = store.sign_vote(&vote_msg(1, 0), 0, &mut signer).unwrap_err();
    assert!(
        matches!(err4, SignError::RoundBelowEpochMinimum { .. }),
        "Step 4: expected RoundBelowEpochMinimum at epoch=1 round=0, got: {err4}"
    );
    println!("[B1] Step 4: RoundBelowEpochMinimum confirmed: {err4}");
    // No frame sent.

    // ── Step 5: advance_epoch_record(1, set_hash, cert_hash) ─────────────────
    println!("[B1] Step 5: advance_epoch_record(1, ...)");
    let (cert_hash, set_hash) = (sha3_32(b"gate-b-cert"), sha3_32(b"gate-b-vset"));
    store.advance_epoch_record(1, set_hash, cert_hash).expect("advance_epoch_record");

    // ── Step 6: attempt epoch=0 round=7 → EpochRegression; no frame ──────────
    println!("[B1] Step 6: attempt sign (0,{})", SEAL_ROUND + 2);
    let err6 = store.sign_vote(&vote_msg(0, SEAL_ROUND + 2), SEAL_ROUND, &mut signer).unwrap_err();
    assert!(
        matches!(err6, SignError::EpochRegression { .. }),
        "Step 6: expected EpochRegression, got: {err6}"
    );
    println!("[B1] Step 6: EpochRegression confirmed: {err6}");
    // No frame sent.

    // ── Step 7: sign epoch=1 round=1 → succeeds; send frame ──────────────────
    println!("[B1] Step 7: sign (1,1)");
    let signed7 = store.sign_vote(&vote_msg(1, 1), 0, &mut signer).unwrap();
    let frame7 = encode_frame(1, 1, &signed7.message, &signed7.envelope);
    assert_eq!(signed7.envelope.signature.len(), 3309,
        "Step 7: ML-DSA-65 signature must be 3309 bytes");
    send_frame(&mut stream, &frame7);
    println!("[B1] Step 7: frame (1,1) sent with real ML-DSA-65 signature");

    // Close sender connection.
    drop(stream);
    recv_thread.join().unwrap();

    // ── Verify receiver log ──────────────────────────────────────────────────
    let received = log.lock().unwrap().clone();
    println!("[B1] receiver log: {:?}", received);

    let epoch0_frames: Vec<_> = received.iter().filter(|v| v.epoch == 0).collect();
    let epoch1_frames: Vec<_> = received.iter().filter(|v| v.epoch == 1).collect();

    assert_eq!(epoch0_frames.len(), 1,
        "Step 7 assert: exactly one epoch-0 frame (the step-1 vote). Got: {epoch0_frames:?}");
    assert_eq!(epoch0_frames[0].round, SEAL_ROUND,
        "Step 7 assert: epoch-0 frame is at round {SEAL_ROUND}");

    assert_eq!(epoch1_frames.len(), 1,
        "Step 7 assert: exactly one epoch-1 frame. Got: {epoch1_frames:?}");
    assert_eq!(epoch1_frames[0].round, 1,
        "Step 7 assert: epoch-1 frame is at round 1");
    assert!(epoch1_frames[0].sig_valid,
        "Step 7 assert: epoch-1 signature must verify with Fips204Verifier");
    assert_eq!(epoch1_frames[0].sig_len, 3309,
        "Step 7 assert: epoch-1 signature is 3309 bytes (real ML-DSA-65)");

    println!("[b1_tcp_epoch_boundary_all_steps] PASS: all 7 steps verified, receiver saw exactly 2 frames");
}
