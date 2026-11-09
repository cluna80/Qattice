//! PQ-HotStuff-2 DEVNET harness pieces (feature `pq-devnet`). **DEVNET ONLY. NOT FOR PRODUCTION.**
//!
//! * A fixed-validator-set devnet configuration (no dynamic membership). Its genesis hash is SHA3-256 of the exact file bytes, so every node
//!   must be given a byte-identical file.
//! * A devnet-only validator key loader: a 32-byte seed in a local file (`validator.seed`), generated on the machine that uses it, never
//!   committed (`*.seed` is git-ignored), never printed. Production key storage is blocked on the review of #109.
//! * A clearly-labelled NON-PRODUCTION file-backed counter. The safety-store contract says an ordinary file is NOT a valid monotonic counter
//!   (whoever owns the file can roll it back). It lets the devnet run the real safety store end to end and nothing more.
//! * A bounded local TCP transport. It is NOT authenticated or encrypted: consensus messages are signed and verified by the engine, sync
//!   responses are validated, and the sender index on a frame is only a reply address and hint, never trusted. It is not the libp2p path.
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chain_forge_consensus::pq_hotstuff::blockstore::BlockStore;
use chain_forge_consensus::pq_hotstuff::certs::{block_id_of, Block, BlockId, Cert, IdCtx};
use chain_forge_consensus::pq_hotstuff::checkpoint::{is_v3, CheckpointConfig, CheckpointParams, CheckpointRef, RefPolicy};
use chain_forge_consensus::pq_hotstuff::driver::DriverConfig;
use chain_forge_consensus::pq_hotstuff::engine::Committed;
use chain_forge_consensus::pq_hotstuff::exec::{ExecCursor, ExecError, Executor, InterimApp};
use chain_forge_consensus::pq_hotstuff::header::{ChainParams, Start};
use chain_forge_consensus::pq_hotstuff::seed::{authenticate_checkpoint, SeedEvidence};
use chain_forge_consensus::pq_hotstuff::safety::{Fips204Verifier, FsStorage, Storage};
use chain_forge_consensus::pq_hotstuff::engine::EngineConfig;
use chain_forge_consensus::pq_hotstuff::limits::PqLimits;
use chain_forge_consensus::pq_hotstuff::netmsg::read_bounded;
use chain_forge_consensus::pq_hotstuff::pacemaker::PacemakerConfig;
use chain_forge_consensus::pq_hotstuff::safety::{ConsensusSigner, CounterBinding, CounterError, CounterState, Fips204Signer, MonotonicCounter, Session};
use chain_forge_consensus::pq_hotstuff::types::{EpochSet, ValidatorEntry};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const DEVNET_LABEL: &str = "DEVNET ONLY: fixed validator set, devnet-interim payloads, non-production keys and counter, unauthenticated local transport";

fn sha3(parts: &[&[u8]]) -> [u8; 32] { let mut h = Sha3_256::new(); for p in parts { h.update(p); } h.finalize().into() }

// ------------------------------------------------------------------------------------------------------------------ configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevnetValidator { pub address: String, pub public_key: String, pub power: u64, pub endpoint: String }

/// Profile v3 only (absent = the existing v2 devnet, whose config files and genesis hash are unchanged): the checkpoint parameters bound into the genesis, and the
/// proposer policy (local, not validity). The whole file is hashed into the genesis hash, so every node must have the identical file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevnetCheckpoint { pub interval: u64, pub max_age: u64, pub margin: u64, pub omit_rotations: u64, pub alarm_age_intervals: u64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevnetConfig {
    pub label: String,
    pub chain_id: String,
    pub protocol_profile: String,
    pub validators: Vec<DevnetValidator>,
    pub max_block_payload_bytes: u64,
    pub max_message_bytes: u64,
    pub max_sync_blocks: usize,
    pub pacemaker_base_ms: u64,
    pub pacemaker_max_ms: u64,
    pub min_propose_gap_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<DevnetCheckpoint>,
}

impl DevnetConfig {
    /// The configuration and its genesis hash (SHA3-256 of the file bytes).
    pub fn load(path: &Path) -> Result<(Self, [u8; 32]), String> {
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let cfg: DevnetConfig = serde_json::from_slice(&bytes).map_err(|e| format!("bad devnet config: {e}"))?;
        if cfg.label != DEVNET_LABEL { return Err("the devnet config is missing the DEVNET ONLY label".into()); }
        Ok((cfg, sha3(&[b"CFH1|devnet-genesis|", &bytes])))
    }

    pub fn set(&self) -> Result<EpochSet, String> {
        let mut v = vec![];
        for x in &self.validators {
            let pk = hex::decode(&x.public_key).map_err(|e| format!("bad public key for {}: {e}", x.address))?;
            v.push(ValidatorEntry { address: x.address.clone(), public_key: pk, power: x.power });
        }
        EpochSet::new(0, v).map_err(|e| e.to_string())
    }

    pub fn limits(&self) -> PqLimits {
        PqLimits { max_validators: self.validators.len(), max_cert_validators: 1024, max_block_payload_bytes: self.max_block_payload_bytes, max_message_bytes: Some(self.max_message_bytes) }
    }

    /// The validator index of `public_key` in the (sorted) set, and the engine configuration for it.
    pub fn engine_config(&self, public_key: &[u8], genesis_hash: [u8; 32]) -> Result<(EngineConfig, usize), String> {
        let set = self.set()?;
        let my_index = set.entries().iter().position(|e| e.public_key == public_key).ok_or("this node's key is not in the validator set")?;
        let checkpoint = self.checkpoint_config()?;
        Ok((EngineConfig { chain_id: self.chain_id.clone(), protocol_profile: self.protocol_profile.clone(), set, my_index, genesis_hash, limits: self.limits(), seed: 0, checkpoint }, my_index))
    }

    /// `None` for the v2 devnet. Profile v3 and checkpoint parameters must come together; anything else is refused (no silent fallback to v2).
    pub fn checkpoint_config(&self) -> Result<Option<CheckpointConfig>, String> {
        match (&self.checkpoint, is_v3(&self.protocol_profile)) {
            (None, false) => Ok(None),
            (Some(_), false) => Err("checkpoint parameters are only valid with the v3 profile".into()),
            (None, true) => Err("the v3 profile needs checkpoint parameters".into()),
            (Some(c), true) => {
                let params = CheckpointParams { interval: c.interval, max_age: c.max_age };
                params.validate().map_err(|e| e.to_string())?;
                let policy = RefPolicy { propose_refs: true, margin: c.margin, omit_rotations: c.omit_rotations, alarm_age_intervals: c.alarm_age_intervals };
                policy.validate().map_err(|e| e.to_string())?;
                Ok(Some(CheckpointConfig { params, policy }))
            }
        }
    }

    pub fn driver_config(&self) -> DriverConfig {
        DriverConfig {
            max_sync_blocks: self.max_sync_blocks, pace: PacemakerConfig { base: self.pacemaker_base_ms, max: self.pacemaker_max_ms },
            sync_ttl: 3 * self.pacemaker_base_ms, sync_outstanding: 8, min_propose_gap: self.min_propose_gap_ms, park_capacity: 32, park_ttl: 6 * self.pacemaker_base_ms, recent: 64, exec_per_tick: None,
        }
    }

    /// Endpoints in validator-index (sorted-address) order.
    pub fn endpoints(&self) -> Result<Vec<String>, String> {
        let set = self.set()?;
        set.entries().iter().map(|e| self.validators.iter().find(|v| v.address == e.address).map(|v| v.endpoint.clone()).ok_or_else(|| "address without endpoint".to_string())).collect()
    }
}

// ------------------------------------------------------------------------------------------------------------------ devnet key loader
pub const SEED_FILE: &str = "validator.seed";
pub const PUB_FILE: &str = "validator.pub";

/// Generate a fresh seed with the operating-system RNG, store it as hex in `dir/validator.seed` (owner-only on Unix) and write the public key
/// to `dir/validator.pub`. Refuses to overwrite an existing seed. The seed is never returned or printed; the public key is.
pub fn keygen(dir: &Path) -> Result<Vec<u8>, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(SEED_FILE);
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("operating-system RNG: {e}"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
    let mut f = opts.open(&path).map_err(|e| format!("{} exists or cannot be created: {e}", path.display()))?;
    f.write_all(hex::encode(seed).as_bytes()).and_then(|_| f.write_all(b"\n")).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    let signer = Fips204Signer::from_seed(&seed);
    seed.fill(0);
    let pk = signer.public_key().to_vec();
    std::fs::write(dir.join(PUB_FILE), hex::encode(&pk)).map_err(|e| e.to_string())?;
    Ok(pk)
}

/// Load the signer from `dir/validator.seed`. On Unix a seed readable by group or others is refused.
pub fn load_signer(dir: &Path) -> Result<Fips204Signer, String> {
    let path = dir.join(SEED_FILE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?.permissions().mode();
        if mode & 0o077 != 0 { return Err(format!("{} is accessible to other users (mode {:o}); refusing to load it", path.display(), mode & 0o777)); }
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut bytes = hex::decode(text.trim()).map_err(|_| "the seed file is not 64 hex characters".to_string())?;
    let mut seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "the seed file is not 32 bytes".to_string())?;
    bytes.fill(0);
    let s = Fips204Signer::from_seed(&seed);
    seed.fill(0);
    Ok(s)
}

// ------------------------------------------------------------------------------------------------------------------ devnet counter
const CTR_MAGIC: &[u8] = b"CFH1|devnet-counter|NONPROD|";
const CTR_LEN: usize = 28 + 32 + 16 + 8 + 32 + 8 + 32;

/// **NON-PRODUCTION.** A counter in an ordinary file. It satisfies the trait's interface (durable replace, one exclusive session, compare-and-
/// advance, bound to one key and instance) but NOT its trust requirement: whoever owns the file can roll it back.
pub struct DevnetFileCounter { path: PathBuf, binding: CounterBinding, st: CounterState, token: u64 }

impl DevnetFileCounter {
    fn seal(&self) -> Vec<u8> {
        let mut b = CTR_MAGIC.to_vec();
        b.extend_from_slice(&sha3(&[&self.binding.public_key]));
        b.extend_from_slice(&self.binding.instance_id);
        b.extend_from_slice(&self.st.value.to_be_bytes());
        b.extend_from_slice(&self.st.digest);
        b.extend_from_slice(&self.token.to_be_bytes());
        let sum = sha3(&[&b]);
        b.extend_from_slice(&sum);
        b
    }
    fn persist(&self) -> Result<(), CounterError> {
        let e = |x: std::io::Error| CounterError(x.to_string());
        let tmp = self.path.with_extension("tmp");
        { let mut f = std::fs::File::create(&tmp).map_err(e)?; f.write_all(&self.seal()).map_err(e)?; f.sync_all().map_err(e)?; }
        std::fs::rename(&tmp, &self.path).map_err(e)?;
        #[cfg(unix)]
        { if let Some(d) = self.path.parent() { std::fs::File::open(d).and_then(|f| f.sync_all()).map_err(e)?; } }
        Ok(())
    }
    /// Create a fresh counter at zero for `public_key` with a new random instance id. Fails if the file exists.
    pub fn create(path: &Path, public_key: &[u8]) -> Result<Self, CounterError> {
        if path.exists() { return Err(CounterError(format!("{} already exists", path.display()))); }
        let mut instance_id = [0u8; 16];
        getrandom::getrandom(&mut instance_id).map_err(|e| CounterError(e.to_string()))?;
        let c = DevnetFileCounter { path: path.to_path_buf(), binding: CounterBinding { public_key: public_key.to_vec(), instance_id }, st: CounterState::INITIAL, token: 0 };
        c.persist()?;
        Ok(c)
    }
    /// Open an existing counter; a damaged file or one that belongs to another key is refused (never reset).
    pub fn open(path: &Path, public_key: &[u8]) -> Result<Self, CounterError> {
        let b = std::fs::read(path).map_err(|e| CounterError(format!("cannot read {}: {e}", path.display())))?;
        if b.len() != CTR_LEN || &b[..28] != CTR_MAGIC { return Err(CounterError("the counter file is damaged".into())); }
        if sha3(&[&b[..CTR_LEN - 32]]) != b[CTR_LEN - 32..] { return Err(CounterError("the counter file fails its checksum".into())); }
        if b[28..60] != sha3(&[public_key]) { return Err(CounterError("the counter file belongs to another key".into())); }
        let instance_id: [u8; 16] = b[60..76].try_into().unwrap();
        let value = u64::from_be_bytes(b[76..84].try_into().unwrap());
        let digest: [u8; 32] = b[84..116].try_into().unwrap();
        let token = u64::from_be_bytes(b[116..124].try_into().unwrap());
        Ok(DevnetFileCounter { path: path.to_path_buf(), binding: CounterBinding { public_key: public_key.to_vec(), instance_id }, st: CounterState { value, digest }, token })
    }
    pub fn instance_id(&self) -> [u8; 16] { self.binding.instance_id }
}

impl MonotonicCounter for DevnetFileCounter {
    fn binding(&self) -> &CounterBinding { &self.binding }
    fn read(&self) -> Result<CounterState, CounterError> { Ok(self.st) }
    fn acquire_session(&mut self) -> Result<Session, CounterError> {
        let next = self.token.checked_add(1).ok_or_else(|| CounterError("session token overflow".into()))?;
        let old = self.token;
        self.token = next;
        if let Err(e) = self.persist() { self.token = old; return Err(e); }
        Ok(Session::new(next))
    }
    fn advance(&mut self, expected: &CounterState, new_digest: [u8; 32], session: &Session) -> Result<(), CounterError> {
        if session.token() != self.token { return Err(CounterError("superseded session".into())); }
        if *expected != self.st { return Err(CounterError("the counter is not at the expected state".into())); }
        let old = self.st;
        self.st = CounterState { value: old.value.checked_add(1).ok_or_else(|| CounterError("counter overflow".into()))?, digest: new_digest };
        if let Err(e) = self.persist() { self.st = old; return Err(e); }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------------------------ transport
/// Frame: `u32 length (BE) || u8 sender index || payload`. The length is checked against the limit BEFORE any payload byte is read, the payload is
/// read incrementally in 8 KiB chunks (never allocated from the header), and a connection that exceeds the limit, stalls, or names a bad sender
/// is closed immediately.
pub struct Transport {
    rx: Receiver<(usize, Vec<u8>)>,
    out: Vec<Option<SyncSender<Vec<u8>>>>,
    blocked: Arc<Mutex<BTreeSet<usize>>>,
    me: usize,
}

fn parse_blocked(text: &str) -> BTreeSet<usize> { text.split(|c: char| !c.is_ascii_digit()).filter_map(|t| t.parse().ok()).collect() }

impl Transport {
    /// `blocked_file` (optional) lists peer indices to cut off in both directions; it is re-read every 200 ms (the devnet's partition control).
    pub fn start(me: usize, endpoints: Vec<String>, max_frame: u64, queue: usize, blocked_file: Option<PathBuf>) -> std::io::Result<Self> {
        let n = endpoints.len();
        let listener = TcpListener::bind(&endpoints[me])?;
        let (tx, rx) = mpsc::channel::<(usize, Vec<u8>)>();
        let blocked: Arc<Mutex<BTreeSet<usize>>> = Arc::new(Mutex::new(BTreeSet::new()));
        if let Some(f) = blocked_file {
            let b = blocked.clone();
            std::thread::spawn(move || loop {
                let set = std::fs::read_to_string(&f).map(|t| parse_blocked(&t)).unwrap_or_default();
                if let Ok(mut g) = b.lock() { *g = set; }
                std::thread::sleep(Duration::from_millis(200));
            });
        }
        {
            let (tx, blocked) = (tx.clone(), blocked.clone());
            std::thread::spawn(move || {
                for conn in listener.incoming().flatten() {
                    let (tx, blocked) = (tx.clone(), blocked.clone());
                    std::thread::spawn(move || read_frames(conn, n, max_frame, tx, blocked));
                }
            });
        }
        let mut out = vec![];
        for (i, ep) in endpoints.into_iter().enumerate() {
            if i == me { out.push(None); continue; }
            let (stx, srx) = mpsc::sync_channel::<Vec<u8>>(queue);
            let blocked = blocked.clone();
            std::thread::spawn(move || write_frames(me, i, ep, srx, blocked));
            out.push(Some(stx));
        }
        Ok(Transport { rx, out, blocked, me })
    }
    /// Queue a frame for a peer; dropped if the peer's queue is full or the peer is blocked.
    pub fn send(&self, to: usize, bytes: Vec<u8>) {
        if to == self.me { return; }
        if self.blocked.lock().map(|b| b.contains(&to)).unwrap_or(false) { return; }
        if let Some(Some(tx)) = self.out.get(to) { let _ = tx.try_send(bytes); }
    }
    pub fn broadcast(&self, bytes: &[u8]) { for to in 0..self.out.len() { self.send(to, bytes.to_vec()); } }
    pub fn recv(&self, wait: Duration) -> Option<(usize, Vec<u8>)> { self.rx.recv_timeout(wait).ok() }
}

fn read_frames(mut conn: TcpStream, n: usize, max_frame: u64, tx: mpsc::Sender<(usize, Vec<u8>)>, blocked: Arc<Mutex<BTreeSet<usize>>>) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(20)));
    loop {
        let mut head = [0u8; 5];
        if conn.read_exact(&mut head).is_err() { return; }
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as u64;
        let from = head[4] as usize;
        if len > max_frame || from >= n { return; } // closes the connection
        let payload = match read_bounded(&mut (&mut conn).take(len), len) { Ok(p) if p.len() as u64 == len => p, _ => return };
        if blocked.lock().map(|b| b.contains(&from)).unwrap_or(false) { continue; }
        if tx.send((from, payload)).is_err() { return; }
    }
}

fn write_frames(me: usize, peer: usize, endpoint: String, rx: Receiver<Vec<u8>>, blocked: Arc<Mutex<BTreeSet<usize>>>) {
    let mut conn: Option<TcpStream> = None;
    while let Ok(frame) = rx.recv() {
        if blocked.lock().map(|b| b.contains(&peer)).unwrap_or(false) { continue; }
        if conn.is_none() {
            conn = TcpStream::connect_timeout(&endpoint.parse().expect("endpoint"), Duration::from_millis(500)).ok();
            if let Some(c) = &conn { let _ = c.set_nodelay(true); let _ = c.set_write_timeout(Some(Duration::from_secs(10))); }
        }
        let Some(c) = conn.as_mut() else { continue };
        let mut buf = Vec::with_capacity(5 + frame.len());
        buf.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        buf.push(me as u8);
        buf.extend_from_slice(&frame);
        if c.write_all(&buf).is_err() { conn = None; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cf-pqdev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn keygen_refuses_to_overwrite_and_the_loaded_key_matches_the_public_file() {
        let d = tmp("keys");
        let pk = keygen(&d).unwrap();
        assert!(keygen(&d).is_err(), "an existing seed is never replaced");
        assert_eq!(hex::decode(std::fs::read_to_string(d.join(PUB_FILE)).unwrap()).unwrap(), pk);
        assert_eq!(load_signer(&d).unwrap().public_key(), pk.as_slice());
        std::fs::write(d.join(SEED_FILE), "zz").unwrap();
        assert!(load_signer(&d).is_err());
    }

    #[test]
    fn the_devnet_counter_advances_once_per_state_refuses_stale_sessions_and_never_resets_on_damage() {
        let d = tmp("ctr");
        let pk = vec![5u8; 1952];
        let p = d.join("counter");
        let mut c = DevnetFileCounter::create(&p, &pk).unwrap();
        assert!(DevnetFileCounter::create(&p, &pk).is_err());
        let s1 = c.acquire_session().unwrap();
        c.advance(&CounterState::INITIAL, [1; 32], &s1).unwrap();
        assert!(c.advance(&CounterState::INITIAL, [2; 32], &s1).is_err(), "no idempotent form: the expected state moved");
        let st = c.read().unwrap();
        assert_eq!(st.value, 1);
        // a second holder supersedes the first
        let mut c2 = DevnetFileCounter::open(&p, &pk).unwrap();
        assert_eq!(c2.read().unwrap(), st);
        let s2 = c2.acquire_session().unwrap();
        assert!(s2.token() > s1.token());
        assert!(c2.advance(&st, [3; 32], &s1).is_err(), "a superseded session cannot advance");
        c2.advance(&st, [3; 32], &s2).unwrap();
        // another key, a damaged file and a truncated file are refused, not reset
        assert!(DevnetFileCounter::open(&p, &[6u8; 1952]).is_err());
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[100] ^= 1;
        std::fs::write(&p, &bytes).unwrap();
        assert!(DevnetFileCounter::open(&p, &pk).is_err());
        std::fs::write(&p, &bytes[..50]).unwrap();
        assert!(DevnetFileCounter::open(&p, &pk).is_err());
    }

    #[test]
    fn the_partition_file_parser_accepts_lists_and_ignores_junk() {
        assert_eq!(parse_blocked("3"), BTreeSet::from([3]));
        assert_eq!(parse_blocked("0, 2\n3 x"), BTreeSet::from([0, 2, 3]));
        assert!(parse_blocked("").is_empty());
    }

    #[test]
    fn the_transport_drops_oversize_frames_and_bad_senders_and_delivers_valid_ones() {
        let ports: Vec<u16> = (0..2).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()).collect();
        let eps: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
        let t = Transport::start(0, vec![eps[0].clone(), eps[1].clone()], 100, 4, None).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let send = |head_len: u32, from: u8, body: &[u8]| {
            let mut c = TcpStream::connect(&eps[0]).unwrap();
            let mut f = head_len.to_be_bytes().to_vec(); f.push(from); f.extend_from_slice(body);
            c.write_all(&f).unwrap();
            c
        };
        let _c1 = send(101, 1, &[1u8; 101]); // over the limit: closed before reading it
        let _c2 = send(3, 9, b"abc");        // sender index outside the set
        assert!(t.recv(Duration::from_millis(400)).is_none());
        let _c3 = send(3, 1, b"abc");
        assert_eq!(t.recv(Duration::from_secs(2)), Some((1, b"abc".to_vec())));
        // a length that promises more than is sent never delivers a partial message
        let mut c4 = send(50, 1, b"short");
        c4.shutdown(std::net::Shutdown::Both).ok();
        assert!(t.recv(Duration::from_millis(400)).is_none());
    }

    fn cfg(profile: &str, checkpoint: Option<DevnetCheckpoint>) -> DevnetConfig {
        DevnetConfig { label: DEVNET_LABEL.into(), chain_id: "c".into(), protocol_profile: profile.into(), validators: vec![], max_block_payload_bytes: 1, max_message_bytes: 1, max_sync_blocks: 1,
            pacemaker_base_ms: 1, pacemaker_max_ms: 2, min_propose_gap_ms: 0, checkpoint }
    }
    fn ck(interval: u64, max_age: u64) -> DevnetCheckpoint { DevnetCheckpoint { interval, max_age, margin: 2, omit_rotations: 1, alarm_age_intervals: 8 } }

    #[test]
    fn profile_v3_is_off_unless_a_consistent_checkpoint_block_is_present_and_a_v2_config_serializes_without_one() {
        let v2 = "qattice-pq-hotstuff-2-v2";
        assert_eq!(cfg(v2, None).checkpoint_config(), Ok(None), "v2 without a checkpoint block is the unchanged devnet");
        assert!(cfg(v2, Some(ck(4, 24))).checkpoint_config().is_err(), "checkpoint parameters need the v3 profile: no silent v2 with parameters");
        assert!(cfg(chain_forge_consensus::pq_hotstuff::checkpoint::PROFILE_V3, None).checkpoint_config().is_err(), "the v3 profile needs checkpoint parameters: no silent v3 without them");
        let ok = cfg(chain_forge_consensus::pq_hotstuff::checkpoint::PROFILE_V3, Some(ck(4, 24))).checkpoint_config().unwrap().unwrap();
        assert_eq!((ok.params.interval, ok.params.max_age), (4, 24));
        for bad in [ck(0, 8), ck(4, 3), ck(1 << 41, 1 << 42), ck(4, (1 << 50) + 1)] { assert!(cfg(chain_forge_consensus::pq_hotstuff::checkpoint::PROFILE_V3, Some(bad)).checkpoint_config().is_err()); }
        assert!(!serde_json::to_string(&cfg(v2, None)).unwrap().contains("checkpoint"), "a v2 config has no checkpoint key, so its bytes (and genesis hash) are what they always were");
        let back: DevnetConfig = serde_json::from_str(&serde_json::to_string(&cfg(v2, None)).unwrap()).unwrap();
        assert!(back.checkpoint.is_none(), "and an old file without the key still parses");
    }

}

// ------------------------------------------------------------------------------------------------------------------ execution log (test aid)
/// Wraps the executor and, if a path is given, appends the height of every block AFTER its effects are durable (so a kill between the two can leave a gap but never a
/// duplicate). A test aid for the live recovery test; with no path it is a pass-through.
pub struct LoggedApp<X: Executor> { pub inner: X, log: Option<PathBuf> }
impl<X: Executor> LoggedApp<X> { pub fn new(inner: X, log: Option<PathBuf>) -> Self { LoggedApp { inner, log } } }
impl<X: Executor> Executor for LoggedApp<X> {
    fn cursor(&self) -> ExecCursor { self.inner.cursor() }
    fn apply(&mut self, b: &Committed) -> Result<ExecCursor, ExecError> {
        let c = self.inner.apply(b)?;
        if let Some(p) = &self.log {
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).map_err(|e| ExecError::Storage(e.to_string()))?;
            f.write_all(format!("{}\n", b.height).as_bytes()).and_then(|_| f.sync_data()).map_err(|e| ExecError::Storage(e.to_string()))?;
        }
        Ok(c)
    }
}

// ------------------------------------------------------------------------------------------------------------------ operator-staged snapshot (offline)
/// TEST-ONLY crash injection for the DEVNET-ONLY staging tool: if the environment variable `PQDEV_TEST_STAGE_CRASH` names this point, the process exits at once (no
/// cleanup), as a crash between two of the staging writes would. Never set outside tests.
fn crash_point(name: &str) { if std::env::var("PQDEV_TEST_STAGE_CRASH").map_or(false, |v| v == name) { std::process::exit(86); } }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged { pub reference: CheckpointRef, pub evidence_bytes: usize }

/// OPERATOR-STAGED, OFFLINE snapshot staging (this is NOT network installation, which stays disabled). Reads an UNSEEDED donor's block store, builds the header-chain
/// evidence for the `back`-th newest checkpoint reference that authenticates, replays the donor's finalized payloads up to that height through the devnet-interim
/// application, checks that the resulting state digest IS the attested root, and writes (1) the evidence into the target's block store (forward only) and (2) the
/// application state into the target's `app` directory. The target's signing-safety state and counter are never touched. The target node re-authenticates the evidence
/// itself at start; nothing here is trusted by it.
pub fn stage_snapshot(cfg: &DevnetConfig, genesis_hash: [u8; 32], donor: &Path, target: &Path, back: usize, lag: usize) -> Result<Staged, String> {
    let ckpt = cfg.checkpoint_config()?.ok_or("staging needs a v3 config")?;
    let loaded = BlockStore::new(FsStorage::new(donor.join("blocks")).map_err(|e| e.0)?).load().map_err(|e| e.to_string())?;
    if loaded.seeded_height != 0 { return Err("the donor is itself seeded: it does not hold the history below its checkpoint".into()); }
    let set = cfg.set()?;
    let idc = IdCtx { protocol_profile: &cfg.protocol_profile, chain_id: &cfg.chain_id, set: &set };
    let by_id: std::collections::BTreeMap<BlockId, &Block> = loaded.blocks.iter().map(|b| (block_id_of(b, &idc).map(|i| (i, b)))).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    let hq = loaded.high_qc.clone().ok_or("the donor has no high QC yet")?;
    let Cert::Qc(q) = &hq else { return Err("the donor's high QC is the genesis certificate".into()) };
    let (mut chain, mut cur) = (vec![], q.block_id);
    while let Some(b) = by_id.get(&cur) { chain.push((*b).clone()); cur = b.parent_id; }
    chain.reverse();
    if chain.first().map_or(true, |b| b.height != 1) { return Err("the donor's chain does not reach the genesis block (it is being written; retry)".into()); }
    // `lag` > 0 ends the evidence that many blocks BEFORE the donor's tip, with the QC embedded in the next block as its high QC (a valid, older view): the node then has more
    // blocks to fetch, and its post-install round is steered deterministically (used by the controlled-leader test). 0 = the donor's own tip and high QC.
    let hq = if lag > 0 {
        if chain.len() <= lag + 1 { return Err("lag is larger than the donor's chain".into()); }
        let cut = chain.len() - lag;
        let qc = chain[cut].qc.clone();
        chain.truncate(cut);
        qc
    } else { hq };
    let headers: Vec<_> = chain.iter().map(Block::to_header).collect();
    let params = ChainParams { protocol_profile: &cfg.protocol_profile, chain_id: &cfg.chain_id, set: &set, genesis_hash, seed: 0, checkpoint: Some(ckpt.params) };
    let mut refs: Vec<CheckpointRef> = vec![];
    for b in &chain { if let Some(r) = b.checkpoint { if refs.last() != Some(&r) { refs.push(r); } } }
    let mut ok = vec![];
    for r in refs.iter().rev() {
        if authenticate_checkpoint(&params, &Fips204Verifier, Start::Genesis, &headers, Some(&hq), headers.len(), r, &hq, None).is_ok() { ok.push(*r); if ok.len() > back { break; } }
    }
    let cref = *ok.get(back).ok_or_else(|| format!("only {} authenticating checkpoints on the donor's chain", ok.len()))?;
    // STALENESS FIRST, before anything at all is created or written in the target: an install only moves forward
    let blocks_dir = target.join("blocks");
    if blocks_dir.is_dir() {
        let bs = BlockStore::new(FsStorage::new(&blocks_dir).map_err(|e| e.0)?);
        if let Some((have, _, _)) = bs.load_seed_evidence().map_err(|e| e.to_string())? {
            if have > cref.height { return Err(format!("stale: the target already holds a checkpoint at height {have}, above {}; installs only move forward; nothing was changed", cref.height)); }
        }
    }
    // ... and the same for the APPLICATION state: a snapshot BELOW what the target has already executed would rewind it (a real application would re-apply effects), and a
    // different block or root at the same height is a divergence. Read-only; a damaged or foreign application state is refused, never overwritten silently.
    let app_dir = target.join("app");
    if app_dir.is_dir() {
        let cur = InterimApp::open(FsStorage::new(&app_dir).map_err(|e| e.0)?, genesis_hash).map_err(|e| format!("the target's application state cannot be read ({e}); remove it explicitly if it is to be replaced; nothing was changed"))?.cursor();
        if cur.height > cref.height { return Err(format!("stale: the target's application state is already at height {}, above the checkpoint at {}; installing an older snapshot would rewind it; nothing was changed", cur.height, cref.height)); }
        if cur.height == cref.height && (cur.block_id != cref.block_id || cur.state_digest != cref.state_root) { return Err("the target's application state at the checkpoint height is a different block or state: it has diverged; nothing was changed".into()); }
    }
    let ev = SeedEvidence { headers, final_qc: Some(hq.clone()), cref, high_qc: hq, high_tc: None };
    // the application state at the checkpoint: the donor's finalized payloads 1..=H through the interim application, built in a scratch directory OUTSIDE the target
    let stage = std::env::temp_dir().join(format!("pqdev-stage-{}-{}", std::process::id(), cref.height));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
    let built = (|| -> Result<Vec<u8>, String> {
        let mut app = InterimApp::open(FsStorage::new(&stage).map_err(|e| e.0)?, genesis_hash).map_err(|e| e.to_string())?;
        for b in chain.iter().filter(|b| b.height <= cref.height) {
            let id = block_id_of(b, &idc).map_err(|e| e.to_string())?;
            app.apply(&Committed { id, round: b.round, height: b.height, payload: b.payload.clone() }).map_err(|e| e.to_string())?;
        }
        let cur = app.cursor();
        if cur.height != cref.height || cur.block_id != cref.block_id || cur.state_digest != cref.state_root { return Err("the replayed application state is not the attested checkpoint (height, block or root differ)".into()); }
        app.storage().read("app-state").map_err(|e| e.0)?.ok_or_else(|| "no application state was written".to_string())
    })();
    let _ = std::fs::remove_dir_all(&stage);
    let bytes = built?;
    // WRITE PHASE. Order: evidence, then the application state (write, sync, rename, sync the directory). A crash after the evidence leaves new evidence over an OLDER
    // executor, which the node refuses to start with (ExecutorBehindBase) - it never signs; redoing the staging completes it. A crash after the rename leaves a complete
    // generation. (The crash model is process death; a power-loss/fsync-reordering model is not tested.)
    for sub in ["blocks", "app"] { std::fs::create_dir_all(target.join(sub)).map_err(|e| e.to_string())?; }
    let mut bs = BlockStore::new(FsStorage::new(&blocks_dir).map_err(|e| e.0)?);
    let enc = ev.encode();
    bs.put_seed_evidence(cref.height, &cref.block_id, &enc).map_err(|e| e.to_string())?;
    crash_point("after-evidence");
    let mut dst = FsStorage::new(target.join("app")).map_err(|e| e.0)?;
    dst.write_tmp("app-state.tmp", &bytes).and_then(|_| dst.sync_file("app-state.tmp")).map_err(|e| e.0)?;
    crash_point("after-app-tmp");
    dst.rename("app-state.tmp", "app-state").map_err(|e| e.0)?;
    crash_point("after-app-rename");
    dst.sync_dir().map_err(|e| e.0)?;
    Ok(Staged { reference: cref, evidence_bytes: enc.len() })

}
