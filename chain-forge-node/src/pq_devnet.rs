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

use chain_forge_consensus::pq_hotstuff::driver::DriverConfig;
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
        Ok((EngineConfig { chain_id: self.chain_id.clone(), protocol_profile: self.protocol_profile.clone(), set, my_index, genesis_hash, limits: self.limits(), seed: 0 }, my_index))
    }

    pub fn driver_config(&self) -> DriverConfig {
        DriverConfig {
            max_sync_blocks: self.max_sync_blocks, pace: PacemakerConfig { base: self.pacemaker_base_ms, max: self.pacemaker_max_ms },
            sync_ttl: 3 * self.pacemaker_base_ms, sync_outstanding: 8, min_propose_gap: self.min_propose_gap_ms, park_capacity: 32, park_ttl: 6 * self.pacemaker_base_ms, recent: 64,
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
}
