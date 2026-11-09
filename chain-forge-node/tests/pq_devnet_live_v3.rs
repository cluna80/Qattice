//! LIVE four-process PQ-HotStuff-2 PROFILE-V3 recovery test (feature `pq-devnet`). **DEVNET ONLY.**
//!
//! What this is: four OS processes, real FIPS 204 ML-DSA-65 keys generated on this machine, a FRESH v3 genesis that binds the checkpoint parameters, local TCP, the real
//! signing-safety store with the NON-PRODUCTION file counter, persistent block stores, and the DEVNET-INTERIM application. One node loses its blocks and application
//! state (its signing-safety state survives), is brought back from an OPERATOR-STAGED, OFFLINE snapshot (evidence + interim application state; NOT automated network
//! installation, which stays disabled), is killed (TerminateProcess/SIGKILL) and restarted, is given a SECOND, newer snapshot, and is killed and restarted again.
//!
//! What it demonstrates is INTERIM-STATE recovery: the application hash-chains opaque devnet-interim payloads. It is NOT recovery of the real Qattice application
//! (transactions, accounts, balances), whose snapshot format and canonical state root do not exist yet. Pruning is not exercised (it is disabled).
//!
//! Run: cargo test --release -p chain-forge-node --features pq-devnet --test pq_devnet_live_v3 -- --nocapture
#![cfg(feature = "pq-devnet")]
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chain_forge_consensus::pq_hotstuff::safety::{decode_record, STATE_FILE};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_pq-devnet-node");
const N: usize = 4;
const VICTIM: usize = 3;
const K: u64 = 4;

/// The live tests each run four OS processes that do synchronous file I/O and real signatures. Run concurrently (cargo's default) they compete for the same disk and CPU,
/// which slows every sync and widens the window in which a kill can interrupt a signing commit. They add nothing to each other, so they run one at a time.
static LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> { LIVE.lock().unwrap_or_else(|e| e.into_inner()) }

struct Net { dirs: Vec<PathBuf>, cfg: PathBuf, kids: Vec<Option<Child>>, root: PathBuf, genesis_hash_file: PathBuf }

impl Drop for Net {
    fn drop(&mut self) {
        for k in self.kids.iter_mut().flatten() { let _ = k.kill(); let _ = k.wait(); }
        if std::env::var("PQDEV_KEEP").is_err() { let _ = std::fs::remove_dir_all(&self.root); }
    }
}

fn free_ports(n: usize) -> Vec<u16> {
    let ls: Vec<std::net::TcpListener> = (0..n).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    ls.iter().map(|l| l.local_addr().unwrap().port()).collect()
}
fn run_ok(args: &[&str]) -> String {
    let o = Command::new(BIN).args(args).output().expect("spawn");
    assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn u(v: &Value) -> u64 { v.as_u64().unwrap_or(0) }

impl Net {
    fn new(tag: &str) -> Net {
        let root = std::env::temp_dir().join(format!("cf-pqdev-v3-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dirs: Vec<PathBuf> = (0..N).map(|i| root.join(format!("n{i}"))).collect();
        for d in &dirs { run_ok(&["keygen", "--dir", d.to_str().unwrap()]); }
        let cfg = root.join("pq-devnet-v3.json");
        let ports: Vec<String> = free_ports(N).iter().map(|p| p.to_string()).collect();
        let dirs_arg = dirs.iter().map(|d| d.to_str().unwrap().to_string()).collect::<Vec<_>>().join(",");
        run_ok(&["assemble", "--out", cfg.to_str().unwrap(), "--chain-id", "qattice-pqhs2-v3-devnet-live", "--ports", &ports.join(","), "--dirs", &dirs_arg,
                 "--checkpoint-interval", &K.to_string(), "--checkpoint-max-age", "24", "--checkpoint-margin", "4"]);
        Net { dirs, cfg, kids: (0..N).map(|_| None).collect(), root: root.clone(), genesis_hash_file: root.join("unused") }
    }
    fn start(&mut self, i: usize) {
        let _ = std::fs::remove_file(self.dirs[i].join("status.json")); // so that the next status read is from the NEW process
        let log = std::fs::OpenOptions::new().create(true).append(true).open(self.dirs[i].join("node.log")).unwrap();
        let child = Command::new(BIN).args(["run", "--config", self.cfg.to_str().unwrap(), "--dir", self.dirs[i].to_str().unwrap(), "--exec-log", self.dirs[i].join("exec.log").to_str().unwrap()])
            .stdout(Stdio::null()).stderr(log).spawn().expect("spawn node");
        self.kids[i] = Some(child);
    }
    fn crash(&mut self, i: usize) { if let Some(mut k) = self.kids[i].take() { let _ = k.kill(); let _ = k.wait(); } }
    fn alive(&mut self, i: usize) -> bool { self.kids[i].as_mut().map_or(false, |k| matches!(k.try_wait(), Ok(None))) }
    fn status(&self, i: usize) -> Option<Value> { serde_json::from_slice(&std::fs::read(self.dirs[i].join("status.json")).ok()?).ok() }
    fn height(&self, i: usize) -> u64 { self.status(i).map_or(0, |s| u(&s["exec"]["height"])) }
    fn heights(&self) -> Vec<u64> { (0..N).map(|i| self.height(i)).collect() }
    fn log_tail(&self, i: usize) -> String { std::fs::read_to_string(self.dirs[i].join("node.log")).map(|t| t.lines().rev().take(6).collect::<Vec<_>>().join(" | ")).unwrap_or_default() }
    fn wait(&mut self, what: &str, secs: u64, cond: impl Fn(&Net) -> bool) {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            // a node that exits while we are waiting for progress is a failure now, not after the timeout
            for i in 0..N { if let Some(k) = self.kids[i].as_mut() { if let Ok(Some(st)) = k.try_wait() { panic!("node {i} exited ({st}) while waiting for: {what}; {}", self.log_tail(i)); } } }
            if cond(self) { println!("  [{:>5.1}s] {what}: heights {:?}", t.elapsed().as_secs_f32(), self.heights()); return; }
            std::thread::sleep(Duration::from_millis(200));
        }
        let logs: Vec<String> = (0..N).map(|i| format!("n{i}: {}", self.log_tail(i))).collect();
        panic!("timed out ({secs}s) waiting for: {what}; heights {:?}; {:?}", self.heights(), logs);
    }
    /// Safety floors as the node last reported them: (hvr, hqr, counter).
    fn floors(&self, i: usize) -> (u64, u64, u64) { let s = self.status(i).expect("status"); (u(&s["safety"]["hvr"]), u(&s["safety"]["hqr"]), u(&s["safety"]["counter"])) }

    /// Every pair of nodes agrees on committed block id and execution root (application state digest) at every height both report; no node reported a fatal error
    /// or signed while recovering.
    fn assert_agreement(&self, label: &str) -> usize {
        let mut by_h: std::collections::BTreeMap<u64, (String, String)> = Default::default();
        let mut compared = 0;
        for i in 0..N {
            let s = self.status(i).expect("status");
            assert!(s["fatal"].is_null(), "{label}: node {i} reported a fatal error: {}", s["fatal"]);
            assert_eq!(s["signed_while_recovering"], Value::Bool(false), "{label}: node {i} signed while recovering");
            assert_eq!(s["sent_signed_while_recovering"], Value::Bool(false), "{label}: node {i} sent a message it signed (new or a re-send) while recovering");
            for c in s["recent"].as_array().unwrap() {
                let (h, id, dg) = (u(&c["height"]), c["block_id"].as_str().unwrap().to_string(), c["state_digest"].as_str().unwrap().to_string());
                if let Some(prev) = by_h.insert(h, (id.clone(), dg.clone())) { assert_eq!(prev, (id, dg), "{label}: DISAGREEMENT at height {h}"); compared += 1; }
            }
        }
        assert!(compared > 0, "{label}: no overlapping heights to compare");
        println!("  agreement ok ({label}): {compared} cross-node comparisons of committed block id AND execution root");
        compared
    }
    /// Executed heights recorded by node `i` in `file`, in order.
    fn exec_log(&self, i: usize, file: &str) -> Vec<u64> {
        std::fs::read_to_string(self.dirs[i].join(file)).map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect()).unwrap_or_default()
    }
    /// One raw staging attempt, optionally with the TEST-ONLY crash hook set (the tool exits at that point with code 86).
    fn stage_raw(&self, target: usize, donor: usize, back: usize, crash: Option<&str>) -> std::process::Output {
        let mut c = Command::new(BIN);
        c.args(["stage-snapshot", "--config", self.cfg.to_str().unwrap(), "--donor", self.dirs[donor].to_str().unwrap(), "--dir", self.dirs[target].to_str().unwrap(), "--back", &back.to_string()]);
        if let Some(p) = crash { c.env("PQDEV_TEST_STAGE_CRASH", p); }
        c.output().unwrap()
    }
    fn wait_exit(&mut self, i: usize, secs: u64) -> Option<std::process::ExitStatus> {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if let Some(k) = self.kids[i].as_mut() { if let Ok(Some(st)) = k.try_wait() { self.kids[i] = None; return Some(st); } }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }
    /// Operator-staged OFFLINE snapshot from `donor` into the (stopped) `target`, retried while the donor's files are mid-write. Returns (height, block id hex, root hex).
    fn stage(&self, target: usize, donor: usize, back: usize) -> Result<(u64, String, String), String> { self.stage_lag(target, donor, back, 0) }
    fn stage_lag(&self, target: usize, donor: usize, back: usize, lag: usize) -> Result<(u64, String, String), String> {
        let mut last = String::new();
        for _ in 0..20 {
            let o = Command::new(BIN).args(["stage-snapshot", "--config", self.cfg.to_str().unwrap(), "--donor", self.dirs[donor].to_str().unwrap(), "--dir", self.dirs[target].to_str().unwrap(), "--back", &back.to_string(), "--lag", &lag.to_string()]).output().unwrap();
            if o.status.success() {
                let v: Value = serde_json::from_slice(&o.stdout).unwrap();
                assert_eq!(v["staged"], Value::Bool(true));
                return Ok((u(&v["height"]), v["block_id"].as_str().unwrap().into(), v["state_root"].as_str().unwrap().into()));
            }
            last = String::from_utf8_lossy(&o.stderr).to_string();
            if last.contains("stale") { return Err(last); }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(last)
    }
}

/// Every file under `dir` (relative path -> bytes). Used to show that a refused operation changed NOTHING.
fn tree(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, d: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() { walk(base, &p, out); } else { out.insert(p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read(&p).unwrap()); }
        }
    }
    let mut m = Default::default(); walk(dir, dir, &mut m); m
}

/// Names of the files that differ between two `tree` snapshots (added, removed or changed).
fn diff_names(a: &std::collections::BTreeMap<String, Vec<u8>>, b: &std::collections::BTreeMap<String, Vec<u8>>) -> Vec<String> {
    let mut v: Vec<String> = a.keys().chain(b.keys()).filter(|k| a.get(*k) != b.get(*k)).cloned().collect();
    v.sort(); v.dedup(); v
}

/// The signing-safety state of a STOPPED node, reduced to what decides whether anything was signed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SafetySig {
    /// Every file under `safety/` except temporary files (an interrupted commit can leave one, and opening the store clears it).
    files: std::collections::BTreeMap<String, Vec<u8>>,
    /// The monotonic counter's committed value and digest (bytes 76..116 of the counter file; the session token at 116..124 is bumped by merely opening it).
    counter_value: u64,
    counter_digest: [u8; 32],
    /// The counter and digest of the durable safety RECORD.
    record_counter: u64,
    record_digest: [u8; 32],
}
fn safety_sig(vd: &Path) -> SafetySig {
    let mut files = tree(&vd.join("safety"));
    files.retain(|k, _| !k.ends_with(".tmp"));
    let c = std::fs::read(vd.join("counter")).unwrap();
    let state = files.get(STATE_FILE).expect("the safety record exists").clone();
    SafetySig {
        counter_value: u64::from_be_bytes(c[76..84].try_into().unwrap()), counter_digest: c[84..116].try_into().unwrap(),
        record_counter: decode_record(&state).expect("the safety record decodes").counter, record_digest: state[state.len() - 32..].try_into().unwrap(), files,
    }
}
/// Nothing was SIGNED between `before` and `after`. Exact model, no tolerance: every signature rewrites the record, so the record and marker files must be byte-identical.
/// The only thing opening the store may legitimately do is finish a commit that a kill interrupted - the record is durable but the counter has not advanced
/// (`record_counter == counter_value + 1`; "nothing from this record was ever returned") - and then the counter must be EXACTLY at that record's digest, one higher.
/// Otherwise the counter must be exactly where it was.
fn check_no_signing(before: &SafetySig, after: &SafetySig) -> Result<(), String> {
    if before.files != after.files { return Err(format!("the signing-safety files changed (a new signature?): {:?}", diff_names(&before.files, &after.files))); }
    let interrupted = before.record_counter == before.counter_value + 1;
    let want = if interrupted { (before.counter_value + 1, before.record_digest) } else { (before.counter_value, before.counter_digest) };
    if (after.counter_value, after.counter_digest) != want {
        return Err(format!("the counter is at {} but the exact model wants {} (an interrupted commit was {}pending before: record counter {}, counter {})",
            after.counter_value, want.0, if interrupted { "" } else { "NOT " }, before.record_counter, before.counter_value));
    }
    Ok(())
}
fn assert_no_signing(label: &str, before: &SafetySig, after: &SafetySig) { if let Err(e) = check_no_signing(before, after) { panic!("{label}: {e}"); } }

#[test]
fn the_no_signing_model_accepts_the_completion_of_an_interrupted_commit_and_nothing_else() {
    let sig = |files: &[(&str, &[u8])], cv: u64, cd: u8, rc: u64, rd: u8| SafetySig { files: files.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect(), counter_value: cv, counter_digest: [cd; 32], record_counter: rc, record_digest: [rd; 32] };
    let quiet = sig(&[("state", b"a")], 7, 1, 7, 1);
    assert_eq!(check_no_signing(&quiet, &quiet.clone()), Ok(()));
    // a kill landed between "record durable" and "counter advanced": opening finishes it - exactly one step, to the record's digest
    let window = sig(&[("state", b"a")], 7, 1, 8, 2);
    assert_eq!(check_no_signing(&window, &sig(&[("state", b"a")], 8, 2, 8, 2)), Ok(()), "an interrupted commit completed by opening the store is accepted");
    // (what, before, after): each of these must be REJECTED
    let bad = [
        ("a new signature rewrote the record", quiet.clone(), sig(&[("state", b"b")], 8, 3, 8, 3)),
        ("the counter moved with no interrupted commit", quiet.clone(), sig(&[("state", b"a")], 8, 2, 7, 1)),
        ("the counter moved but not to the record's digest", window.clone(), sig(&[("state", b"a")], 8, 9, 8, 2)),
        ("the counter moved more than one step", window.clone(), sig(&[("state", b"a")], 9, 2, 8, 2)),
        ("an interrupted commit was left pending", window.clone(), window.clone()),
    ];
    for (what, before, after) in bad {
        assert!(check_no_signing(&before, &after).is_err(), "the model must reject: {what}");
    }
}

/// No duplicates, strictly increasing; at most `max_gaps` missing heights (a kill between the durable application step and the log append can lose one line, never repeat one).
fn check_log(label: &str, log: &[u64], first: u64, max_gaps: usize) {
    assert!(!log.is_empty(), "{label}: nothing executed");
    assert_eq!(log[0], first, "{label}: the first block executed after the snapshot must be the one directly above it");
    assert!(log.windows(2).all(|w| w[1] > w[0]), "{label}: DUPLICATE or out-of-order execution: {:?}", &log[..log.len().min(40)]);
    let gaps: usize = log.windows(2).map(|w| (w[1] - w[0] - 1) as usize).sum();
    assert!(gaps <= max_gaps, "{label}: {gaps} missing heights (allowed {max_gaps}) in {:?}", &log[..log.len().min(40)]);
}

#[test]
fn live_v3_four_processes_snapshot_recovery_kill_restart_second_install_and_agreement_without_duplicate_execution() {
    let _serial = serial();
    let mut net = Net::new("a");
    let _ = &net.genesis_hash_file;

    // ---- 0. a FRESH v3 genesis that binds the checkpoint parameters, real ML-DSA-65 keys, four processes
    let cfg_text = std::fs::read_to_string(&net.cfg).unwrap();
    assert!(cfg_text.contains("qattice-pq-hotstuff-2-v3") && cfg_text.contains("\"checkpoint\"") && cfg_text.contains("\"max_age\": 24"), "the genesis file names profile v3 and carries the checkpoint parameters");
    for i in 0..N { let pk = std::fs::read_to_string(net.dirs[i].join("validator.pub")).unwrap(); assert_eq!(pk.trim().len(), 2 * 1952, "node {i} has a real ML-DSA-65 public key (1952 bytes, hex)"); }
    for i in 0..N { net.start(i); }
    net.wait("all four execute height 48 (references are flowing)", 240, |n| n.heights().iter().all(|h| *h >= 48));
    net.assert_agreement("steady state");
    // the checkpoint parameters are bound into the genesis: staging against a file whose parameters differ cannot authenticate the same chain
    let altered = net.root.join("altered.json");
    std::fs::write(&altered, cfg_text.replace("\"max_age\": 24", "\"max_age\": 25")).unwrap();
    let o = Command::new(BIN).args(["stage-snapshot", "--config", altered.to_str().unwrap(), "--donor", net.dirs[0].to_str().unwrap(), "--dir", net.root.join("scratch").to_str().unwrap()]).output().unwrap();
    assert!(!o.status.success(), "evidence from a chain with other checkpoint parameters must not authenticate: {}", String::from_utf8_lossy(&o.stdout));

    // ---- 1. the victim loses its blocks and application state; its signing-safety state survives; install A is staged offline
    let pre = net.floors(VICTIM);
    net.crash(VICTIM);
    let pre_kill = net.floors(VICTIM); // the last status the process wrote (at most ~250 ms before the kill)
    assert!(pre_kill.0 > 0 && pre_kill.1 > 0 && pre_kill.2 > 0 && pre_kill >= pre, "the victim has been signing: {pre_kill:?}");
    let vd = net.dirs[VICTIM].clone();
    std::fs::remove_dir_all(vd.join("blocks")).unwrap();
    std::fs::remove_dir_all(vd.join("app")).unwrap();
    std::fs::rename(vd.join("exec.log"), vd.join("exec.log.epoch0")).unwrap();
    net.wait("the three others keep finalizing", 120, |n| (0..3).all(|i| n.height(i) >= 56));
    let (a_h, a_id, a_root) = net.stage(VICTIM, 0, 1).expect("stage install A");
    println!("  staged install A: height {a_h}, block {}…, root {}…", &a_id[..8], &a_root[..8]);
    assert!(a_h % K == 0 && a_h > 8 && a_h < net.height(0));
    net.start(VICTIM);
    net.wait("the victim's first status from the new process", 60, |n| n.status(VICTIM).is_some());
    let first = net.status(VICTIM).unwrap();
    assert_eq!(first["base"]["height"].as_u64(), Some(a_h), "the node rebuilt the checkpoint base from the stored evidence it re-authenticated");
    assert_eq!(first["base"]["id"].as_str(), Some(a_id.as_str()));
    let f1 = (u(&first["safety"]["hvr"]), u(&first["safety"]["hqr"]), u(&first["safety"]["counter"]));
    assert!(f1.0 >= pre_kill.0 && f1.1 >= pre_kill.1 && f1.2 >= pre_kill.2, "signing floors survived process death: before {pre_kill:?}, after start {f1:?}");
    assert_eq!(u(&first["exec"]["height"]), a_h, "the executor starts exactly at the staged checkpoint");
    net.wait("the victim recovers and catches up", 240, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) >= a_h + 12 && u(&s["exec"]["height"]) + 3 >= n.height(0)));
    assert!(net.alive(VICTIM), "the recovered node is still running");
    let s = net.status(VICTIM).unwrap();
    assert!(u(&s["sync_requests"]) > 0, "it caught up by block sync");
    net.assert_agreement("after install A");
    check_log("install A", &net.exec_log(VICTIM, "exec.log"), a_h + 1, 0);
    let recovered_floors = net.floors(VICTIM);
    assert!(recovered_floors.0 >= f1.0 && recovered_floors.1 >= f1.1 && recovered_floors.2 >= f1.2, "floors only moved forward");

    // ---- 2. kill and restart the recovered node: same base, history and cursor survive; nothing re-executes
    let before = net.status(VICTIM).unwrap();
    net.crash(VICTIM);
    net.start(VICTIM);
    net.wait("the victim's first status after the restart", 60, |n| n.status(VICTIM).is_some());
    let again = net.status(VICTIM).unwrap();
    assert_eq!(again["base"]["id"].as_str(), Some(a_id.as_str()), "the same base is reconstructed after process death");
    assert!(u(&again["exec"]["height"]) >= u(&before["exec"]["height"]).saturating_sub(1), "no rewind of the executed state");
    assert!(u(&again["committed_height"]) + 2 >= u(&before["committed_height"]), "committed history survived");
    let f2 = (u(&again["safety"]["hvr"]), u(&again["safety"]["hqr"]), u(&again["safety"]["counter"]));
    assert!(f2.0 >= u(&before["safety"]["hvr"]) && f2.1 >= u(&before["safety"]["hqr"]) && f2.2 >= u(&before["safety"]["counter"]), "floors did not go back across the restart");
    net.wait("the restarted node resumes", 120, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) >= u(&before["exec"]["height"]) + 6));
    net.assert_agreement("after restart 1");
    check_log("after restart 1", &net.exec_log(VICTIM, "exec.log"), a_h + 1, 1);

    // ---- 3. the victim is stopped FIRST; the network moves on without it; a NEWER snapshot B, strictly above everything the victim ever executed, is staged over its old
    // store (a stale staging attempt is refused before anything is touched)
    net.crash(VICTIM);
    std::fs::rename(vd.join("exec.log"), vd.join("exec.log.epoch1")).unwrap();
    let victim_last = net.exec_log(VICTIM, "exec.log.epoch1").last().copied().unwrap();
    net.wait("the three others advance well beyond the stopped victim", 240, |n| (0..3).all(|i| n.height(i) >= victim_last + 40));
    let app_before = std::fs::read(vd.join("app").join("app-state")).unwrap();
    let (b_h, b_id, _b_root) = net.stage(VICTIM, 1, 1).expect("stage install B");
    assert!(b_h > victim_last, "install B ({b_h}) is strictly above the highest block the victim ever executed ({victim_last}): a real forward install, not a replacement by an older state");
    assert!(b_h > a_h + 8, "the second checkpoint ({b_h}) is well above the first ({a_h})");
    assert_ne!(std::fs::read(vd.join("app").join("app-state")).unwrap(), app_before, "staging B replaced the application state");
    let app_b = std::fs::read(vd.join("app").join("app-state")).unwrap();
    let whole = tree(&vd);
    let stale = net.stage(VICTIM, 0, 3);
    assert!(matches!(&stale, Err(m) if m.contains("stale")), "an older checkpoint is refused: {stale:?}");
    assert_eq!(std::fs::read(vd.join("app").join("app-state")).unwrap(), app_b, "and the stale attempt did not touch the application state");
    assert!(tree(&vd) == whole, "a refused stale staging left the ENTIRE target (evidence, blocks, application state, safety state, logs) byte-for-byte unchanged");
    let pre_b = net.floors(VICTIM);
    net.start(VICTIM);
    net.wait("the victim's first status from the new process", 60, |n| n.status(VICTIM).is_some());
    let first_b = net.status(VICTIM).unwrap();
    assert_eq!(first_b["base"]["height"].as_u64(), Some(b_h), "the NEWEST evidence is the base");
    assert_eq!(first_b["base"]["id"].as_str(), Some(b_id.as_str()));
    let fb = (u(&first_b["safety"]["hvr"]), u(&first_b["safety"]["hqr"]), u(&first_b["safety"]["counter"]));
    assert!(fb.0 >= pre_b.0 && fb.1 >= pre_b.1 && fb.2 >= pre_b.2, "floors did not go back across the second install: {pre_b:?} -> {fb:?}");
    net.wait("the victim recovers from the second snapshot", 240, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) >= b_h + 10 && u(&s["exec"]["height"]) + 3 >= n.height(0)));
    net.assert_agreement("after install B");
    check_log("install B", &net.exec_log(VICTIM, "exec.log"), b_h + 1, 0);

    // ---- 4. another kill and restart on top of the second install
    net.crash(VICTIM);
    net.start(VICTIM);
    net.wait("the victim's first status after the last restart", 60, |n| n.status(VICTIM).is_some());
    assert_eq!(net.status(VICTIM).unwrap()["base"]["id"].as_str(), Some(b_id.as_str()), "the second base survives process death");
    let pre_end = net.height(0);
    net.wait("the victim is back in step", 240, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) >= pre_end + 6 && u(&s["exec"]["height"]) + 3 >= n.height(0)));

    // ---- 5. final: everybody alive, nobody fatal, nobody signed while recovering; committed block ids and execution roots agree
    for i in 0..N { assert!(net.alive(i), "node {i} stopped: {}", net.log_tail(i)); }
    net.assert_agreement("end");
    check_log("after the last restart", &net.exec_log(VICTIM, "exec.log"), b_h + 1, 1);
    // at one common height all four report the identical committed block id and execution root (the victim's history starts at its snapshot)
    let common = (0..N).map(|i| net.height(i)).min().unwrap().saturating_sub(2);
    let at = |i: usize| -> Option<(String, String)> { net.status(i)?["recent"].as_array()?.iter().find(|c| u(&c["height"]) == common).map(|c| (c["block_id"].as_str().unwrap().to_string(), c["state_digest"].as_str().unwrap().to_string())) };
    let want = at(0).expect("height reported by node 0");
    for i in 0..N { assert_eq!(at(i).as_ref(), Some(&want), "node {i} at height {common}"); }
    println!("final heights {:?}; all four agree at height {common}", net.heights());
}


#[test]
fn live_v3_a_crash_between_the_staging_writes_never_lets_the_node_sign_on_a_half_staged_snapshot_and_a_stale_staging_changes_nothing() {
    let _serial = serial();
    let mut net = Net::new("c");
    for i in 0..N { net.start(i); }
    net.wait("all four execute height 48", 240, |n| n.heights().iter().all(|h| *h >= 48));
    net.crash(VICTIM);
    let vd = net.dirs[VICTIM].clone();
    std::fs::remove_dir_all(vd.join("blocks")).unwrap();
    std::fs::remove_dir_all(vd.join("app")).unwrap();
    std::fs::rename(vd.join("exec.log"), vd.join("exec.log.epoch0")).unwrap();
    net.wait("the three others keep finalizing", 120, |n| (0..3).all(|i| n.height(i) >= 56));
    // The baseline is read after the kill, and the kill can land in the middle of a signing commit; see `assert_no_signing` for the exact model.
    let mut signing_state = safety_sig(&vd);

    // ---- crash 1: the process dies right after the evidence was written and before ANY application state exists
    let o = net.stage_raw(VICTIM, 0, 1, Some("after-evidence"));
    assert_eq!(o.status.code(), Some(86), "the staging tool died at the injected point: {}", String::from_utf8_lossy(&o.stderr));
    assert!(tree(&vd).keys().any(|k| k.starts_with("blocks/seed-")), "the evidence is on disk");
    assert!(!tree(&vd).keys().any(|k| k == "app/app-state"), "and no application state is");
    net.start(VICTIM);
    let st = net.wait_exit(VICTIM, 60).expect("a node over half-staged state must refuse to run, not keep running");
    assert!(!st.success());
    assert!(net.log_tail(VICTIM).contains("below the seeded checkpoint"), "refused for the right reason: {}", net.log_tail(VICTIM));
    assert!(net.status(VICTIM).is_none(), "it never got as far as reporting a status, let alone signing");
    let now = safety_sig(&vd);
    assert_no_signing("after the first refused start", &signing_state, &now);
    signing_state = now; // from here the state is settled: any change at all would be a signature

    // ---- crash 2: the process dies after the application state was written to its temporary file and before it was renamed into place
    let o = net.stage_raw(VICTIM, 0, 1, Some("after-app-tmp"));
    assert_eq!(o.status.code(), Some(86), "{}", String::from_utf8_lossy(&o.stderr));
    let t = tree(&vd);
    assert!(t.contains_key("app/app-state.tmp") && !t.contains_key("app/app-state"), "the state is staged but not in place");
    net.start(VICTIM);
    let st = net.wait_exit(VICTIM, 60).expect("must refuse to run");
    assert!(!st.success());
    assert!(net.log_tail(VICTIM).contains("below the seeded checkpoint"), "{}", net.log_tail(VICTIM));
    let now = safety_sig(&vd);
    assert_no_signing("after the second refused start", &signing_state, &now);

    // ---- crash 3: the process dies right after the rename: a COMPLETE generation (evidence + matching application state) - the node recovers from it
    let o = net.stage_raw(VICTIM, 0, 1, Some("after-app-rename"));
    assert_eq!(o.status.code(), Some(86), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(tree(&vd).contains_key("app/app-state"), "the application state is in place");
    net.start(VICTIM);
    net.wait("the victim's first status", 60, |n| n.status(VICTIM).is_some());
    let first = net.status(VICTIM).unwrap();
    let base = u(&first["base"]["height"]);
    assert!(base > 8 && base % K == 0 && u(&first["exec"]["height"]) == base, "a consistent generation: base {base}, executor at the base");
    let f = (u(&first["safety"]["hvr"]), u(&first["safety"]["hqr"]), u(&first["safety"]["counter"]));
    assert!(f.0 > 0 && f.1 > 0 && f.2 > 0, "the floors the node had before are still there: {f:?}");
    net.wait("the victim recovers and catches up", 240, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) >= base + 10 && u(&s["exec"]["height"]) + 3 >= n.height(0)));
    net.assert_agreement("after the crash-injected staging");
    check_log("after the crash-injected staging", &net.exec_log(VICTIM, "exec.log"), base + 1, 0);

    // ---- a staging attempt that is NEWER than the installed evidence but BELOW what the target has already executed is refused (it would rewind the application state)
    net.crash(VICTIM);
    let executed = net.exec_log(VICTIM, "exec.log").last().copied().unwrap();
    let whole = tree(&vd);
    let o = net.stage_raw(VICTIM, 0, 0, None); // the newest authenticating checkpoint: above the installed one, below the executed height
    let err = String::from_utf8_lossy(&o.stderr).to_string();
    assert!(!o.status.success() && err.contains("stale") && err.contains("rewind"), "installing a snapshot below the executed height (executed {executed}) must be refused: {err}");
    assert!(tree(&vd) == whole, "and that refusal changed nothing in the target");
    // ---- a stale staging attempt (an older checkpoint) is refused and changes NOTHING in the target
    let o = net.stage_raw(VICTIM, 0, 3, None);
    assert!(!o.status.success() && String::from_utf8_lossy(&o.stderr).contains("stale"), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(tree(&vd) == whole, "the stale attempt left the entire target unchanged (no file added, removed or rewritten, no scratch directory left behind)");
    net.start(VICTIM);
    net.wait("the victim restarts normally afterwards", 240, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) + 3 >= n.height(0)));
    net.assert_agreement("end");
    for i in 0..N { assert!(net.alive(i), "node {i} stopped: {}", net.log_tail(i)); }
}

/// CONTROLLED LEADER SCENARIO. The proposal gate is only reached if the recovering node is the LEADER of its post-install round. That round is `max(high QC round + 1, hvr)`,
/// where `hvr` is the node's own last signed round, so what decides whether the victim leads it is WHERE IT WAS KILLED, not how the snapshot is staged (observed: varying the
/// staged evidence only moves the round while the victim is down, and no QC can form for the round just before its own slot, so it never lands there). The victim is therefore
/// run, killed at a varying moment, wiped, staged with evidence old enough that the round is its last signed round, and started - repeatedly, letting it rejoin between tries so
/// that its last signed round moves on - until its first status says it leads its round while recovering. The test then waits for the node itself to report that its engine was
/// ASKED to propose while recovering and REFUSED (the gate was reached and held) and checks that nothing was signed or sent.
/// What this does and does not prove: the gate is reached and holds in a real process. A process-level MUTANT of the gate is caught only when the round is fresh; if the victim
/// already proposed in that round, the SafetyStore's same-round rule (a conflicting message is refused) stops the proposal anyway, so the gate is not the only defense there.
/// The deterministic coverage of the gate itself is in-process. A stored-timeout re-send is NOT reachable this way and remains covered in-process only.
#[test]
fn live_v3_a_recovering_node_that_leads_its_round_is_asked_to_propose_refuses_and_signs_nothing() {
    let _serial = serial();
    let mut net = Net::new("l");
    for i in 0..N { net.start(i); }
    net.wait("all four execute height 48", 240, |n| n.heights().iter().all(|h| *h >= 48));
    let vd = net.dirs[VICTIM].clone();
    let wipe = |net: &mut Net, tag: &str| {
        net.crash(VICTIM);
        for sub in ["blocks", "app"] { let _ = std::fs::remove_dir_all(vd.join(sub)); }
        if vd.join("exec.log").exists() { std::fs::rename(vd.join("exec.log"), vd.join(format!("exec.log.{tag}"))).unwrap(); }
    };
    // first install: the victim becomes a seeded node that takes part in consensus (so it keeps signing)
    wipe(&mut net, "first");
    net.stage(VICTIM, 0, 1).expect("stage the first snapshot");
    net.start(VICTIM);
    net.wait("the victim recovers", 240, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) + 3 >= n.height(0)));
    let mut led = None;
    for cycle in 1..=24 {
        // let it sign for a varying moment, then kill it: its last signed round (hvr) depends on the moment
        std::thread::sleep(Duration::from_millis(300 + u64::from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos() % 700)));
        wipe(&mut net, &format!("c{cycle}"));
        // evidence ending 20 blocks before the donor's tip: old enough that (high QC round + 1) <= hvr, so the post-install round IS the victim's last signed round
        net.stage_lag(VICTIM, cycle % 3, 1, 20).expect("stage a snapshot");
        net.start(VICTIM);
        net.wait("the victim's first status", 60, |n| n.status(VICTIM).is_some());
        let first = net.status(VICTIM).unwrap();
        println!("  cycle {cycle}: is_leader={} round={} hvr={} high_qc_round={} recovering={}", first["is_leader"], first["round"], first["safety"]["hvr"], first["high_qc_round"], first["recovering"]);
        if first["is_leader"] == Value::Bool(true) && first["recovering"] == Value::Bool(true) { led = Some(cycle); break; }
        // not the leader: let it recover and take part again, so its last signed round moves on before the next try
        net.wait("the victim rejoins", 240, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) + 3 >= n.height(0)));
    }
    let cycle = led.expect("the victim led its post-install round in at least one of 24 kill states (each is roughly a one-in-four chance)");
    println!("  the victim led its post-install round in cycle {cycle}");
    net.wait("the gate is reached: the engine is asked to propose while recovering and refuses", 30, |n| {
        n.status(VICTIM).map_or(false, |s| u(&s["propose_refused_while_recovering"]) >= 1 && s["recovering"] == Value::Bool(true))
    });
    let s = net.status(VICTIM).unwrap();
    assert!(s["fatal"].is_null(), "the node did not stop: {}", s["fatal"]);
    assert_eq!(s["signed_while_recovering"], Value::Bool(false));
    assert_eq!(s["sent_signed_while_recovering"], Value::Bool(false));
    println!("  proposal attempts refused while recovering: {}; timeout attempts refused: {}", u(&s["propose_refused_while_recovering"]), u(&s["timeout_refused_while_recovering"]));
    net.wait("the victim recovers and catches up", 240, |n| n.status(VICTIM).map_or(false, |s| s["recovering"] == Value::Bool(false) && u(&s["exec"]["height"]) + 3 >= n.height(0)));
    for i in 0..N { assert!(net.alive(i), "node {i} stopped: {}", net.log_tail(i)); }
    net.assert_agreement("after the controlled-leader recovery");
}
