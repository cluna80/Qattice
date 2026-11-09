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

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_pq-devnet-node");
const N: usize = 4;
const VICTIM: usize = 3;
const K: u64 = 4;

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
    /// Operator-staged OFFLINE snapshot from `donor` into the (stopped) `target`, retried while the donor's files are mid-write. Returns (height, block id hex, root hex).
    fn stage(&self, target: usize, donor: usize, back: usize) -> Result<(u64, String, String), String> {
        let mut last = String::new();
        for _ in 0..20 {
            let o = Command::new(BIN).args(["stage-snapshot", "--config", self.cfg.to_str().unwrap(), "--donor", self.dirs[donor].to_str().unwrap(), "--dir", self.dirs[target].to_str().unwrap(), "--back", &back.to_string()]).output().unwrap();
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
    let stale = net.stage(VICTIM, 0, 3);
    assert!(matches!(&stale, Err(m) if m.contains("stale")), "an older checkpoint is refused: {stale:?}");
    assert_eq!(std::fs::read(vd.join("app").join("app-state")).unwrap(), app_b, "and the stale attempt did not touch the application state");
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
