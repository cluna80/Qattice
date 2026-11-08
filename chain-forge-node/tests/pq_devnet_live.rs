//! LIVE four-node PQ-HotStuff-2 devnet (feature `pq-devnet`): four OS processes, real FIPS 204 ML-DSA-65 keys generated on this machine
//! (never committed), a fixed validator set, local TCP, the real signing-safety store with the NON-PRODUCTION file counter, persistent block
//! stores, and the DEVNET-INTERIM application. The application hash-chains opaque payloads: this proves proposal, certification, finalization,
//! the execution handoff, crash recovery and partition/rejoin. It is NOT transaction-execution validation (blocked on the payload codec, U5).
//!
//! Run: cargo test --release -p chain-forge-node --features pq-devnet --test pq_devnet_live -- --nocapture
#![cfg(feature = "pq-devnet")]
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_pq-devnet-node");
const N: usize = 4;

struct Net { dirs: Vec<PathBuf>, cfg: PathBuf, kids: Vec<Option<Child>>, root: PathBuf }

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

fn run_ok(args: &[&str]) {
    let o = Command::new(BIN).args(args).output().expect("spawn");
    assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

impl Net {
    fn new(tag: &str) -> Net {
        let root = std::env::temp_dir().join(format!("cf-pqdev-live-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dirs: Vec<PathBuf> = (0..N).map(|i| root.join(format!("n{i}"))).collect();
        for d in &dirs { run_ok(&["keygen", "--dir", d.to_str().unwrap()]); }
        let cfg = root.join("pq-devnet.json");
        let ports: Vec<String> = free_ports(N).iter().map(|p| p.to_string()).collect();
        let dirs_arg = dirs.iter().map(|d| d.to_str().unwrap().to_string()).collect::<Vec<_>>().join(",");
        run_ok(&["assemble", "--out", cfg.to_str().unwrap(), "--chain-id", "qattice-pqhs2-devnet-live", "--ports", &ports.join(","), "--dirs", &dirs_arg]);
        Net { dirs, cfg, kids: (0..N).map(|_| None).collect(), root }
    }
    fn start(&mut self, i: usize) {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(self.dirs[i].join("node.log")).unwrap();
        let child = Command::new(BIN).args(["run", "--config", self.cfg.to_str().unwrap(), "--dir", self.dirs[i].to_str().unwrap()])
            .stdout(Stdio::null()).stderr(log).spawn().expect("spawn node");
        self.kids[i] = Some(child);
    }
    fn crash(&mut self, i: usize) { if let Some(mut k) = self.kids[i].take() { let _ = k.kill(); let _ = k.wait(); } }
    fn alive(&mut self, i: usize) -> bool { self.kids[i].as_mut().map_or(false, |k| matches!(k.try_wait(), Ok(None))) }
    fn status(&self, i: usize) -> Option<Value> { serde_json::from_slice(&std::fs::read(self.dirs[i].join("status.json")).ok()?).ok() }
    fn height(&self, i: usize) -> u64 { self.status(i).and_then(|s| s["exec"]["height"].as_u64()).unwrap_or(0) }
    fn heights(&self) -> Vec<u64> { (0..N).map(|i| self.height(i)).collect() }
    fn partition(&self, i: usize, cut: &[usize]) { std::fs::write(self.dirs[i].join("partition.txt"), cut.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",")).unwrap(); }
    fn log_tail(&self, i: usize) -> String { std::fs::read_to_string(self.dirs[i].join("node.log")).map(|t| t.lines().rev().take(5).collect::<Vec<_>>().join(" | ")).unwrap_or_default() }

    fn wait(&mut self, what: &str, secs: u64, cond: impl Fn(&Net) -> bool) {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if cond(self) { println!("  [{:>5.1}s] {what}: heights {:?}", t.elapsed().as_secs_f32(), self.heights()); return; }
            std::thread::sleep(Duration::from_millis(200));
        }
        let logs: Vec<String> = (0..N).map(|i| format!("n{i}: {}", self.log_tail(i))).collect();
        panic!("timed out ({secs}s) waiting for: {what}; heights {:?}; {:?}", self.heights(), logs);
    }

    /// Every pair of nodes agrees on block id and application state digest at every height both still report.
    fn assert_agreement(&self, label: &str) {
        let mut by_h: std::collections::BTreeMap<u64, (String, String)> = Default::default();
        let mut compared = 0;
        for i in 0..N {
            let s = self.status(i).expect("status");
            assert!(s["fatal"].is_null(), "{label}: node {i} reported a fatal error: {}", s["fatal"]);
            for c in s["recent"].as_array().unwrap() {
                let (h, id, dg) = (c["height"].as_u64().unwrap(), c["block_id"].as_str().unwrap().to_string(), c["state_digest"].as_str().unwrap().to_string());
                if let Some(prev) = by_h.insert(h, (id.clone(), dg.clone())) { assert_eq!(prev, (id, dg), "{label}: DISAGREEMENT at height {h}"); compared += 1; }
            }
        }
        assert!(compared > 0, "{label}: no overlapping heights to compare");
        println!("  agreement ok ({label}): {compared} cross-node comparisons");
    }
}

#[test]
fn four_nodes_finalize_execute_recover_from_crashes_and_partitions_and_agree() {
    let mut net = Net::new("a");
    for i in 0..N { net.start(i); }

    // 1. proposal, certification, finalization, execution
    net.wait("all four execute height 6", 120, |n| n.heights().iter().all(|h| *h >= 6));
    net.assert_agreement("steady state");

    // 2. one node crashes (killed, no clean shutdown); three of four keep finalizing; it restarts from disk and rejoins
    let before_crash = net.height(2);
    net.crash(2);
    let others = (0..N).filter(|i| *i != 2).map(|i| net.height(i)).max().unwrap();
    net.wait("three nodes finalize 4 more blocks with one down", 120, |n| [0, 1, 3].iter().all(|i| n.height(*i) >= others + 4));
    net.start(2);
    net.wait("restarted node recovers and catches up", 120, |n| { let m = n.heights().into_iter().max().unwrap(); n.height(2) + 1 >= m && n.height(2) > before_crash });
    assert!(net.height(2) >= before_crash, "recovery never goes back");
    assert!(net.alive(2), "the restarted node must still be running (a duplicate execution or a safety refusal would have stopped it)");
    net.assert_agreement("after crash recovery");

    // 3. partition: node 3 is cut off from everyone (both directions); the majority keeps going; the partition heals and node 3 syncs
    for i in 0..N { net.partition(i, if i == 3 { &[0, 1, 2] } else { &[3] }); }
    std::thread::sleep(Duration::from_millis(800));
    let frozen = net.height(3);
    let ahead = (0..3).map(|i| net.height(i)).max().unwrap();
    net.wait("the majority finalizes 5 more blocks without node 3", 120, |n| (0..3).all(|i| n.height(i) >= ahead + 5));
    assert!(net.height(3) <= frozen + 1, "an isolated node must not advance (it was {frozen}, now {})", net.height(3));
    for i in 0..N { net.partition(i, &[]); }
    net.wait("the partitioned node rejoins and catches up", 120, |n| { let m = (0..3).map(|i| n.height(i)).max().unwrap(); n.height(3) + 1 >= m && n.height(3) > frozen + 3 });
    let s3 = net.status(3).unwrap();
    assert!(s3["sync_requests"].as_u64().unwrap() > 0, "the rejoining node must have used block sync");
    net.assert_agreement("after partition heal");

    // 4. every node stops and restarts together: committed history and application state survive and the chain continues
    let before_all = net.heights().into_iter().max().unwrap();
    for i in 0..N { net.crash(i); }
    for i in 0..N { net.start(i); }
    net.wait("the whole network resumes past its old height", 120, |n| n.heights().iter().all(|h| *h >= before_all + 3));
    for i in 0..N { assert!(net.alive(i), "node {i} stopped"); }
    net.assert_agreement("after full restart");
    println!("final heights {:?}", net.heights());
}
