//! Live four-node PQ-HotStuff-2 devnet with defensive pruning watermark (feature `pq-anchored-evidence`).
//! Runs the full node binary; verifies that the pruning watermark advances in status.json, that
//! blk-* payload files are deleted, and that a node restarted from a pruned store recovers correctly.
//!
//! Run:
//!   cargo test --release -p chain-forge-node --features pq-anchored-evidence \
//!     --test pq_pruning_devnet_live -- --nocapture
#![cfg(feature = "pq-anchored-evidence")]
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
        let root = std::env::temp_dir().join(format!("cf-pqdev-prune-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dirs: Vec<PathBuf> = (0..N).map(|i| root.join(format!("n{i}"))).collect();
        for d in &dirs { run_ok(&["keygen", "--dir", d.to_str().unwrap()]); }
        let cfg = root.join("pq-devnet.json");
        let ports: Vec<String> = free_ports(N).iter().map(|p| p.to_string()).collect();
        let dirs_arg = dirs.iter().map(|d| d.to_str().unwrap().to_string()).collect::<Vec<_>>().join(",");
        run_ok(&["assemble", "--out", cfg.to_str().unwrap(), "--chain-id", "qattice-pqhs2-pruning-live", "--ports", &ports.join(","), "--dirs", &dirs_arg]);
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

    fn pruned_watermark(&self, i: usize) -> u64 {
        self.status(i).and_then(|s| s["pruned_watermark"].as_u64()).unwrap_or(0)
    }

    fn blk_file_count(&self, i: usize) -> usize {
        std::fs::read_dir(self.dirs[i].join("blocks"))
            .map(|rd| rd.filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("blk-")).count())
            .unwrap_or(0)
    }

    fn log_tail(&self, i: usize) -> String {
        std::fs::read_to_string(self.dirs[i].join("node.log"))
            .map(|t| t.lines().rev().take(5).collect::<Vec<_>>().join(" | "))
            .unwrap_or_default()
    }

    fn wait(&mut self, what: &str, secs: u64, cond: impl Fn(&Net) -> bool) {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if cond(self) {
                println!("  [{:>5.1}s] {what}: heights {:?}", t.elapsed().as_secs_f32(), self.heights());
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let logs: Vec<String> = (0..N).map(|i| format!("n{i}: {}", self.log_tail(i))).collect();
        panic!("timed out ({secs}s) waiting for: {what}; heights {:?}; {:?}", self.heights(), logs);
    }
}

#[test]
fn pruning_watermark_advances_payloads_are_deleted_and_restart_recovers() {
    // PRUNE_KEEP = 64 in the node. We need committed_height > 64 to see pruning.
    // Run all four nodes until they reach height 80 so the watermark moves.
    let mut net = Net::new("prune");
    for i in 0..N { net.start(i); }

    // 1. All four nodes finalize past the pruning keep window (PRUNE_KEEP=64).
    net.wait("all four execute height 70", 180, |n| n.heights().iter().all(|h| *h >= 70));
    println!("  heights after steady state: {:?}", net.heights());

    // 2. The pruning watermark must have advanced on at least one node.
    let mut any_pruned = false;
    let mut watermarks = vec![0u64; N];
    for i in 0..N {
        watermarks[i] = net.pruned_watermark(i);
        if watermarks[i] > 0 { any_pruned = true; }
    }
    println!("  pruned_watermark per node: {:?}", watermarks);
    assert!(any_pruned, "at least one node must have advanced its pruning watermark past 0 (heights {:?})", net.heights());

    // 3. The blk-* file count must be below the total committed count (some payloads deleted).
    let heights = net.heights();
    for i in 0..N {
        if watermarks[i] > 0 {
            let blk_count = net.blk_file_count(i);
            // blocks store files for all heights (committed + speculative); committed alone = heights[i]
            // After pruning below watermark, blk files at h < watermark are gone.
            println!("  node {i}: height={}, watermark={}, blk-* files={}", heights[i], watermarks[i], blk_count);
            assert!(blk_count < heights[i] as usize,
                "node {i}: blk-* file count ({blk_count}) must be less than committed height ({}) after pruning",
                heights[i]);
        }
    }

    // 4. Crash one node; let the others advance a little; restart; verify it recovers past its last height.
    let victim = 2;
    let before_crash = net.height(victim);
    net.crash(victim);
    let others_ahead = (0..N).filter(|i| *i != victim).map(|i| net.height(i)).max().unwrap();
    net.wait("three nodes finalize 4 more after crash", 60, |n| {
        [0usize, 1, 3].iter().all(|i| n.height(*i) >= others_ahead + 4)
    });
    net.start(victim);
    net.wait("restarted node recovers past its last height", 120, |n| {
        let m = n.heights().into_iter().max().unwrap();
        n.height(victim) + 1 >= m && n.height(victim) > before_crash
    });
    assert!(net.alive(victim), "restarted node must still be running (no duplicate execution or safety violation)");

    // 5. Verify no fatal error on any node.
    for i in 0..N {
        if let Some(s) = net.status(i) {
            assert!(s["fatal"].is_null(), "node {i} reported a fatal: {}", s["fatal"]);
        }
    }

    println!("final heights {:?}; watermarks {:?}", net.heights(), (0..N).map(|i| net.pruned_watermark(i)).collect::<Vec<_>>());
}
