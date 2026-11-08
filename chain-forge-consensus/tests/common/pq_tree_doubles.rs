// Test double for the directory-tree filesystem (recovery::tree::TreeFs) with a crash model.
//   * file CONTENT is durable only after sync_file; an unsynced file may survive a crash empty or torn;
//   * directory ENTRIES (a creation, rename or removal of a child) are durable only after sync_dir of the parent (both parents for a rename);
//   * an unsynced entry effect may or may not have happened, but never before an earlier effect on a related path it depends on.
// crash_outcomes() SAMPLES the state space (none, all, every prefix, every single omission, and a number of pseudo-random subsets, each with the
// unsynced files whole / empty / half): it is not exhaustive and is documented as such.
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use chain_forge_consensus::pq_hotstuff::recovery::tree::{check_path, parent_of, FsError, TreeFs};

#[derive(Default, Debug)]
pub struct TFaults {
    pub ops: usize,
    /// the process dies before mutating operation number N: it and every later one fail without effect
    pub crash_before: Option<usize>,
    /// sync_file / sync_dir of exactly these paths fail with an I/O error (no crash)
    pub fail_sync: BTreeSet<String>,
}
pub type TShared = Rc<RefCell<TFaults>>;
pub fn tfaults() -> TShared { Rc::new(RefCell::new(TFaults::default())) }

#[derive(Clone, Debug)]
enum Ent { Dir, File(usize) }
#[derive(Clone, Debug)]
struct Inode { data: Vec<u8>, synced: bool }
#[derive(Clone, Debug)]
enum Eff { Create { path: String, ent: Ent }, Rename { from: String, to: String }, Remove { path: String } }
#[derive(Clone, Debug)]
struct Pending { eff: Eff, need: BTreeSet<String> }

fn related(a: &str, b: &str) -> bool { a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/")) }
fn paths_of(e: &Eff) -> Vec<&str> { match e { Eff::Create { path, .. } | Eff::Remove { path } => vec![path], Eff::Rename { from, to } => vec![from, to] } }
fn conflicts(a: &Eff, b: &Eff) -> bool { paths_of(a).iter().any(|x| paths_of(b).iter().any(|y| related(x, y))) }

#[derive(Clone)]
pub struct MemTreeFs {
    vol: BTreeMap<String, Ent>,
    dur: BTreeMap<String, Ent>,
    inodes: Vec<Inode>,
    pending: Vec<Pending>,
    pub faults: TShared,
    pub devices_differ: bool,
}

fn apply(ns: &mut BTreeMap<String, Ent>, e: &Eff) -> bool {
    let parent_ok = |ns: &BTreeMap<String, Ent>, p: &str| { let par = parent_of(p); par.is_empty() || matches!(ns.get(par), Some(Ent::Dir)) };
    match e {
        Eff::Create { path, ent } => { if ns.contains_key(path) || !parent_ok(ns, path) { return false; } ns.insert(path.clone(), ent.clone()); true }
        Eff::Remove { path } => { let pre = format!("{path}/"); ns.retain(|k, _| k != path && !k.starts_with(&pre)); true }
        Eff::Rename { from, to } => {
            let Some(src) = ns.get(from).cloned() else { return false };
            if !parent_ok(ns, to) { return false; }
            if matches!(src, Ent::Dir) && ns.contains_key(to) { return false; }
            if let Some(Ent::Dir) = ns.get(to) { return false; }
            ns.remove(to);
            let pre = format!("{from}/");
            let moved: Vec<(String, Ent)> = ns.iter().filter(|(k, _)| k.as_str() == from || k.starts_with(&pre)).map(|(k, v)| (k.clone(), v.clone())).collect();
            for (k, _) in &moved { ns.remove(k); }
            for (k, v) in moved { ns.insert(format!("{to}{}", &k[from.len()..]), v); }
            true
        }
    }
}

impl MemTreeFs {
    pub fn new(faults: TShared) -> Self { MemTreeFs { vol: BTreeMap::new(), dur: BTreeMap::new(), inodes: vec![], pending: vec![], faults, devices_differ: false } }

    fn tick(&self) -> Result<(), FsError> {
        let mut f = self.faults.borrow_mut();
        let i = f.ops;
        if let Some(c) = f.crash_before { if i >= c { return Err(FsError(format!("crashed before operation {i}"))); } }
        f.ops += 1;
        Ok(())
    }
    fn dir_ok(&self, d: &str) -> bool { d.is_empty() || matches!(self.vol.get(d), Some(Ent::Dir)) }
    fn settle(&mut self) {
        loop {
            let mut progressed = false;
            for i in 0..self.pending.len() {
                if !self.pending[i].need.is_empty() { continue; }
                if (0..i).any(|j| conflicts(&self.pending[j].eff, &self.pending[i].eff)) { continue; }
                let mut trial = self.dur.clone();
                if apply(&mut trial, &self.pending[i].eff) { self.dur = trial; self.pending.remove(i); progressed = true; break; }
            }
            if !progressed { break; }
        }
    }
    /// Everything visible to the running process: path -> file bytes (None for a directory).
    pub fn snapshot(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        self.vol.iter().map(|(k, v)| (k.clone(), match v { Ent::Dir => None, Ent::File(i) => Some(self.inodes[*i].data.clone()) })).collect()
    }
    /// Plain-text view of the files (path -> bytes) under a prefix.
    pub fn files_under(&self, prefix: &str) -> BTreeMap<String, Vec<u8>> {
        let pre = format!("{prefix}/");
        self.snapshot().into_iter().filter_map(|(k, v)| v.filter(|_| k.starts_with(&pre)).map(|d| (k, d))).collect()
    }
    pub fn raw(&self, path: &str) -> Option<Vec<u8>> { TreeFs::read(self, path).ok().flatten() }
    /// Overwrite (or create) a file directly in the volatile AND durable view, bypassing fault injection (for tests that damage records on purpose).
    pub fn set_raw(&mut self, path: &str, data: Vec<u8>) {
        let ino = self.inodes.len();
        self.inodes.push(Inode { data, synced: true });
        self.vol.insert(path.to_string(), Ent::File(ino));
        self.dur.insert(path.to_string(), Ent::File(ino));
    }
    pub fn delete_raw(&mut self, path: &str) { let pre = format!("{path}/"); self.vol.retain(|k, _| k != path && !k.starts_with(&pre)); self.dur.retain(|k, _| k != path && !k.starts_with(&pre)); }

    pub fn crash_outcomes(&self, samples: usize) -> Vec<MemTreeFs> {
        let m = self.pending.len();
        let mut masks: Vec<Vec<bool>> = vec![vec![false; m], vec![true; m]];
        for k in 1..m { masks.push((0..m).map(|i| i < k).collect()); }
        for k in 0..m { masks.push((0..m).map(|i| i != k).collect()); }
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ (m as u64).wrapping_mul(0x1000_0000_01B3);
        for _ in 0..samples { masks.push((0..m).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x & 1 == 1 }).collect()); }
        let mut seen: BTreeSet<Vec<(String, Option<Vec<u8>>)>> = BTreeSet::new();
        let mut out = vec![];
        for mask in masks {
            let mut ns = self.dur.clone();
            let mut applied = vec![false; m];
            for i in 0..m {
                if !mask[i] { continue; }
                if (0..i).any(|j| !applied[j] && conflicts(&self.pending[j].eff, &self.pending[i].eff)) { continue; }
                let mut trial = ns.clone();
                if apply(&mut trial, &self.pending[i].eff) { ns = trial; applied[i] = true; }
            }
            for variant in 0..3 {
                let mut vol = BTreeMap::new();
                let mut inodes = vec![];
                let mut key = vec![];
                for (k, e) in &ns {
                    match e {
                        Ent::Dir => { vol.insert(k.clone(), Ent::Dir); key.push((k.clone(), None)); }
                        Ent::File(i) => {
                            let ino = &self.inodes[*i];
                            let data = if ino.synced || variant == 0 { ino.data.clone() } else if variant == 1 { vec![] } else { ino.data[..ino.data.len() / 2].to_vec() };
                            key.push((k.clone(), Some(data.clone())));
                            inodes.push(Inode { data, synced: true });
                            vol.insert(k.clone(), Ent::File(inodes.len() - 1));
                        }
                    }
                }
                if seen.insert(key) { out.push(MemTreeFs { dur: vol.clone(), vol, inodes, pending: vec![], faults: tfaults(), devices_differ: self.devices_differ }); }
            }
        }
        out
    }
}

impl TreeFs for MemTreeFs {
    fn mkdir_all(&mut self, path: &str) -> Result<(), FsError> {
        check_path(path)?; self.tick()?;
        let mut cur = String::new();
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if !cur.is_empty() { cur.push('/'); }
            cur.push_str(comp);
            match self.vol.get(&cur) {
                Some(Ent::Dir) => {}
                Some(Ent::File(_)) => return Err(FsError(format!("{cur} is a file"))),
                None => { self.vol.insert(cur.clone(), Ent::Dir); let need = [parent_of(&cur).to_string()].into_iter().collect(); self.pending.push(Pending { eff: Eff::Create { path: cur.clone(), ent: Ent::Dir }, need }); }
            }
        }
        Ok(())
    }
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), FsError> {
        check_path(path)?; self.tick()?;
        if path.is_empty() || self.vol.contains_key(path) { return Err(FsError(format!("{path} exists"))); }
        if !self.dir_ok(parent_of(path)) { return Err(FsError(format!("no directory {}", parent_of(path)))); }
        let ino = self.inodes.len();
        self.inodes.push(Inode { data: data.to_vec(), synced: false });
        self.vol.insert(path.to_string(), Ent::File(ino));
        let need = [parent_of(path).to_string()].into_iter().collect();
        self.pending.push(Pending { eff: Eff::Create { path: path.to_string(), ent: Ent::File(ino) }, need });
        Ok(())
    }
    fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
        check_path(path)?; self.tick()?;
        if self.faults.borrow().fail_sync.contains(path) { return Err(FsError(format!("injected I/O error syncing {path}"))); }
        match self.vol.get(path) { Some(Ent::File(i)) => { let i = *i; self.inodes[i].synced = true; Ok(()) } _ => Err(FsError(format!("no file {path}"))) }
    }
    fn sync_dir(&mut self, dir: &str) -> Result<(), FsError> {
        check_path(dir)?; self.tick()?;
        if self.faults.borrow().fail_sync.contains(dir) { return Err(FsError(format!("injected I/O error syncing {dir:?}"))); }
        if !self.dir_ok(dir) { return Err(FsError(format!("no directory {dir}"))); }
        for p in &mut self.pending { p.need.remove(dir); }
        self.settle();
        Ok(())
    }
    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        check_path(from)?; check_path(to)?; self.tick()?;
        let is_dir = match self.vol.get(from) { Some(Ent::Dir) => true, Some(Ent::File(_)) => false, None => return Err(FsError(format!("no {from}"))) };
        if !self.dir_ok(parent_of(to)) { return Err(FsError(format!("no directory {}", parent_of(to)))); }
        if is_dir && self.vol.contains_key(to) { return Err(FsError(format!("{to} exists"))); }
        if matches!(self.vol.get(to), Some(Ent::Dir)) { return Err(FsError(format!("{to} is a directory"))); }
        let eff = Eff::Rename { from: from.to_string(), to: to.to_string() };
        apply(&mut self.vol, &eff);
        let need = [parent_of(from).to_string(), parent_of(to).to_string()].into_iter().collect();
        self.pending.push(Pending { eff, need });
        Ok(())
    }
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, FsError> {
        check_path(path)?;
        Ok(match self.vol.get(path) { Some(Ent::File(i)) => Some(self.inodes[*i].data.clone()), _ => None })
    }
    fn list(&self, dir: &str) -> Result<Vec<String>, FsError> {
        check_path(dir)?;
        Ok(self.vol.keys().filter(|k| parent_of(k) == dir).map(|k| k.rsplit('/').next().unwrap().to_string()).collect())
    }
    fn is_dir(&self, path: &str) -> bool { path.is_empty() || matches!(self.vol.get(path), Some(Ent::Dir)) }
    fn exists(&self, path: &str) -> bool { path.is_empty() || self.vol.contains_key(path) }
    fn remove_all(&mut self, path: &str) -> Result<(), FsError> {
        check_path(path)?; self.tick()?;
        if !self.vol.contains_key(path) { return Ok(()); }
        let eff = Eff::Remove { path: path.to_string() };
        apply(&mut self.vol, &eff);
        let need = [parent_of(path).to_string()].into_iter().collect();
        self.pending.push(Pending { eff, need });
        Ok(())
    }
    fn same_device(&self, _: &str, _: &str) -> bool { !self.devices_differ }
}
