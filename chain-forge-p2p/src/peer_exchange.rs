//! Peer exchange: every node learns the listen addresses of the peers it is
//! connected to (from libp2p identify), shares them with its peers, and dials
//! the ones it is not connected to. Without this a node only knows its
//! `--bootstrap` addresses, the network forms a star around the bootstrap node,
//! and losing that one node partitions every other validator.
//!
//! Addresses are dialled without a peer id: a node gets a fresh libp2p identity
//! on every start, so a restarted validator is found again at its usual address.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Most entries one announcement may carry, and most peers remembered.
pub const MAX_ENTRIES: usize = 64;
/// Most addresses kept per peer.
pub const MAX_ADDRS_PER_PEER: usize = 8;
/// An address is not redialled more often than this.
pub const REDIAL_EVERY: Duration = Duration::from_secs(10);

/// One peer and the addresses it listens on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

/// Gossiped list of peers the sender is connected to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    pub peers: Vec<PeerEntry>,
}

#[derive(Default)]
pub struct PeerExchange {
    known: HashMap<String, Vec<String>>,
    last_dial: HashMap<String, Instant>,
}

/// A dialable listen address: TCP on a concrete IP, without a `/p2p/` suffix.
fn usable(addr: &str) -> Option<String> {
    let a = addr.split("/p2p/").next().unwrap_or(addr).trim_end_matches('/').to_string();
    let concrete = (a.starts_with("/ip4/") && !a.starts_with("/ip4/0.0.0.0/"))
        || (a.starts_with("/ip6/") && !a.starts_with("/ip6/::/"));
    (concrete && a.contains("/tcp/")).then_some(a)
}

impl PeerExchange {
    pub fn new() -> Self { Self::default() }

    /// Record the listen addresses `peer` reported about itself (identify).
    pub fn record(&mut self, peer: &str, addrs: impl IntoIterator<Item = String>) {
        let mut list: Vec<String> = addrs.into_iter().filter_map(|a| usable(&a)).collect();
        list.sort();
        list.dedup();
        list.truncate(MAX_ADDRS_PER_PEER);
        if list.is_empty() {
            return;
        }
        if !self.known.contains_key(peer) && self.known.len() >= MAX_ENTRIES {
            return;
        }
        self.known.insert(peer.to_string(), list);
    }

    /// Merge an announcement from a peer, ignoring this node's own entries.
    pub fn merge(&mut self, ann: &Announcement, self_id: &str, own_addrs: &HashSet<String>) {
        for e in ann.peers.iter().take(MAX_ENTRIES) {
            if e.peer_id == self_id {
                continue;
            }
            let addrs: Vec<String> = e.addrs.iter()
                .filter_map(|a| usable(a))
                .filter(|a| !own_addrs.contains(a))
                .collect();
            self.record(&e.peer_id, addrs);
        }
    }

    /// What this node announces: the connected peers whose addresses it knows.
    pub fn announcement(&self, connected: &HashSet<String>) -> Announcement {
        let mut peers: Vec<PeerEntry> = self.known.iter()
            .filter(|(p, _)| connected.contains(*p))
            .map(|(p, a)| PeerEntry { peer_id: p.clone(), addrs: a.clone() })
            .collect();
        peers.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        peers.truncate(MAX_ENTRIES);
        Announcement { peers }
    }

    /// Addresses to dial now: known addresses of peers that are not connected,
    /// that no connected peer is listening on, not this node's own, and not
    /// dialled within `REDIAL_EVERY`.
    pub fn due_dials(&mut self, connected: &HashSet<String>, own_addrs: &HashSet<String>, now: Instant) -> Vec<String> {
        let in_use: HashSet<&String> = self.known.iter()
            .filter(|(p, _)| connected.contains(*p))
            .flat_map(|(_, a)| a.iter())
            .collect();
        let mut out = vec![];
        for (peer, addrs) in &self.known {
            if connected.contains(peer) {
                continue;
            }
            for a in addrs {
                if in_use.contains(a) || own_addrs.contains(a) {
                    continue;
                }
                if self.last_dial.get(a).is_some_and(|t| now.duration_since(*t) < REDIAL_EVERY) {
                    continue;
                }
                out.push(a.clone());
            }
        }
        out.sort();
        out.dedup();
        for a in &out {
            self.last_dial.insert(a.clone(), now);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[&str]) -> HashSet<String> { v.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn leaves_of_a_star_learn_each_other_through_the_hub() {
        // The hub (alice) is connected to bob and carol and knows their addresses.
        let mut hub = PeerExchange::new();
        hub.record("bob", vec!["/ip4/127.0.0.1/tcp/2001".into()]);
        hub.record("carol", vec!["/ip4/127.0.0.1/tcp/2002".into()]);
        let ann = hub.announcement(&set(&["bob", "carol"]));

        // Bob only knows the hub; after the hub's announcement he dials carol.
        let mut bob = PeerExchange::new();
        bob.merge(&ann, "bob", &set(&["/ip4/127.0.0.1/tcp/2001"]));
        let dials = bob.due_dials(&set(&["alice"]), &set(&["/ip4/127.0.0.1/tcp/2001"]), Instant::now());
        assert_eq!(dials, vec!["/ip4/127.0.0.1/tcp/2002".to_string()]);
    }

    #[test]
    fn redials_are_rate_limited_and_skip_connected_addresses() {
        let mut px = PeerExchange::new();
        px.record("carol", vec!["/ip4/127.0.0.1/tcp/2002".into()]);
        let t0 = Instant::now();
        assert_eq!(px.due_dials(&set(&[]), &set(&[]), t0).len(), 1);
        assert!(px.due_dials(&set(&[]), &set(&[]), t0 + Duration::from_secs(1)).is_empty(), "too soon");
        assert_eq!(px.due_dials(&set(&[]), &set(&[]), t0 + REDIAL_EVERY).len(), 1);
        // A restarted carol (new peer id) is connected at the same address: stop dialling the old id's address.
        px.record("carol-new", vec!["/ip4/127.0.0.1/tcp/2002".into()]);
        assert!(px.due_dials(&set(&["carol-new"]), &set(&[]), t0 + REDIAL_EVERY * 3).is_empty());
    }

    #[test]
    fn unusable_addresses_and_oversized_input_are_dropped() {
        let mut px = PeerExchange::new();
        px.record("x", vec!["/ip4/0.0.0.0/tcp/1".into(), "/ip4/1.2.3.4/udp/1".into()]);
        assert!(px.announcement(&set(&["x"])).peers.is_empty());
        px.record("y", vec!["/ip4/1.2.3.4/tcp/9/p2p/12D3Koo".into()]);
        assert_eq!(px.announcement(&set(&["y"])).peers[0].addrs, vec!["/ip4/1.2.3.4/tcp/9".to_string()]);
        for i in 0..200 { px.record(&format!("p{i}"), vec![format!("/ip4/10.0.0.1/tcp/{i}")]); }
        assert!(px.known.len() <= MAX_ENTRIES);
    }
}
