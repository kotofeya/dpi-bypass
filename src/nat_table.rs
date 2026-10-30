//! Stateful NAT for the transparent Telegram redirect (Engine A <-> Engine B).
//!
//! WinDivert "reflects" an outbound flow  L:cport -> T:dport  into an inbound flow
//! T:cport -> L:BRIDGE, so the bridge's `accept()` sees the original Telegram address as the
//! peer IP. What is lost is the original destination port, and the reply direction
//! L:BRIDGE -> T:cport has to be turned back into T:dport -> L:cport. Both lookups are keyed by
//! (Telegram IP, client port), which is unique per redirected flow.
//!
//! Lookups run on the packet path for every segment, so entries are read-mostly: the map is a
//! sharded `DashMap` and all per-flow mutable state lives in atomics (no write lock per packet).
//!
//! The table also tracks "bypass" ports: sockets that Engine B / Engine C open themselves
//! (WebSocket gateways, direct fallbacks) bind first and register their local port, so their SYN
//! towards a Telegram address is not reflected back into the bridge.

use dashmap::DashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    /// the Telegram server address the client originally dialed
    pub remote: Ipv4Addr,
    /// the client's local (ephemeral) port
    pub client_port: u16,
}

/// client sent FIN
pub const CLIENT_FIN: u8 = 1;
/// bridge sent FIN
pub const BRIDGE_FIN: u8 = 2;
/// either side sent RST
pub const RESET: u8 = 4;
/// at least one non-SYN segment went through
pub const ESTABLISHED: u8 = 8;

pub struct Entry {
    /// the client's own (NIC) address
    pub local: Ipv4Addr,
    /// original destination port (443 / 80 / 5222)
    pub orig_port: u16,
    last_seen_ms: AtomicU64,
    state: AtomicU8,
}

impl Entry {
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::Relaxed)
    }
}

/// Timeouts for garbage collection.
const SYN_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const CLOSED_LINGER: Duration = Duration::from_secs(10);

pub struct NatTable {
    epoch: Instant,
    flows: DashMap<FlowKey, Arc<Entry>>,
    /// local port -> number of live guards
    bypass: DashMap<u16, u32>,
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NatTable {
    pub fn new() -> Self {
        Self { epoch: Instant::now(), flows: DashMap::new(), bypass: DashMap::new() }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Client SYN: create (or recycle, on port reuse) the mapping.
    pub fn on_syn(&self, key: FlowKey, local: Ipv4Addr, orig_port: u16) -> Arc<Entry> {
        let now = self.now_ms();
        let mut slot = self.flows.entry(key).or_insert_with(|| {
            Arc::new(Entry { local, orig_port, last_seen_ms: AtomicU64::new(now), state: AtomicU8::new(0) })
        });
        let e = slot.value();
        if e.local != local || e.orig_port != orig_port || e.state() & (RESET | CLIENT_FIN | BRIDGE_FIN) != 0 {
            *slot = Arc::new(Entry { local, orig_port, last_seen_ms: AtomicU64::new(now), state: AtomicU8::new(0) });
        } else {
            e.last_seen_ms.store(now, Ordering::Relaxed);
        }
        slot.value().clone()
    }

    /// Packet-path lookup; refreshes the idle timer.
    pub fn lookup(&self, key: &FlowKey) -> Option<Arc<Entry>> {
        let e = self.flows.get(key)?.value().clone();
        e.last_seen_ms.store(self.now_ms(), Ordering::Relaxed);
        Some(e)
    }

    pub fn mark(&self, e: &Entry, flags: u8) {
        e.state.fetch_or(flags, Ordering::Relaxed);
    }

    pub fn remove(&self, key: &FlowKey) {
        self.flows.remove(key);
    }

    /// For the bridge: the original destination of an accepted (reflected) connection.
    pub fn original_dst(&self, peer: SocketAddrV4) -> Option<SocketAddrV4> {
        let key = FlowKey { remote: *peer.ip(), client_port: peer.port() };
        self.lookup(&key).map(|e| SocketAddrV4::new(*peer.ip(), e.orig_port))
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Drops half-open, idle and closed flows. Returns how many were removed.
    pub fn gc(&self) -> usize {
        let now = self.now_ms();
        let before = self.flows.len();
        self.flows.retain(|_, e| {
            let idle = Duration::from_millis(now.saturating_sub(e.last_seen_ms.load(Ordering::Relaxed)));
            let st = e.state();
            if st & RESET != 0 || st & (CLIENT_FIN | BRIDGE_FIN) == (CLIENT_FIN | BRIDGE_FIN) {
                idle < CLOSED_LINGER
            } else if st & ESTABLISHED == 0 {
                idle < SYN_TIMEOUT
            } else {
                idle < IDLE_TIMEOUT
            }
        });
        before.saturating_sub(self.flows.len())
    }

    // ------------------------------------------------------------ bypass ports

    /// Registers `port` as one of our own sockets until the guard is dropped.
    pub fn bypass(self: &Arc<Self>, port: u16) -> BypassGuard {
        *self.bypass.entry(port).or_insert(0) += 1;
        BypassGuard { table: self.clone(), port }
    }

    pub fn is_bypassed(&self, port: u16) -> bool {
        self.bypass.contains_key(&port)
    }

    fn release(&self, port: u16) {
        self.bypass.remove_if_mut(&port, |_, n| {
            *n -= 1;
            *n == 0
        });
    }
}

pub struct BypassGuard {
    table: Arc<NatTable>,
    port: u16,
}

impl Drop for BypassGuard {
    fn drop(&mut self) {
        self.table.release(self.port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(p: u16) -> FlowKey {
        FlowKey { remote: Ipv4Addr::new(149, 154, 167, 51), client_port: p }
    }

    #[test]
    fn syn_lookup_and_original_dst() {
        let t = NatTable::new();
        let local = Ipv4Addr::new(192, 168, 1, 10);
        t.on_syn(key(50000), local, 443);
        let e = t.lookup(&key(50000)).unwrap();
        assert_eq!(e.local, local);
        assert_eq!(e.orig_port, 443);
        let peer = SocketAddrV4::new(Ipv4Addr::new(149, 154, 167, 51), 50000);
        assert_eq!(t.original_dst(peer), Some(SocketAddrV4::new(*peer.ip(), 443)));
        assert!(t.lookup(&key(50001)).is_none());
    }

    #[test]
    fn port_reuse_resets_state() {
        let t = NatTable::new();
        let local = Ipv4Addr::new(10, 0, 0, 2);
        let e = t.on_syn(key(1), local, 443);
        t.mark(&e, RESET);
        let e2 = t.on_syn(key(1), local, 5222);
        assert_eq!(e2.orig_port, 5222);
        assert_eq!(e2.state(), 0);
    }

    #[test]
    fn gc_keeps_live_flows() {
        let t = NatTable::new();
        let e = t.on_syn(key(2), Ipv4Addr::LOCALHOST, 443);
        t.mark(&e, ESTABLISHED);
        assert_eq!(t.gc(), 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn bypass_guards_refcount() {
        let t = Arc::new(NatTable::new());
        let a = t.bypass(40000);
        let b = t.bypass(40000);
        assert!(t.is_bypassed(40000));
        drop(a);
        assert!(t.is_bypassed(40000));
        drop(b);
        assert!(!t.is_bypassed(40000));
    }
}
