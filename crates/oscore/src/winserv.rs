//! Pure window-server policy for Phase 2.2.
//!
//! The server itself runs as a guest (`guest/window_server.c`) and cannot
//! run under `cargo test`. This module is the host-testable half of its
//! policy: who owns which window, where a pointer event goes, and how
//! clients rendezvous through the well-known `/winserv` paths.
//!
//! Delivery stays deliberately thin. Every guest already shares the global
//! input queue (`INPUT_FD`), so routing an event means picking the owning
//! client and focusing its window (`WINDOW_FOCUS`); the client then reads
//! the event itself and ignores anything addressed to another window.

/// Maximum clients the server tracks, mirroring `guest/window_server.c`.
pub const MAX_CLIENTS: usize = 16;
/// Well-known directory clients register in.
pub const CLIENTS_DIR: &str = "/winserv/clients";
/// Well-known file the server writes its pid to for discovery.
pub const SERVER_PID_PATH: &str = "/winserv/server.pid";

/// Registration path for a client with process id `pid`.
pub fn client_path(pid: u32) -> String {
    format!("{CLIENTS_DIR}/{pid}")
}

/// Parses a registration file body (ASCII window id, optional newline).
pub fn parse_registration(body: &str) -> Option<u32> {
    body.trim().parse::<u32>().ok()
}

/// One registered client: a process and the window it owns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    /// Guest process id.
    pub pid: u32,
    /// Window id owned by this client.
    pub win_id: u32,
}

/// Registry of window-server clients.
#[derive(Clone, Debug, Default)]
pub struct ClientRegistry {
    clients: Vec<Client>,
}

impl ClientRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered clients.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Registers a client. Re-registering a pid moves it onto the new
    /// window (a client that recreates its window keeps its slot).
    /// Returns false when the table is full and the pid is new.
    pub fn register(&mut self, pid: u32, win_id: u32) -> bool {
        if let Some(c) = self.clients.iter_mut().find(|c| c.pid == pid) {
            c.win_id = win_id;
            return true;
        }
        if self.clients.len() >= MAX_CLIENTS {
            return false;
        }
        self.clients.push(Client { pid, win_id });
        true
    }

    /// Removes a client. Returns true when one was present.
    pub fn unregister(&mut self, pid: u32) -> bool {
        let n = self.clients.len();
        self.clients.retain(|c| c.pid != pid);
        self.clients.len() != n
    }

    /// Removes every client whose pid is not in `alive`. Returns how many
    /// were removed (crashed or reaped children).
    pub fn sweep(&mut self, alive: &[u32]) -> usize {
        let n = self.clients.len();
        self.clients.retain(|c| alive.contains(&c.pid));
        n - self.clients.len()
    }

    /// Index of the client owning `pid`, if registered.
    pub fn find(&self, pid: u32) -> Option<usize> {
        self.clients.iter().position(|c| c.pid == pid)
    }

    /// Index of the client owning window `win_id`, if registered.
    pub fn owner_of(&self, win_id: u32) -> Option<usize> {
        self.clients.iter().position(|c| c.win_id == win_id)
    }

    pub fn get(&self, idx: usize) -> Option<&Client> {
        self.clients.get(idx)
    }

    /// Routes a pointer event at `(x, y)` given the hit-test result.
    ///
    /// `hit` is the topmost window id from `Display::hit_test`
    /// (`SYS_DISPLAY_WINDOW_AT`), or `None` when the pointer is over no
    /// window. Returns the client index that should receive the event
    /// (and whose window the server should focus), or `None` to drop it.
    pub fn route(&self, hit: Option<u32>) -> Option<usize> {
        self.owner_of(hit?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_paths_and_bodies() {
        assert_eq!(client_path(42), "/winserv/clients/42");
        assert_eq!(parse_registration("7\n"), Some(7));
        assert_eq!(parse_registration("  12  "), Some(12));
        assert_eq!(parse_registration(""), None);
        assert_eq!(parse_registration("win"), None);
    }

    #[test]
    fn register_find_and_unregister() {
        let mut r = ClientRegistry::new();
        assert!(r.is_empty());
        assert!(r.register(10, 1));
        assert!(r.register(11, 2));
        assert_eq!(r.len(), 2);
        assert_eq!(r.find(10), Some(0));
        assert_eq!(r.owner_of(2), Some(1));
        assert_eq!(r.owner_of(99), None);
        // Re-registering a pid moves windows, not slots.
        assert!(r.register(10, 5));
        assert_eq!(r.len(), 2);
        assert_eq!(r.owner_of(5), Some(0));
        assert!(r.unregister(10));
        assert!(!r.unregister(10));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn table_is_bounded() {
        let mut r = ClientRegistry::new();
        for i in 0..MAX_CLIENTS as u32 {
            assert!(r.register(100 + i, i));
        }
        assert!(!r.register(999, 999), "a new pid past capacity is refused");
        // But an existing client can still move windows.
        assert!(r.register(100, 999));
    }

    #[test]
    fn sweep_removes_dead_clients() {
        let mut r = ClientRegistry::new();
        r.register(1, 1);
        r.register(2, 2);
        r.register(3, 3);
        assert_eq!(r.sweep(&[1, 3]), 1);
        assert_eq!(r.len(), 2);
        assert!(r.find(2).is_none());
    }

    #[test]
    fn route_delivers_hits_to_owners_and_drops_misses() {
        let mut r = ClientRegistry::new();
        r.register(10, 1);
        r.register(11, 2);
        assert_eq!(r.route(Some(2)), Some(1));
        assert_eq!(r.route(Some(99)), None, "unknown window is dropped");
        assert_eq!(r.route(None), None, "empty space is dropped");
    }
}
