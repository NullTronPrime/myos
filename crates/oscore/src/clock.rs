//! A guest clock: a monotonic base plus a wall-clock offset.
//!
//! Time has to be readable without a host, so this is a pure value the platform
//! layer refreshes from a real clock before each trap. Everything a syscall can
//! ask about time resolves here.

/// `CLOCK_REALTIME`.
pub const CLOCK_REALTIME: i64 = 0;
/// `CLOCK_MONOTONIC`.
pub const CLOCK_MONOTONIC: i64 = 1;
/// `CLOCK_PROCESS_CPUTIME_ID`.
pub const CLOCK_PROCESS_CPUTIME_ID: i64 = 2;
/// `CLOCK_THREAD_CPUTIME_ID`.
pub const CLOCK_THREAD_CPUTIME_ID: i64 = 3;
/// `CLOCK_MONOTONIC_RAW`.
pub const CLOCK_MONOTONIC_RAW: i64 = 4;
/// `CLOCK_REALTIME_COARSE`.
pub const CLOCK_REALTIME_COARSE: i64 = 5;
/// `CLOCK_BOOTTIME`.
pub const CLOCK_BOOTTIME: i64 = 7;

/// Nanoseconds in a second.
pub const NANOS_PER_SEC: i64 = 1_000_000_000;
/// Resolution reported for every clock: one nanosecond.
pub const CLOCK_RESOLUTION_NS: i64 = 1;

/// A Linux-style `struct timespec`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

impl Timespec {
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Timespec { sec, nsec }
    }

    pub fn zero() -> Self {
        Timespec::new(0, 0)
    }

    pub fn to_nanos(self) -> i64 {
        self.sec
            .saturating_mul(NANOS_PER_SEC)
            .saturating_add(self.nsec)
    }

    pub fn from_nanos(nanos: i64) -> Self {
        Timespec {
            sec: nanos.div_euclid(NANOS_PER_SEC),
            nsec: nanos.rem_euclid(NANOS_PER_SEC),
        }
    }

    /// Little-endian bytes, as the kernel writes a `timespec` into guest memory.
    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.sec.to_le_bytes());
        out[8..16].copy_from_slice(&self.nsec.to_le_bytes());
        out
    }

    /// Parses a guest `timespec`, rejecting non-normalised and negative fields.
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let sec = i64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let nsec = i64::from_le_bytes(bytes[8..16].try_into().ok()?);
        if sec < 0 || nsec < 0 || nsec >= NANOS_PER_SEC {
            return None;
        }
        Some(Timespec { sec, nsec })
    }

    pub fn is_valid(&self) -> bool {
        self.sec >= 0 && self.nsec >= 0 && self.nsec < NANOS_PER_SEC
    }
}

/// A Linux-style `struct timeval`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Timeval {
    pub sec: i64,
    pub usec: i64,
}

impl Timeval {
    pub fn from_timespec(ts: Timespec) -> Self {
        Timeval {
            sec: ts.sec,
            usec: ts.nsec / 1_000,
        }
    }

    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.sec.to_le_bytes());
        out[8..16].copy_from_slice(&self.usec.to_le_bytes());
        out
    }
}

/// Monotonic nanoseconds since boot, and the wall-clock time the OS started.
///
/// The monotonic base is stored as an `Instant`-style duration since first read,
/// so a guest can never see time run backwards. Realtime is derived from it by
/// adding a fixed offset captured when the OS booted.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    /// Wall-clock nanoseconds at boot, from the host.
    boot_wall_ns: i64,
    /// Monotonic nanoseconds when the OS booted.
    boot_mono_ns: i64,
    /// Latest monotonic reading, refreshed by the platform each trap.
    mono_ns: i64,
}

impl Default for Clock {
    fn default() -> Self {
        // The epoch is a valid wall clock: a guest that only wants a
        // non-decreasing sequence still gets one, and realtime starts at 1970
        // rather than at some arbitrary large value.
        Clock {
            boot_wall_ns: 0,
            boot_mono_ns: 0,
            mono_ns: 0,
        }
    }
}

impl Clock {
    /// Builds a clock from host readings taken at boot.
    pub fn new(boot_wall_ns: i64, boot_mono_ns: i64) -> Self {
        Clock {
            boot_wall_ns,
            boot_mono_ns,
            mono_ns: boot_mono_ns,
        }
    }

    /// Records a fresh monotonic reading. Called by the platform before each trap.
    pub fn advance_to(&mut self, mono_ns: i64) {
        // Monotonic time never goes backwards, even if the host's clock does.
        if mono_ns > self.mono_ns {
            self.mono_ns = mono_ns;
        }
    }

    /// Advances by a relative amount, used by tests and by `nanosleep`.
    pub fn advance(&mut self, delta_ns: i64) {
        self.advance_to(self.mono_ns.saturating_add(delta_ns));
    }

    pub fn monotonic_ns(&self) -> i64 {
        self.mono_ns
    }

    pub fn realtime_ns(&self) -> i64 {
        self.boot_wall_ns + (self.mono_ns - self.boot_mono_ns)
    }

    /// Reads the named clock. Returns `None` for a clock this OS does not have.
    pub fn now(&self, id: i64) -> Option<Timespec> {
        let ns = match id {
            CLOCK_REALTIME | CLOCK_REALTIME_COARSE => self.realtime_ns(),
            CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME => self.monotonic_ns(),
            // Single-threaded: the process has used all of its time so far.
            CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => self.monotonic_ns(),
            _ => return None,
        };
        Some(Timespec::from_nanos(ns.max(0)))
    }

    pub fn resolution(&self, id: i64) -> Option<Timespec> {
        self.now(id)
            .is_some()
            .then(|| Timespec::new(0, CLOCK_RESOLUTION_NS))
    }

    /// Seconds for `time(2)`, or `None` when it fails.
    pub fn time(&self) -> Option<i64> {
        Some(self.realtime_ns().div_euclid(NANOS_PER_SEC))
    }

    /// How long still needs to pass for a `nanosleep` deadline to arrive.
    ///
    /// A deadline in the past returns zero rather than an error, matching Linux.
    pub fn sleep_remaining(&self, deadline: Timespec) -> Option<i64> {
        if !deadline.is_valid() {
            return None;
        }
        let target = deadline.to_nanos();
        let now = self.monotonic_ns();
        Some((target - now).max(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_clock_starts_at_the_epoch_and_never_goes_backwards() {
        let mut c = Clock::default();
        assert_eq!(c.now(CLOCK_REALTIME).unwrap(), Timespec::new(0, 0));
        c.advance_to(1_000_000_000);
        assert_eq!(c.now(CLOCK_REALTIME).unwrap().sec, 1);
        c.advance_to(500);
        assert_eq!(
            c.monotonic_ns(),
            1_000_000_000,
            "a stale reading must not rewind"
        );
    }

    #[test]
    fn realtime_tracks_monotonic_from_the_boot_offset() {
        let mut c = Clock::new(1_700_000_000 * NANOS_PER_SEC, 0);
        assert_eq!(c.now(CLOCK_REALTIME).unwrap().sec, 1_700_000_000);
        c.advance(5 * NANOS_PER_SEC);
        assert_eq!(c.now(CLOCK_REALTIME).unwrap().sec, 1_700_000_005);
        assert_eq!(c.now(CLOCK_MONOTONIC).unwrap().sec, 5);
    }

    #[test]
    fn every_known_clock_is_served_and_unknown_ones_are_not() {
        let c = Clock::default();
        for id in [
            CLOCK_REALTIME,
            CLOCK_MONOTONIC,
            CLOCK_PROCESS_CPUTIME_ID,
            CLOCK_THREAD_CPUTIME_ID,
            CLOCK_MONOTONIC_RAW,
            CLOCK_REALTIME_COARSE,
            CLOCK_BOOTTIME,
        ] {
            assert!(c.now(id).is_some(), "clock {id} should exist");
            assert!(c.resolution(id).is_some());
        }
        assert_eq!(c.now(9), None);
        assert_eq!(c.resolution(-1), None);
    }

    #[test]
    fn nanosleep_deadline_counts_down_and_floors_at_zero() {
        let mut c = Clock::default();
        // 1.5 s expressed the normalised way: `nsec` must stay under a second.
        let deadline = Timespec::new(1, 500_000_000);
        assert_eq!(c.sleep_remaining(deadline).unwrap(), 1_500_000_000);
        c.advance(1_000_000_000);
        assert_eq!(c.sleep_remaining(deadline).unwrap(), 500_000_000);
        c.advance(5_000_000_000);
        assert_eq!(
            c.sleep_remaining(deadline).unwrap(),
            0,
            "a past deadline is not an error"
        );
    }

    #[test]
    fn a_malformed_sleep_deadline_is_rejected() {
        let c = Clock::default();
        assert_eq!(c.sleep_remaining(Timespec::new(0, 2_000_000_000)), None);
        assert_eq!(c.sleep_remaining(Timespec::new(-1, 0)), None);
        assert_eq!(c.sleep_remaining(Timespec::new(0, -5)), None);
    }

    #[test]
    fn timespec_bytes_round_trip_and_reject_bad_fields() {
        let ts = Timespec::new(12, 345);
        assert_eq!(Timespec::from_le_bytes(&ts.to_le_bytes()), Some(ts));
        assert_eq!(
            Timespec::from_le_bytes(&Timespec::new(0, 1_000_000_000).to_le_bytes()),
            None
        );
        assert_eq!(
            Timespec::from_le_bytes(&Timespec::new(-1, 0).to_le_bytes()),
            None
        );
        assert_eq!(Timespec::from_le_bytes(&[0u8; 8]), None);
    }

    #[test]
    fn timespec_conversion_keeps_signs_normalised() {
        assert_eq!(
            Timespec::from_nanos(2_500_000_000),
            Timespec::new(2, 500_000_000)
        );
        assert_eq!(Timespec::new(2, 500_000_000).to_nanos(), 2_500_000_000);
        assert_eq!(Timespec::from_nanos(1_500_000_000).nsec, 500_000_000);
        assert!(Timespec::new(0, 999_999_999).is_valid());
        assert!(!Timespec::new(0, 1_000_000_000).is_valid());
    }

    #[test]
    fn time_returns_whole_seconds() {
        let mut c = Clock::default();
        c.advance(2_750_000_000);
        assert_eq!(c.time().unwrap(), 2);
    }

    #[test]
    fn timeval_derives_microseconds_from_nanoseconds() {
        let tv = Timeval::from_timespec(Timespec::new(3, 1_500_500));
        assert_eq!(tv.sec, 3);
        assert_eq!(tv.usec, 1_500);
    }
}
