//! The guest input queue: keyboard and mouse events in one ordered stream.
//!
//! Events arrive from the host's windowing system and are handed to guests
//! through a pollable descriptor. The queue lives here, pure and testable, so the
//! platform layer only has to push events in and hand out fds.

/// What kind of input an event describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    KeyDown,
    KeyUp,
    MouseDown,
    MouseUp,
    MouseMove,
    MouseWheel,
    /// The window was exposed and should be redrawn.
    Expose,
    /// The window was closed by the window manager.
    Close,
    /// The window was resized; the payload carries the new size.
    Resize,
}

/// A mouse button, matching X11 numbering so a host can pass it straight
/// through.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Button {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
    Other(u8),
}

impl Button {
    pub fn from_x11(code: u8) -> Button {
        match code {
            1 => Button::Left,
            2 => Button::Middle,
            3 => Button::Right,
            4 => Button::WheelUp,
            5 => Button::WheelDown,
            other => Button::Other(other),
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            Button::Left => 1,
            Button::Middle => 2,
            Button::Right => 3,
            Button::WheelUp => 4,
            Button::WheelDown => 5,
            Button::Other(c) => *c,
        }
    }
}

/// Keyboard modifiers, as a bitmask.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Mods {
    pub shift: bool,
    pub control: bool,
    pub alt: bool,
    pub meta: bool,
}

impl Mods {
    pub fn bits(&self) -> u8 {
        (self.shift as u8)
            | ((self.control as u8) << 1)
            | ((self.alt as u8) << 2)
            | ((self.meta as u8) << 3)
    }

    pub fn from_bits(b: u8) -> Mods {
        Mods {
            shift: b & 1 != 0,
            control: b & 2 != 0,
            alt: b & 4 != 0,
            meta: b & 8 != 0,
        }
    }
}

/// One input event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Event {
    pub kind: EventKind,
    /// Window the event belongs to, or `0` for a display-wide event.
    pub window: u32,
    /// X for a pointer event, or the keysym for a key event.
    pub x: i32,
    pub y: i32,
    pub button: Button,
    pub mods: Mods,
    /// True for a key-down of a key that produces text.
    pub text: bool,
    /// Width for `Resize`, unused otherwise.
    pub width: u32,
    pub height: u32,
}

impl Event {
    pub fn key_down(window: u32, keysym: i32, mods: Mods, text: bool) -> Self {
        Event {
            kind: EventKind::KeyDown,
            window,
            x: keysym,
            y: 0,
            button: Button::Other(0),
            mods,
            text,
            width: 0,
            height: 0,
        }
    }

    pub fn key_up(window: u32, keysym: i32, mods: Mods) -> Self {
        Event {
            kind: EventKind::KeyUp,
            text: false,
            ..Event::key_down(window, keysym, mods, false)
        }
    }

    pub fn pointer(
        kind: EventKind,
        window: u32,
        x: i32,
        y: i32,
        button: Button,
        mods: Mods,
    ) -> Self {
        Event {
            kind,
            window,
            x,
            y,
            button,
            mods,
            text: false,
            width: 0,
            height: 0,
        }
    }

    pub fn resize(window: u32, width: u32, height: u32) -> Self {
        Event {
            kind: EventKind::Resize,
            window,
            x: 0,
            y: 0,
            button: Button::Other(0),
            mods: Mods::default(),
            text: false,
            width,
            height,
        }
    }

    pub fn simple(kind: EventKind, window: u32) -> Self {
        Event {
            kind,
            window,
            x: 0,
            y: 0,
            button: Button::Other(0),
            mods: Mods::default(),
            text: false,
            width: 0,
            height: 0,
        }
    }

    /// Serialises to the fixed record the guest reads: 32 bytes,
    /// little-endian, naturally aligned so a plain C struct (no packing
    /// pragmas) decodes it: `kind`/`window`/`x`/`y`/`button` as `u32`,
    /// `mods`/`text` bytes, two pad bytes, then `width`/`height` as `u32`.
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0..4].copy_from_slice(&self.kind_code().to_le_bytes());
        out[4..8].copy_from_slice(&self.window.to_le_bytes());
        out[8..12].copy_from_slice(&self.x.to_le_bytes());
        out[12..16].copy_from_slice(&self.y.to_le_bytes());
        out[16..20].copy_from_slice(&(self.button.code() as u32).to_le_bytes());
        out[20] = self.mods.bits();
        out[21] = self.text as u8;
        // out[22..24] is padding, always zero.
        out[24..28].copy_from_slice(&self.width.to_le_bytes());
        out[28..32].copy_from_slice(&self.height.to_le_bytes());
        out
    }

    fn kind_code(&self) -> u32 {
        match self.kind {
            EventKind::KeyDown => 1,
            EventKind::KeyUp => 2,
            EventKind::MouseDown => 3,
            EventKind::MouseUp => 4,
            EventKind::MouseMove => 5,
            EventKind::MouseWheel => 6,
            EventKind::Expose => 7,
            EventKind::Close => 8,
            EventKind::Resize => 9,
        }
    }

    /// Byte size of one serialised event.
    pub const BYTES: usize = 32;
}

/// Byte size of one serialised event.
pub const EVENT_SIZE: usize = Event::BYTES;

/// Events above this depth are dropped rather than growing without bound; a
/// guest that stops reading must not be able to exhaust host memory.
pub const MAX_QUEUE: usize = 4096;

/// An ordered, bounded queue of input events.
#[derive(Clone, Debug, Default)]
pub struct InputQueue {
    events: std::collections::VecDeque<Event>,
    /// Total ever pushed, so a guest can notice a dropped event.
    pushed: u64,
    /// Total ever discarded because the queue was full.
    dropped: u64,
    /// Set while at least one event is waiting, mirroring a pollable fd.
    readable: bool,
}

impl InputQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an event. Returns false when the queue was full.
    pub fn push(&mut self, e: Event) -> bool {
        if self.events.len() >= MAX_QUEUE {
            self.dropped += 1;
            return false;
        }
        self.events.push_back(e);
        self.pushed += 1;
        self.readable = true;
        true
    }

    /// Removes the oldest event.
    pub fn pop(&mut self) -> Option<Event> {
        let e = self.events.pop_front();
        if e.is_none() {
            self.readable = false;
        }
        self.readable = !self.events.is_empty();
        e
    }

    /// Number of queued events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// True when a poll would report the descriptor readable.
    pub fn readable(&self) -> bool {
        self.readable
    }

    pub fn pushed(&self) -> u64 {
        self.pushed
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Drains up to `max` events into a byte buffer for a guest `read`.
    pub fn read_into(&mut self, buf: &mut [u8]) -> usize {
        let n = (buf.len() / EVENT_SIZE).min(self.events.len());
        for i in 0..n {
            let e = self.events.pop_front().unwrap();
            buf[i * EVENT_SIZE..(i + 1) * EVENT_SIZE].copy_from_slice(&e.to_bytes());
        }
        self.readable = !self.events.is_empty();
        n * EVENT_SIZE
    }

    /// Discards events for a window that has been destroyed.
    pub fn drop_window(&mut self, window: u32) {
        self.events.retain(|e| e.window != window);
        self.readable = !self.events.is_empty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_come_back_in_the_order_they_went_in() {
        let mut q = InputQueue::new();
        assert!(q.is_empty());
        q.push(Event::key_down(1, 0x41, Mods::default(), true));
        q.push(Event::pointer(
            EventKind::MouseMove,
            1,
            10,
            20,
            Button::Left,
            Mods::default(),
        ));
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop().unwrap().kind, EventKind::KeyDown);
        assert_eq!(q.pop().unwrap().kind, EventKind::MouseMove);
        assert!(q.pop().is_none());
    }

    #[test]
    fn readability_tracks_whether_anything_is_queued() {
        let mut q = InputQueue::new();
        assert!(!q.readable());
        q.push(Event::simple(EventKind::Expose, 1));
        assert!(q.readable());
        q.pop();
        assert!(!q.readable());
        q.push(Event::simple(EventKind::Expose, 1));
        q.push(Event::simple(EventKind::Close, 1));
        q.pop();
        assert!(q.readable(), "still one left after a partial drain");
    }

    #[test]
    fn read_handles_several_events_and_leaves_the_remainder() {
        let mut q = InputQueue::new();
        for i in 0..5 {
            q.push(Event::key_down(1, i, Mods::default(), true));
        }
        // Room for two whole records only.
        let mut buf = vec![0u8; EVENT_SIZE * 2 + 3];
        assert_eq!(q.read_into(&mut buf), EVENT_SIZE * 2);
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn read_into_zero_or_short_buffers_returns_nothing() {
        let mut q = InputQueue::new();
        q.push(Event::simple(EventKind::Expose, 1));
        let mut empty: [u8; 0] = [];
        assert_eq!(q.read_into(&mut empty), 0);
        let mut short = [0u8; 5];
        assert_eq!(q.read_into(&mut short), 0);
        assert_eq!(q.len(), 1, "nothing is consumed by a partial record");
    }

    #[test]
    fn serialised_event_carries_every_field() {
        let e = Event {
            kind: EventKind::MouseDown,
            window: 7,
            x: -5,
            y: 120,
            button: Button::Right,
            mods: Mods {
                shift: true,
                control: false,
                alt: true,
                meta: false,
            },
            text: false,
            width: 0,
            height: 0,
        };
        let b = e.to_bytes();
        assert_eq!(b[0..4], 3u32.to_le_bytes());
        assert_eq!(b[4..8], 7u32.to_le_bytes());
        assert_eq!(i32::from_le_bytes(b[8..12].try_into().unwrap()), -5);
        assert_eq!(i32::from_le_bytes(b[12..16].try_into().unwrap()), 120);
        assert_eq!(b[16], 3);
        assert_eq!(b[20] & 1, 1, "shift");
        assert_eq!(b[20] & 4, 4, "alt");
    }

    #[test]
    fn record_matches_a_plain_c_struct_layout() {
        // A C guest declares the record with no packing pragmas, so the
        // kernel layout must equal the compiler's natural alignment:
        // 5 x u32, 2 x u8, 2 pad bytes, 2 x u32 == 32 bytes. This test
        // pins that contract; changing it breaks every guest reader.
        assert_eq!(Event::BYTES, 32);
        assert_eq!(EVENT_SIZE, 32);
        let b = Event::simple(EventKind::MouseMove, 1).to_bytes();
        assert_eq!(b[22], 0, "pad byte 0");
        assert_eq!(b[23], 0, "pad byte 1");
    }

    #[test]
    fn serialised_resize_carries_both_dimensions() {
        let b = Event::resize(4, 1024, 768).to_bytes();
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 9);
        assert_eq!(u32::from_le_bytes(b[24..28].try_into().unwrap()), 1024);
        assert_eq!(u32::from_le_bytes(b[28..32].try_into().unwrap()), 768);
        assert_eq!(b.len(), EVENT_SIZE);
    }

    #[test]
    fn every_event_kind_has_a_distinct_code() {
        let kinds = [
            EventKind::KeyDown,
            EventKind::KeyUp,
            EventKind::MouseDown,
            EventKind::MouseUp,
            EventKind::MouseMove,
            EventKind::MouseWheel,
            EventKind::Expose,
            EventKind::Close,
            EventKind::Resize,
        ];
        let codes: std::collections::BTreeSet<u32> = kinds
            .iter()
            .map(|k| Event::simple(*k, 1).kind_code())
            .collect();
        assert_eq!(codes.len(), kinds.len());
    }

    #[test]
    fn resize_events_carry_the_new_size() {
        let e = Event::resize(3, 800, 600);
        assert_eq!(e.kind, EventKind::Resize);
        assert_eq!(e.width, 800);
        assert_eq!(e.height, 600);
    }

    #[test]
    fn x11_button_numbers_round_trip() {
        for code in [1u8, 2, 3, 4, 5, 9] {
            assert_eq!(Button::from_x11(code).code(), code);
        }
        assert_eq!(Button::from_x11(1), Button::Left);
        assert_eq!(Button::from_x11(5), Button::WheelDown);
        assert_eq!(Button::from_x11(9), Button::Other(9));
    }

    #[test]
    fn modifiers_round_trip_through_their_bitmask() {
        let m = Mods {
            shift: true,
            control: false,
            alt: true,
            meta: true,
        };
        assert_eq!(Mods::from_bits(m.bits()), m);
        assert_eq!(Mods::from_bits(0), Mods::default());
    }

    #[test]
    fn a_full_queue_drops_rather_than_growing() {
        let mut q = InputQueue::new();
        for _ in 0..MAX_QUEUE {
            assert!(q.push(Event::simple(EventKind::MouseMove, 1)));
        }
        assert!(!q.push(Event::simple(EventKind::MouseMove, 1)));
        assert_eq!(q.len(), MAX_QUEUE);
        assert_eq!(q.dropped(), 1);
    }

    #[test]
    fn destroying_a_window_discards_its_pending_events() {
        let mut q = InputQueue::new();
        q.push(Event::key_down(1, 65, Mods::default(), true));
        q.push(Event::key_down(2, 66, Mods::default(), true));
        q.push(Event::pointer(
            EventKind::MouseMove,
            2,
            1,
            1,
            Button::Left,
            Mods::default(),
        ));
        q.drop_window(2);
        assert_eq!(q.len(), 1);
        assert_eq!(q.pop().unwrap().window, 1);
    }

    #[test]
    fn dropping_the_last_event_for_a_window_clears_readability() {
        let mut q = InputQueue::new();
        q.push(Event::key_down(2, 66, Mods::default(), true));
        q.drop_window(2);
        assert!(q.is_empty());
        assert!(!q.readable());
    }
}
