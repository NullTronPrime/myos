//! A live X11 display and input source, spoken over the wire.
//!
//! The crate deliberately has no X11 client library available, so the protocol
//! is written directly against the server socket. That is more code than a
//! binding would be, but it is a small, fixed subset of the protocol: connect,
//! authenticate, create one window, push an image, read events back.
//!
//! Everything here is best-effort. If there is no display, no socket or no
//! authorisation, [`connect`] returns `None` and the OS keeps running against
//! its in-memory framebuffer. A window server is an output device, not a
//! requirement for booting.

use parasyte_core::input::{Button, Event, EventKind, Mods};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::OnceLock;

/// The X11 core protocol version this speaks.
const PROTOCOL: u16 = 11;
/// Major revision of that version.
const REVISION: u16 = 0;

/// `CreateWindow`, opcode 1.
const OP_CREATE_WINDOW: u8 = 1;
/// `MapWindow`, opcode 8.
const OP_MAP_WINDOW: u8 = 8;
/// `ConfigureWindow`, opcode 12.
const OP_CONFIGURE_WINDOW: u8 = 12;
/// `GetGeometry`, opcode 14.
const OP_GET_GEOMETRY: u8 = 14;
/// `ChangeProperty`, opcode 18.
const OP_CHANGE_PROPERTY: u8 = 18;
/// `CreateGC`, opcode 55.
const OP_CREATE_GC: u8 = 55;
/// `PutImage`, opcode 72.
const OP_PUT_IMAGE: u8 = 72;

/// `CW*` bits in a `CreateWindow` value mask.
const CW_BACK_PIXEL: u32 = 1 << 1;
const CW_EVENT_MASK: u32 = 1 << 11;

/// `EventMask` bits for the events a guest window needs.
const EXPOSURE: u32 = 1 << 15;
const KEY_PRESS: u32 = 1 << 0;
const KEY_RELEASE: u32 = 1 << 1;
const BUTTON_PRESS: u32 = 1 << 2;
const BUTTON_RELEASE: u32 = 1 << 3;
const POINTER_MOTION: u32 = 1 << 6;
const STRUCTURE_NOTIFY: u32 = 1 << 17;

/// The event masks to try, richest first.
///
/// Which core events a server will deliver is not something the protocol lets a
/// client discover, and the answer varies: a full Xorg honours the whole core
/// mask, while the reduced Xwayland that WSLg ships answers `BadValue` for
/// everything except key presses, exposure and structure changes. Rather than
/// hardcode one server's answer, each candidate is tried in turn and the first
/// the server accepts is used, so the window comes up on either.
const EVENT_MASKS: &[(&str, u32)] = &[
    (
        "all events",
        EXPOSURE
            | KEY_PRESS
            | KEY_RELEASE
            | BUTTON_PRESS
            | BUTTON_RELEASE
            | POINTER_MOTION
            | STRUCTURE_NOTIFY,
    ),
    (
        "key press, exposure and resize",
        EXPOSURE | KEY_PRESS | STRUCTURE_NOTIFY,
    ),
    ("key press and exposure", EXPOSURE | KEY_PRESS),
    ("exposure only", EXPOSURE),
    ("no events", 0),
];

/// An open connection to the display server.
///
/// The socket is kept open for the life of the process: reconnecting per frame
/// would be both slow and, on most servers, refused.
pub struct Display {
    stream: UnixStream,
    /// The window the guest draws into.
    window: u32,
    /// Graphics context `PutImage` draws with.
    gc: u32,
    /// Resource id base handed out by the server during the handshake.
    id_base: u32,
    /// Next resource id to allocate.
    id_next: u32,
    /// Current drawable size, which the guest may change.
    width: u32,
    height: u32,
    /// Bytes still owed to the server on its input queue.
    pending: u32,
    /// Resource id mask handed out by the server.
    id_mask: u32,
    /// Set when the server last answered a request with `BadValue`.
    ///
    /// A void request such as `CreateWindow` has no reply, so the only evidence
    /// that it was refused is an error packet arriving later. This is how the
    /// window setup notices that the requested event mask was too ambitious.
    bad_value: bool,
    /// Set when the server last refused a graphics context.
    ///
    /// A server that will not make a context cannot accept `PutImage`, so this
    /// is how start-up learns to stop asking.
    bad_gc: bool,
    /// The core events this window was actually created with.
    events: u32,
    /// Set while deliberately sending requests that may be refused.
    ///
    /// Probing for an event mask the server will accept means expecting some
    /// rejections, and reporting each one would bury the result in noise that
    /// looks like a fault.
    probing: bool,
    /// Whether the server will accept pixel output at all.
    ///
    /// A reduced server may hand out windows but refuse to make a graphics
    /// context, which leaves `PutImage` with nothing to draw through. That is
    /// worth discovering once, at start-up, rather than once per frame.
    pixels: bool,
    /// Sticky read buffer: the socket is a byte stream, so packet framing
    /// survives short reads by accumulating here.
    rbuf: Vec<u8>,
}

static DISPLAY: OnceLock<Mutex<Option<Display>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Display>> {
    DISPLAY.get_or_init(|| Mutex::new(None))
}

/// Opens the display, if there is one.
///
/// Returns `None` for every reason the display might be unavailable, so a caller
/// can treat "no window" as an ordinary state rather than an error.
pub fn connect() -> Option<()> {
    let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_some() {
        return Some(());
    }
    let d = Display::open()?;
    *guard = Some(d);
    Some(())
}

/// Whether a window is currently open.
pub fn is_open() -> bool {
    slot().lock().map(|g| g.is_some()).unwrap_or(false)
}

/// Runs the compositor loop: composites dirty windows and presents at ~60fps.
///
/// This is the frame loop that drives presentation independently of guest
/// `display_present` calls. It polls input, composites dirty regions, and
/// presents the result.
pub fn compositor_loop() {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let frame_interval = Duration::from_millis(16); // ~60fps
    let mut last_frame = Instant::now();
    let mut frame_count = 0u64;

    loop {
        // Poll for input events
        let events = poll_events();
        if !events.is_empty() {
            if let Ok(mut g) = crate::trap::state().lock() {
                for e in events {
                    g.input.push(e);
                }
            }
        }

        // Check if any window is dirty
        let has_dirty = {
            let state = crate::trap::state();
            match state.lock() {
                Ok(g) => g.display.windows().iter().any(|w| w.dirty && w.visible && !w.minimized),
                Err(p) => p.into_inner().display.windows().iter().any(|w| w.dirty && w.visible && !w.minimized),
            }
        };

        if has_dirty && last_frame.elapsed() >= frame_interval {
            // Composite and present
            let frame = {
                let state = crate::trap::state();
                match state.lock() {
                    Ok(g) => {
                        let fb = g.display.composite(|win| {
                            if win.buffer == 0 {
                                return Err(parasyte_core::vfs::Errno::Inval);
                            }
                            let buf = unsafe {
                                std::slice::from_raw_parts(
                                    win.buffer as *const u8,
                                    win.byte_len() as usize,
                                )
                            };
                            Ok(buf.chunks_exact(4)
                                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                                .collect())
                        }).ok();
                        fb.map(|f| f.to_ppm())
                    }
                    Err(p) => None,
                }
            };
            if let Some(ppm) = frame {
                present(&ppm);
                frame_count += 1;
                if frame_count % 60 == 0 {
                    eprintln!("compositor: {} frames", frame_count);
                }
            }
            last_frame = Instant::now();
        }

        // Small sleep to avoid busy-waiting
        std::thread::sleep(Duration::from_millis(1));

        // Check if guest exited
        if crate::trap::exit_status().is_some() {
            break;
        }
    }
}

/// Pushes a composited frame to the window.
///
/// `frame` is a PPM as produced by the core: a `P6` header followed by RGB
/// triples. Anything else is ignored, because the core owns the format.
pub fn present(frame: &[u8]) {
    let Some((pixels, w, h)) = decode_ppm(frame) else {
        return;
    };
    let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());
    let Some(d) = guard.as_mut() else { return };
    // Start-up already found out whether this server will take pixels at all.
    if !d.pixels {
        return;
    }
    if w != d.width || h != d.height {
        // The guest resized its window; the server needs to be told before the
        // image will fit, and a failed request would desynchronise the stream.
        // Failure is reported (once per process) rather than silently
        // painting black: a stuck size mismatch is otherwise undebuggable.
        if d.resize(w, h).is_none() {
            static RESIZE_WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !RESIZE_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!("parasyteos: display resize to {}x{} refused", w, h);
            }
            return;
        }
    }
    // A failure here means the server is gone. Dropping the connection lets the
    // guest keep running headless rather than writing into a dead socket.
    if d.put_image(&pixels, w, h).is_none() {
        eprintln!("parasyteos: DBG display put_image failed, dropping connection");
        *guard = None;
        return;
    }
    // `PutImage` is a void request, so a malformed one is answered with an error
    // rather than a reply. Reading without waiting costs nothing and turns "the
    // screen is blank for no visible reason" into a message that says why.
    if d.read_packets(false).is_err() {
        eprintln!("parasyteos: DBG display read failed after present, dropping connection");
        *guard = None;
    }
}

/// Decodes a binary PPM into `(rgb triples, width, height)`.
fn decode_ppm(frame: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    if frame.len() < 2 || &frame[0..2] != b"P6" {
        return None;
    }
    let mut i = 2usize;
    let next = |i: &mut usize| -> Option<u32> {
        // Header fields are whitespace separated, with `#` comments.
        loop {
            while *i < frame.len() && frame[*i].is_ascii_whitespace() {
                *i += 1;
            }
            if *i < frame.len() && frame[*i] == b'#' {
                while *i < frame.len() && frame[*i] != b'\n' {
                    *i += 1;
                }
                continue;
            }
            break;
        }
        let start = *i;
        while *i < frame.len() && frame[*i].is_ascii_digit() {
            *i += 1;
        }
        if start == *i {
            return None;
        }
        std::str::from_utf8(&frame[start..*i]).ok()?.parse().ok()
    };
    let w = next(&mut i)?;
    let h = next(&mut i)?;
    let _maxval = next(&mut i)?;
    // Exactly one whitespace byte separates the header from the pixels.
    i += 1;
    let want = (w as usize) * (h as usize) * 3;
    if frame.len() < i + want {
        return None;
    }
    Some((frame[i..i + want].to_vec(), w, h))
}

/// How long any single exchange with the display server may take.
///
/// A window is an output device. If the server is slow, wedged, or speaking a
/// protocol revision this code does not understand, the OS must still boot, so
/// every read is bounded and a timeout drops the connection rather than hanging
/// the guest indefinitely.
const SERVER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

impl Display {
    /// Connects, authenticates and creates the guest window.
    fn open() -> Option<Display> {
        let path = socket_path()?;
        let mut stream = UnixStream::connect(&path).ok()?;
        // Close-on-exec: forked-then-exec'd children inherit every fd, and
        // every parasyteos process pumps its own X socket before each syscall. A
        // shared socket means N readers splitting one packet stream, which
        // desynchronises ALL of them (dead input, vanishing windows). The
        // creating process must be the only reader, so children never
        // inherit it.
        {
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
                return None;
            }
        }
        stream.set_read_timeout(Some(SERVER_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(SERVER_TIMEOUT)).ok()?;

        let (auth_name, auth_data) = read_authority().unwrap_or_default();
        write_all(&mut stream, &handshake(&auth_name, &auth_data))?;

        let mut head = [0u8; 8];
        stream.read_exact(&mut head).ok()?;
        // A failed setup answers with `failed`, whose only useful field is the
        // reason length that follows.
        if head[0] != 1 {
            let reason_len = u8::from_be_bytes([head[1]]) as usize;
            let mut reason = vec![0u8; reason_len];
            stream.read_exact(&mut reason).ok()?;
            eprintln!(
                "parasyteos: X11 setup refused: {}",
                String::from_utf8_lossy(&reason)
            );
            return None;
        }

        // The rest of the setup reply is fixed-length except for the vendor
        // string, which is padded to a four-byte boundary, and the trailing
        // format and screen lists.
        // Everything the server sends after that first byte follows the byte
        // order this client asked for, which is little-endian. Reading the
        // length the other way round asks for 139288 bytes instead of 6688 and
        // then blocks until the read times out, which looks exactly like a
        // server that will not talk to us.
        let words = u16::from_le_bytes([head[6], head[7]]) as usize;
        let mut rest = vec![0u8; words * 4];
        stream.read_exact(&mut rest).ok()?;
        if rest.len() < 32 {
            return None;
        }
        let dword = |at: usize| u32::from_le_bytes(rest[at..at + 4].try_into().unwrap());
        let id_base = dword(4);
        let id_mask = dword(8);
        let vendor_len = u16::from_le_bytes([rest[16], rest[17]]) as usize;
        let num_formats = rest[21] as usize;
        // The vendor string is padded up to a four-byte boundary.
        let formats_at = (32 + vendor_len + 3) & !3;
        let screen_at = formats_at + num_formats * 8;
        if rest.len() < screen_at + 40 {
            return None;
        }
        let screen = &rest[screen_at..];
        let root = u32::from_le_bytes(screen[0..4].try_into().unwrap());
        let root_visual = u32::from_le_bytes(screen[32..36].try_into().unwrap());
        let root_depth = screen[38];

        let (width, height) = display_size();
        let mut d = Display {
            stream,
            window: 0,
            gc: 0,
            id_base,
            id_mask,
            id_next: 1,
            width,
            height,
            pending: 0,
            bad_value: false,
            bad_gc: false,
            events: 0,
            probing: true,
            pixels: false,
            rbuf: Vec::new(),
        };

        let window = d.next_id();
        // Embedded clients parent to the desktop's window (same visual and
        // depth throughout the tree, so the root's serve the child too).
        let parent = embed_parent().unwrap_or(root);
        // Find an event mask this server will actually deliver. A rejected mask
        // leaves no window behind at all, so the refusal has to be noticed here
        // rather than left to surface later as a screen that never updates.
        let mut chosen = None;
        for (i, (label, mask)) in EVENT_MASKS.iter().enumerate() {
            d.bad_value = false;
            d.create_window(parent, root_visual, root_depth, window, width, height, *mask)?;
            d.settle();
            if !d.bad_value {
                if i != 0 {
                    eprintln!("parasyteos: display events limited to {label}");
                }
                chosen = Some(*mask);
                break;
            }
        }
        let Some(events) = chosen else {
            // Even an empty mask was refused, so there is nothing to draw on.
            return None;
        };
        d.probing = false;
        d.events = events;
        d.set_title(window)?;
        d.map(window)?;
        // Take the server's word for the size rather than the one that was
        // asked for, so the frame the guest draws is the frame that is shown.
        if let Some((real_w, real_h)) = d.geometry(window) {
            d.width = real_w;
            d.height = real_h;
        }
        d.window = window;
        // The context is made last so it cannot outlive a window that was never
        // created, and so `geometry` has already settled the stream first.
        d.gc = d.create_gc(window)?;
        // Ask the server whether pixels will land, once, before the guest starts
        // painting. A server that refuses this would otherwise be reported on
        // every single frame for as long as the guest ran.
        d.probing = true;
        let one = vec![0u8; 4];
        let drawn = d.put_image(&one, 1, 1).is_some();
        d.settle();
        d.probing = false;
        d.pixels = drawn && !d.bad_gc;
        if !d.pixels {
            eprintln!("parasyteos: display cannot show pixels: the server refused PutImage");
        }
        Some(d)
    }

    /// Allocates the next resource id for this client.
    ///
    /// Ids are `id_base` with the low bits of the server's mask filled in, so
    /// they are always in the range the client owns.
    fn next_id(&mut self) -> u32 {
        let id = self.id_base | (self.id_next & self.id_mask);
        self.id_next = self.id_next.wrapping_add(1);
        id
    }

    /// Issues `CreateWindow` with the given core event mask.
    fn create_window(
        &mut self,
        root: u32,
        visual: u32,
        depth: u8,
        id: u32,
        width: u32,
        height: u32,
        events: u32,
    ) -> Option<()> {
        // opcode, depth, length(2), wid, parent, x, y, width, height, border,
        // class, visual, value-mask, then one value per mask bit in bit order.
        // The mask has to come before the values: the server walks the value list
        // by counting the bits it finds in the mask, so a mask that disagrees with
        // the number of values is answered with `BadLength`.
        let mut req = Vec::with_capacity(44);
        req.push(OP_CREATE_WINDOW);
        req.push(depth);
        req.extend_from_slice(&[0, 0]); // request length, filled in below
        req.extend_from_slice(&id.to_le_bytes());
        req.extend_from_slice(&root.to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes()); // x
        req.extend_from_slice(&0u16.to_le_bytes()); // y
        req.extend_from_slice(&(width as u16).to_le_bytes());
        req.extend_from_slice(&(height as u16).to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes()); // border width
        req.extend_from_slice(&1u16.to_le_bytes()); // class: InputOutput
        req.extend_from_slice(&visual.to_le_bytes());
        // `CWBackPixel` is bit 1 and `CWEventMask` is bit 10, so the values
        // follow in that order.
        req.extend_from_slice(&(CW_BACK_PIXEL | CW_EVENT_MASK).to_le_bytes());
        req.extend_from_slice(&0x0000_0002u32.to_le_bytes()); // BackPixel: black
        req.extend_from_slice(&events.to_le_bytes()); // EventMask
        finish(&mut req, 2)?;
        write_all(&mut self.stream, &req)?;
        Some(())
    }

    /// Sets `WM_NAME` so the window is identifiable in a task list.
    fn set_title(&mut self, id: u32) -> Option<()> {
        let title = b"parasyteos";
        // opcode, mode, length(2), window, property, type, format, unused(3),
        // data length, data, then padding to a word boundary.
        let mut req = Vec::with_capacity(28 + title.len());
        req.push(OP_CHANGE_PROPERTY);
        req.push(0); // mode: Replace
        req.extend_from_slice(&[0, 0]); // request length, filled in below
        req.extend_from_slice(&id.to_le_bytes()); // window
        req.extend_from_slice(&39u32.to_le_bytes()); // WM_NAME (predefined atom 39)
        req.extend_from_slice(&31u32.to_le_bytes()); // STRING (predefined atom 31)
        req.push(8); // format
        req.extend_from_slice(&[0, 0, 0]); // unused
        req.extend_from_slice(&(title.len() as u32).to_le_bytes()); // length in format units
        req.extend_from_slice(title);
        finish(&mut req, 2)?;
        write_all(&mut self.stream, &req)?;
        Some(())
    }

    /// Asks the server for the window's real size.
    ///
    /// The requested size is only a request: a window manager or the server
    /// itself may hand back something smaller. Every later `PutImage` band is
    /// sized from `width`/`height`, so believing the request instead of the
    /// reply would write outside the window and be refused.
    fn geometry(&mut self, id: u32) -> Option<(u32, u32)> {
        let mut req = Vec::with_capacity(8);
        req.push(OP_GET_GEOMETRY);
        req.push(0); // unused
        req.extend_from_slice(&2u16.to_le_bytes()); // request length in words
        req.extend_from_slice(&id.to_le_bytes());
        write_all(&mut self.stream, &req)?;
        self.pending += 1;

        // `GetGeometry` is one of the few requests here that is answered with a
        // reply, so the wait ends on that reply rather than on a timeout.
        for _ in 0..16 {
            if self.pending == 0 {
                break;
            }
            let pkts = self.read_packets(true).ok()?;
            if pkts.is_empty() {
                break;
            }
            for pkt in pkts {
                if pkt[0] != 1 {
                    continue; // an error or an event, already reported
                }
                let width = u16::from_le_bytes([pkt[16], pkt[17]]) as u32;
                let height = u16::from_le_bytes([pkt[18], pkt[19]]) as u32;
                if width != 0 && height != 0 {
                    self.pending = 0;
                    return Some((width, height));
                }
            }
        }
        self.pending = 0;
        None
    }

    fn map(&mut self, id: u32) -> Option<()> {
        let mut req = Vec::with_capacity(8);
        req.push(OP_MAP_WINDOW);
        req.push(0); // unused
        req.extend_from_slice(&2u16.to_le_bytes()); // request length in words
        req.extend_from_slice(&id.to_le_bytes());
        write_all(&mut self.stream, &req)?;
        Some(())
    }

    /// Resizes the window.
    fn resize(&mut self, width: u32, height: u32) -> Option<()> {
        // `ConfigureWindow`: opcode, unused, length(2), window, value-mask(2),
        // unused(2), then one 4-byte value per mask bit in bit order. Each value
        // is a 16-bit quantity followed by two padding bytes.
        let mut req = Vec::with_capacity(20);
        req.push(OP_CONFIGURE_WINDOW);
        req.push(0); // unused
        req.extend_from_slice(&[0, 0]); // request length, filled in below
        req.extend_from_slice(&self.window.to_le_bytes());
        req.extend_from_slice(&0x0000_0003u16.to_le_bytes()); // width | height
        req.extend_from_slice(&[0, 0]); // unused
        req.extend_from_slice(&(width as u16).to_le_bytes());
        req.extend_from_slice(&[0, 0]); // padding
        req.extend_from_slice(&(height as u16).to_le_bytes());
        req.extend_from_slice(&[0, 0]); // padding
        finish(&mut req, 2)?;
        write_all(&mut self.stream, &req)?;
        self.width = width;
        self.height = height;
        // The server answers a resize with events rather than a reply, so
        // nothing is added to `pending` here.
        Some(())
    }

    /// Creates the graphics context used to upload frames.
    ///
    /// `PutImage` names a context, and although the protocol allows "none" the
    /// server is free to insist on a real one, so one is made with default
    /// values: the pixels are written verbatim and nothing is combined with what
    /// is already there.
    fn create_gc(&mut self, drawable: u32) -> Option<u32> {
        let gc = self.next_id();
        let mut req = Vec::with_capacity(16);
        req.push(OP_CREATE_GC);
        req.push(0); // unused
        req.extend_from_slice(&[0, 0]); // request length, filled in below
        req.extend_from_slice(&gc.to_le_bytes()); // resource id for the new GC
        req.extend_from_slice(&drawable.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes()); // value mask: all defaults
        finish(&mut req, 2)?;
        write_all(&mut self.stream, &req)?;
        Some(gc)
    }

    /// Uploads the pixels with `PutImage` in `ZPixmap` format.
    ///
    /// The core hands over RGB triples; the server wants a 32-bit pixel for the
    /// window's depth, so the conversion happens here.
    fn put_image(&mut self, rgb: &[u8], width: u32, height: u32) -> Option<()> {
        // Maximum request size is 16 MiB of payload, so a very large window is
        // sent as horizontal bands rather than being refused.
        const BAND_ROWS: u32 = 64;
        let mut y = 0u32;
        while y < height {
            let rows = BAND_ROWS.min(height - y);
            let mut body = Vec::with_capacity((width as usize) * (rows as usize) * 4);
            for row in 0..rows {
                for col in 0..width as usize {
                    let at = ((y + row) as usize * width as usize + col) * 3;
                    if at + 2 >= rgb.len() {
                        break;
                    }
                    let (r, g, b) = (rgb[at] as u32, rgb[at + 1] as u32, rgb[at + 2] as u32);
                    body.extend_from_slice(&((r << 16) | (g << 8) | b).to_le_bytes());
                }
            }
            // opcode, format, length(2), drawable, gc, width, height, dst-x,
            // dst-y, left-pad, depth, unused(2), data.
            let mut req = Vec::with_capacity(24 + body.len());
            req.push(OP_PUT_IMAGE);
            req.push(2); // format: ZPixmap (0=XYBitmap, 1=XYPixmap, 2=ZPixmap)
            req.extend_from_slice(&[0, 0]); // request length, filled in below
            req.extend_from_slice(&self.window.to_le_bytes()); // drawable
            req.extend_from_slice(&self.gc.to_le_bytes());
            req.extend_from_slice(&(width as u16).to_le_bytes());
            req.extend_from_slice(&(rows as u16).to_le_bytes());
            req.extend_from_slice(&0u16.to_le_bytes()); // dst-x
            req.extend_from_slice(&(y as u16).to_le_bytes()); // dst-y
            req.push(0); // left pad: the rows are already word aligned
            req.push(24); // depth
            req.extend_from_slice(&0u16.to_le_bytes()); // unused
            req.extend_from_slice(&body);
            finish(&mut req, 2)?;
            write_all(&mut self.stream, &req)?;
            y += rows;
        }
        // `PutImage` is a void request: the server sends back an event, and an
        // error if the request was malformed, but never a reply. Counting a
        // reply here would leave `pending` permanently above zero and hide the
        // error that a bad request produces.
        Some(())
    }

    /// Waits for the server to catch up, so a void request can be judged.
    ///
    /// `CreateWindow` and `MapWindow` are answered with nothing at all when they
    /// succeed, and with a single error packet when they do not. Reading here
    /// with a short deadline is the only way to tell those two cases apart
    /// before carrying on to use the window.
    ///
    /// The wait ends as soon as the socket falls quiet, so the common case costs
    /// one timeout rather than a fixed number of them.
    fn settle(&mut self) {
        // Long enough for a local socket round trip, short enough that a server
        // which has simply gone quiet does not stall start-up.
        let deadline = std::time::Duration::from_millis(120);
        let _ = self.stream.set_read_timeout(Some(deadline));
        // One silent read only proves the server had not answered *yet*. Giving
        // up after two in a row keeps a slow reply from being mistaken for a
        // request that was accepted, which would leave the caller believing a
        // refused request had worked.
        let mut silent = 0;
        for _ in 0..8 {
            match self.read_packets(true) {
                Ok(pkts) if pkts.is_empty() => {
                    silent += 1;
                    if silent >= 2 {
                        break;
                    }
                }
                Ok(_) => silent = 0,
                Err(_) => break,
            }
        }
        let _ = self.stream.set_read_timeout(Some(SERVER_TIMEOUT));
    }
}

/// X11 `BadValue`: a request was well-formed but carried a value the server will
/// not accept, such as an event mask its input extension does not implement.
const ERR_BAD_VALUE: u8 = 2;

/// X11 `BadGC`: the graphics context named by a request does not exist.
///
/// A server that refuses `CreateGC` makes this unavoidable, so it is treated as
/// a permanent "pixels are not available here" rather than a fault to report.
const ERR_BAD_GC: u8 = 13;

/// Pads a request to a word boundary and writes its length.
///
/// Every X11 request carries a 16-bit length in four-byte units at a fixed
/// offset that depends on the request: usually it follows the opcode byte, but
/// `CreateWindow` puts the window depth there, `ChangeProperty` the mode and
/// `PutImage` the format, so those start the length one byte later. Getting the
/// offset wrong is answered with `BadLength`.
///
/// `len_at` is the index of the first byte of the length field.
fn finish(req: &mut Vec<u8>, len_at: usize) -> Option<()> {
    while req.len() % 4 != 0 {
        req.push(0);
    }
    let words = u16::try_from(req.len() / 4).ok()?;
    req[len_at..len_at + 2].copy_from_slice(&words.to_le_bytes());
    Some(())
}

/// A human-readable name for the X11 error codes a client is likely to hit.
fn error_name(code: u8) -> &'static str {
    match code {
        1 => "BadRequest",
        2 => "BadValue",
        3 => "BadWindow",
        4 => "BadPixmap",
        5 => "BadAtom",
        6 => "BadCursor",
        7 => "BadFont",
        8 => "BadMatch",
        9 => "BadDrawable",
        10 => "BadAccess",
        11 => "BadAlloc",
        12 => "BadColor",
        13 => "BadGC",
        14 => "BadIDChoice",
        15 => "BadName",
        16 => "BadLength",
        17 => "BadImplementation",
        _ => "unknown error",
    }
}

/// The unix socket the display server listens on.
///
/// `DISPLAY` is honoured for the `:N.s` form that WSLg and every desktop use;
/// a host name or an Xauthority-indirect display is not supported.
fn socket_path() -> Option<std::path::PathBuf> {
    let d = std::env::var("DISPLAY").ok()?;
    let d = d.split('.').next()?;
    let n: u32 = d.strip_prefix(':')?.parse().ok()?;
    Some(std::path::PathBuf::from(format!("/tmp/.X11-unix/X{n}")))
}

/// The window size requested through the environment.
fn display_size() -> (u32, u32) {
    let env = |k: &str, dflt: u32| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(dflt)
    };
    (env("PARASYTEOS_WIDTH", 640), env("PARASYTEOS_HEIGHT", 480))
}

/// An X window to parent this client's window to, for embedded mode.
///
/// `PARASYTEOS_EMBED_PARENT` names the desktop's outer window (decimal or 0x
/// hex). The child window then lives INSIDE the desktop's top-level
/// window instead of opening a second one: one OS window on the host,
/// with the desktop compositor and the app side by side in it. Input
/// keeps flowing over the child's own connection, so no other code
/// changes.
fn embed_parent() -> Option<u32> {
    let s = std::env::var("PARASYTEOS_EMBED_PARENT").ok()?;
    let s = s.trim();
    let v = if let Some(h) = s.strip_prefix("0x") {
        u32::from_str_radix(h, 16).ok()?
    } else {
        s.parse::<u32>().ok()?
    };
    if v == 0 {
        None
    } else {
        Some(v)
    }
}

/// This client's outer X window id, for rendezvous (the desktop publishes
/// it so apps can reparent into it).
pub fn xid() -> Option<u32> {
    slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(|d| d.window)
}

/// Resizes the outer window (embedded apps following a desktop resize).
/// Mirrors move_outer: guest-model resize is handled by the dispatcher.
pub fn resize_outer(width: u32, height: u32) -> bool {
    let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());
    let Some(d) = guard.as_mut() else {
        return false;
    };
    let mut req = Vec::with_capacity(20);
    req.push(OP_CONFIGURE_WINDOW);
    req.push(0); // unused
    req.extend_from_slice(&[0, 0]); // request length, filled in below
    req.extend_from_slice(&d.window.to_le_bytes());
    req.extend_from_slice(&0x0000_000cu16.to_le_bytes()); // width | height
    req.extend_from_slice(&[0, 0]); // unused
    req.extend_from_slice(&(width as u16).to_le_bytes());
    req.extend_from_slice(&[0, 0]); // padding
    req.extend_from_slice(&(height as u16).to_le_bytes());
    req.extend_from_slice(&[0, 0]); // padding
    if finish(&mut req, 2).is_none() {
        return false;
    }
    if write_all(&mut d.stream, &req).is_none() {
        return false;
    }
    d.width = width;
    d.height = height;
    true
}

/// Moves the outer window (embedded drag). Coordinates are parent-relative
/// i16s; the guest model move is handled by the dispatcher, this only
/// tells the server.
pub fn move_outer(x: i32, y: i32) -> bool {
    let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());
    let Some(d) = guard.as_mut() else {
        return false;
    };
    let mut req = Vec::with_capacity(16);
    req.push(OP_CONFIGURE_WINDOW);
    req.push(0); // unused
    req.extend_from_slice(&[0, 0]); // request length, filled in below
    req.extend_from_slice(&d.window.to_le_bytes());
    req.extend_from_slice(&0x0000_0003u16.to_le_bytes()); // x | y
    req.extend_from_slice(&[0, 0]); // unused
    req.extend_from_slice(&(x as i16).to_le_bytes());
    req.extend_from_slice(&[0, 0]); // padding
    req.extend_from_slice(&(y as i16).to_le_bytes());
    req.extend_from_slice(&[0, 0]); // padding
    if finish(&mut req, 2).is_none() {
        return false;
    }
    write_all(&mut d.stream, &req).is_some()
}

/// Builds the connection setup request.
fn handshake(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut req = Vec::with_capacity(12 + name.len() + data.len());
    req.push(b'l'); // little-endian
    req.push(0); // unused
    req.extend_from_slice(&PROTOCOL.to_le_bytes());
    req.extend_from_slice(&REVISION.to_le_bytes());
    req.extend_from_slice(&(name.len() as u16).to_le_bytes());
    req.extend_from_slice(&(data.len() as u16).to_le_bytes());
    req.extend_from_slice(&0u16.to_le_bytes()); // unused
    req.extend_from_slice(name);
    // The authorisation data must be padded to a four-byte boundary.
    req.extend_from_slice(data);
    while req.len() % 4 != 0 {
        req.push(0);
    }
    req
}

/// Finds the MIT-MAGIC-COOKIE-1 entry for this display in `~/.Xauthority`.
///
/// The file is a sequence of records in a fixed big-endian layout. Only the
/// entry whose display number matches is used; a server that allows
/// unauthenticated local connections needs none, and an empty result is
/// handled by sending a zero-length authorisation.
fn read_authority() -> Option<(Vec<u8>, Vec<u8>)> {
    let path = std::env::var_os("XAUTHORITY")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".Xauthority"))
        })?;
    let data = std::fs::read(path).ok()?;
    let want = std::env::var("DISPLAY").ok()?;
    let num = want.split('.').next()?.trim_start_matches(':').to_string();

    let mut i = 0usize;
    let take = |i: &mut usize| -> Option<Vec<u8>> {
        if *i + 2 > data.len() {
            return None;
        }
        let n = u16::from_be_bytes([data[*i], data[*i + 1]]) as usize;
        *i += 2;
        if *i + n > data.len() {
            return None;
        }
        let v = data[*i..*i + n].to_vec();
        *i += n;
        Some(v)
    };
    while i < data.len() {
        if i + 2 > data.len() {
            break;
        }
        // The two family fields sit before the address pairs.
        i += 2;
        let _family = take(&mut i)?;
        let _address = take(&mut i)?;
        let _number = take(&mut i)?;
        let _name = take(&mut i)?;
        let value = take(&mut i)?;
        if String::from_utf8_lossy(&_number) == num {
            return Some((_name, value));
        }
    }
    None
}

/// Reads whatever the server has sent and turns it into core input events.
///
/// Returns an empty vector when there is no display, so a headless run pays
/// nothing but a lock. A server that has gone away drops the connection rather
/// than being retried forever.
pub fn poll_events() -> Vec<Event> {
    let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());
    let Some(d) = guard.as_mut() else {
        return Vec::new();
    };
    let raw = match d.read_packets(false) {
        Ok(r) => r,
        Err(()) => {
            eprintln!("parasyteos: DBG display read failed in poll, dropping connection");
            *guard = None;
            return Vec::new();
        }
    };
    // Every 32-byte packet that is not an error or a reply is an event:
    // genuine server events carry codes 2-35 WITHOUT the high bit (that
    // bit is the SendEvent flag for synthetic events only), so filtering
    // on it strands all real input. Errors and replies fall through
    // decode_event to None.
    raw.iter()
        .filter(|p| p[0] != 0 && p[0] != 1)
        .filter_map(|p| decode_event(p, d.window))
        .collect()
}

/// Event codes from the core protocol.
mod ev {
    pub const KEY_PRESS: u8 = 2;
    pub const KEY_RELEASE: u8 = 3;
    pub const BUTTON_PRESS: u8 = 4;
    pub const BUTTON_RELEASE: u8 = 5;
    pub const MOTION_NOTIFY: u8 = 6;
    pub const EXPOSE: u8 = 12;
    pub const CONFIGURE_NOTIFY: u8 = 22;
}

impl Display {
    /// Classifies one packet: an error is reported and remembered, and anything
    /// that answers a request settles one unit of the outstanding count.
    fn take(&mut self, pkt: [u8; 32]) {
        match pkt[0] {
            0 => {
                // The sequence number ties the error to the request that caused
                // it, so a malformed request is reported rather than silently
                // ignored.
                let code = pkt[1];
                let seq = u16::from_le_bytes([pkt[2], pkt[3]]);
                let major = pkt[10];
                let minor = u16::from_le_bytes([pkt[8], pkt[9]]);
                if !self.probing {
                    eprintln!(
                        "parasyteos: X11 error {} ({}) for request {}.{} sequence {seq}",
                        error_name(code),
                        code,
                        major,
                        minor
                    );
                }
                if code == ERR_BAD_VALUE {
                    self.bad_value = true;
                }
                if code == ERR_BAD_GC {
                    self.bad_gc = true;
                }
                if self.pending > 0 {
                    self.pending -= 1;
                }
            }
            // A reply or an event also tells us one request is done.
            _ if self.pending > 0 => self.pending -= 1,
            _ => {}
        }
    }

    /// Reads every 32-byte packet the server has ready, without blocking.
    ///
    /// Replies and errors are counted off the outstanding-replies total and
    /// discarded: the requests this module sends do not ask for anything back
    /// that the guest needs to see.
    ///
    /// The socket is a byte stream, not a message pipe: a short read is
    /// normal traffic (pointer bursts fragment all the time), so bytes
    /// accumulate in a sticky buffer and packets split off it. Only EOF or
    /// a hard error drops the connection.
    fn read_packets(&mut self, wait: bool) -> Result<Vec<[u8; 32]>, ()> {
        if wait && self.rbuf.len() < 32 {
            // One blocking byte first, so a caller that needs to know whether
            // a void request was accepted actually waits for the verdict
            // instead of concluding "no news is good news" before the error
            // has arrived. Quiet is an empty answer, not a dead server.
            self.stream.set_nonblocking(false).map_err(|_| ())?;
            let mut one = [0u8; 1];
            match self.stream.read(&mut one) {
                Ok(0) => return Err(()),
                Ok(_) => self.rbuf.push(one[0]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(Vec::new())
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(()),
            }
        }
        // Drain whatever is waiting into the sticky buffer.
        self.stream.set_nonblocking(true).map_err(|_| ())?;
        loop {
            let mut tmp = [0u8; 512];
            match self.stream.read(&mut tmp) {
                Ok(0) => return Err(()),
                Ok(n) => {
                    self.rbuf.extend_from_slice(&tmp[..n]);
                    if self.rbuf.len() > 65536 {
                        return Err(());
                    }
                }
                // Nothing waiting is the normal case between frames. The
                // non-blocking mode never reports a timeout, but both spellings
                // are handled so the pump also works if the mode is dropped.
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(()),
            }
        }
        self.stream.set_nonblocking(false).map_err(|_| ())?;
        let mut out = Vec::new();
        while self.rbuf.len() >= 32 {
            let pkt: [u8; 32] = self.rbuf[..32].try_into().map_err(|_| ())?;
            self.take(pkt);
            out.push(pkt);
            self.rbuf.drain(..32);
        }
        Ok(out)
    }
}

/// Turns one core-protocol event into a guest event.
fn decode_event(p: &[u8; 32], window: u32) -> Option<Event> {
    let code = p[0] & 0x7f;
    let word = |at: usize| u16::from_le_bytes([p[at], p[at + 1]]);
    let dword = |at: usize| u32::from_le_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
    let x = word(24) as i32;
    let y = word(26) as i32;
    match code {
        ev::KEY_PRESS => {
            let keycode = p[1];
            let mods = modifiers(word(28));
            Some(Event::key_down(
                window,
                keysym(keycode, mods.shift),
                mods,
                keycode >= 38 && keycode <= 58,
            ))
        }
        ev::KEY_RELEASE => {
            let mods = modifiers(word(28));
            Some(Event::key_up(window, keysym(p[1], mods.shift), mods))
        }
        ev::BUTTON_PRESS => {
            let mods = modifiers(word(28));
            Some(Event::pointer(
                EventKind::MouseDown,
                window,
                x,
                y,
                button(p[1]),
                mods,
            ))
        }
        ev::BUTTON_RELEASE => {
            let mods = modifiers(word(28));
            Some(Event::pointer(
                EventKind::MouseUp,
                window,
                x,
                y,
                button(p[1]),
                mods,
            ))
        }
        ev::MOTION_NOTIFY => {
            let mods = modifiers(word(28));
            Some(Event::pointer(
                EventKind::MouseMove,
                window,
                x,
                y,
                Button::Other(0),
                mods,
            ))
        }
        ev::EXPOSE => Some(Event::simple(EventKind::Expose, dword(8))),
        ev::CONFIGURE_NOTIFY => Some(Event::resize(dword(8), word(20) as u32, word(22) as u32)),
        _ => None,
    }
}

/// Maps the X11 modifier state onto the core's modifier flags.
///
/// The state word carries Shift, Lock, Control and the eight `Mod` slots; the
/// first `Mod` is Alt on every layout this kernel is likely to meet, so that is
/// what gets reported as `alt`.
fn modifiers(state: u16) -> Mods {
    Mods {
        shift: state & (1 << 0) != 0,
        control: state & (1 << 2) != 0,
        alt: state & (1 << 3) != 0,
        // Caps Lock arrives as a modifier bit but has no field of its own in
        // the core, so it is reported as `meta` rather than being dropped.
        meta: state & (1 << 1) != 0,
    }
}

/// Maps an X11 button number onto the core's enum.
fn button(b: u8) -> Button {
    match b {
        1 => Button::Left,
        2 => Button::Middle,
        3 => Button::Right,
        _ => Button::Other(b),
    }
}

/// Maps a keycode onto a keysym for the keys a guest actually reads.
///
/// The full mapping lives on the server and would need a `GetKeyboardMapping`
/// round trip; the layout below covers the PC/XT arrangement that every server
/// uses as a minimum, which is enough to type with. Anything unmapped becomes
/// `XK_VoidSymbol`, and the guest still sees the key press and release.
/// Shift selects the upper symbol (letters go uppercase); guests treat the
/// shift bit as consumed by the keysym and keep rejecting ctrl/alt combos.
fn keysym(keycode: u8, shifted: bool) -> i32 {
    const VOID: i32 = 0xffff;
    if shifted {
        return match keycode {
            38 => b'A' as i32,
            39 => b'S' as i32,
            40 => b'D' as i32,
            41 => b'F' as i32,
            42 => b'G' as i32,
            43 => b'H' as i32,
            44 => b'J' as i32,
            45 => b'K' as i32,
            46 => b'L' as i32,
            52 => b'Z' as i32,
            53 => b'X' as i32,
            54 => b'C' as i32,
            55 => b'V' as i32,
            56 => b'B' as i32,
            57 => b'N' as i32,
            58 => b'M' as i32,
            24 => b'Q' as i32,
            25 => b'W' as i32,
            26 => b'E' as i32,
            27 => b'R' as i32,
            28 => b'T' as i32,
            29 => b'Y' as i32,
            30 => b'U' as i32,
            31 => b'I' as i32,
            32 => b'O' as i32,
            33 => b'P' as i32,
            34 => b'{' as i32,
            35 => b'}' as i32,
            47 => b':' as i32,
            48 => b'"' as i32,
            49 => b'~' as i32,
            51 => b'|' as i32,
            59 => b'<' as i32,
            60 => b'>' as i32,
            61 => b'?' as i32,
            20 => b'_' as i32,
            21 => b'+' as i32,
            10 => b'!' as i32,
            11 => b'@' as i32,
            12 => b'#' as i32,
            13 => b'$' as i32,
            14 => b'%' as i32,
            15 => b'^' as i32,
            16 => b'&' as i32,
            17 => b'*' as i32,
            18 => b'(' as i32,
            19 => b')' as i32,
            _ => VOID,
        };
    }
    match keycode {
        9 => 0xff1b,  // Escape
        22 => 0xff08, // BackSpace
        23 => 0xff09, // Tab
        36 | 104 => 0xff0d, // Return (104 is keypad Enter)
        37 => 0xffe3, // Control_L
        38 => b'a' as i32,
        39 => b's' as i32,
        40 => b'd' as i32,
        41 => b'f' as i32,
        42 => b'g' as i32,
        43 => b'h' as i32,
        44 => b'j' as i32,
        45 => b'k' as i32,
        46 => b'l' as i32,
        50 => 0xffe1, // Shift_L
        52 => b'z' as i32,
        53 => b'x' as i32,
        54 => b'c' as i32,
        55 => b'v' as i32,
        56 => b'b' as i32,
        57 => b'n' as i32,
        58 => b'm' as i32,
        65 => 0x20, // space
        20 => b'-' as i32,
        21 => b'=' as i32,
        10..=19 => b'1' as i32 + (keycode as i32 - 10),
        // Top letter row, spelled out: qwerty is NOT contiguous in ASCII,
        // so `b'q' + offset` decodes o as y (and w as r, e as s, ...).
        24 => b'q' as i32,
        25 => b'w' as i32,
        26 => b'e' as i32,
        27 => b'r' as i32,
        28 => b't' as i32,
        29 => b'y' as i32,
        30 => b'u' as i32,
        31 => b'i' as i32,
        32 => b'o' as i32,
        33 => b'p' as i32,
        34 => b'[' as i32,
        35 => b']' as i32,
        47 => b';' as i32,
        48 => b'\'' as i32,
        49 => b'`' as i32,
        51 => b'\\' as i32,
        59 => b',' as i32,
        60 => b'.' as i32,
        61 => b'/' as i32,
        111 | 110 => 0xff51, // Up, Down
        113 | 114 => 0xff52, // Left, Right
        119 => 0xff50,       // Home
        112 => 0xff55,       // Prior / Page Up
        117 => 0xff57,       // End
        116 => 0xff54,       // Next / Page Down
        _ => VOID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The top letter row is not ASCII-contiguous; arithmetic here once
    /// decoded "google.com" as "gy..." (o->y, e->s).
    #[test]
    fn keysym_decodes_a_url() {
        let word: String = [42, 32, 32, 42, 46, 26, 60, 54, 32, 58]
            .iter()
            .map(|&kc| keysym(kc, false) as u8 as char)
            .collect();
        assert_eq!(word, "google.com");
    }

    #[test]
    fn keysym_maps_both_enter_keys() {
        assert_eq!(keysym(36, false), 0xff0d);
        assert_eq!(keysym(104, false), 0xff0d);
    }

    #[test]
    fn keysym_shift_selects_upper_symbols() {
        // https:// needs Shift for the colon (and the host for capitals).
        assert_eq!(keysym(47, true), b':' as i32);
        assert_eq!(keysym(42, true), b'G' as i32);
        assert_eq!(keysym(10, true), b'!' as i32);
        assert_eq!(keysym(47, false), b';' as i32);
    }
}

/// Writes every byte, treating a short write as an error.
fn write_all(s: &mut UnixStream, buf: &[u8]) -> Option<()> {
    let mut off = 0;
    while off < buf.len() {
        match s.write(&buf[off..]) {
            Ok(0) => return None,
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(())
}
