//! A pure, host-testable pixel model: framebuffer primitives, a window model,
//! and PPM serialisation.
//!
//! The guest and the host share one address space, so the pixels a guest writes
//! through a mapped window buffer are real host bytes. Everything here is plain
//! arithmetic over `u32` pixels so the compositor can be tested without a
//! display, a GPU, or even an operating system.
//!
//! Pixels are `0x00RRGGBB` (XRGB8888): byte order in memory is B, G, R, X on
//! little-endian, matching Linux's `DRM_FORMAT_XRGB8888`.

use crate::vfs::Errno;

/// Pixel format identifier reported to the guest: XRGB8888.
pub const FORMAT_XRGB8888: u32 = 0;

/// The colour the compositor clears the screen to before drawing windows.
pub const BACKGROUND: u32 = 0x0010_1418;

/// Largest window the model will create, in pixels, to bound allocations.
const MAX_WINDOW_PIXELS: u64 = 16 * 1024 * 1024;

/// Packs 8-bit channels into a pixel.
pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// A rectangular array of XRGB8888 pixels, row-major from the top left.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Framebuffer {
    width: u32,
    height: u32,
    pixels: Vec<u32>,
}

impl Framebuffer {
    /// Allocates a `width * height` surface, cleared to black.
    ///
    /// A zero dimension yields an empty surface rather than a panic, so callers
    /// can validate as they see fit.
    pub fn new(width: u32, height: u32) -> Self {
        let len = (width as usize).saturating_mul(height as usize);
        Framebuffer {
            width,
            height,
            pixels: vec![0; len],
        }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    /// Pixels in row-major order.
    pub fn pixels(&self) -> &[u32] {
        &self.pixels
    }

    /// Mutable pixel storage, for loading a surface from a guest buffer.
    pub fn pixels_mut(&mut self) -> &mut [u32] {
        &mut self.pixels
    }

    /// Number of pixels.
    pub fn len(&self) -> usize {
        self.pixels.len()
    }

    /// True when the surface holds no pixels.
    pub fn is_empty(&self) -> bool {
        self.pixels.is_empty()
    }

    /// Fills every pixel with `color`.
    pub fn clear(&mut self, color: u32) {
        self.pixels.fill(color);
    }

    /// Writes one pixel, silently ignoring coordinates outside the surface.
    pub fn set(&mut self, x: i32, y: i32, color: u32) {
        if x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return;
        }
        let idx = y as usize * self.width as usize + x as usize;
        self.pixels[idx] = color;
    }

    /// Reads one pixel, or `None` when outside the surface.
    pub fn get(&self, x: i32, y: i32) -> Option<u32> {
        if x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return None;
        }
        Some(self.pixels[y as usize * self.width as usize + x as usize])
    }

    /// Fills an axis-aligned rectangle, clipped to the surface.
    pub fn fill_rect(&mut self, x: i32, y: i32, w: u32, h: u32, color: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let x0 = x.max(0);
        let y0 = y.max(0);
        let x1 = (x.saturating_add(w as i32)).min(self.width as i32);
        let y1 = (y.saturating_add(h as i32)).min(self.height as i32);
        for yy in y0..y1 {
            let row = yy as usize * self.width as usize;
            for xx in x0..x1 {
                self.pixels[row + xx as usize] = color;
            }
        }
    }

    /// Copies `src` onto this surface with its top-left at `(x, y)`, clipped.
    pub fn blit(&mut self, x: i32, y: i32, src: &Framebuffer) {
        self.blit_pixels(x, y, src.width, src.height, src.pixels());
    }

    /// Copies a `w * h` block of pixels, clipped to the surface.
    ///
    /// The block is read row-major; `src` must hold at least `w * h` pixels.
    pub fn blit_pixels(&mut self, x: i32, y: i32, w: u32, h: u32, src: &[u32]) {
        if w == 0 || h == 0 {
            return;
        }
        let need = (w as usize).saturating_mul(h as usize);
        if src.len() < need {
            return;
        }
        for row in 0..h as i32 {
            let dy = y.saturating_add(row);
            if dy < 0 || dy >= self.height as i32 {
                continue;
            }
            for col in 0..w as i32 {
                let dx = x.saturating_add(col);
                if dx < 0 || dx >= self.width as i32 {
                    continue;
                }
                self.pixels[dy as usize * self.width as usize + dx as usize] =
                    src[row as usize * w as usize + col as usize];
            }
        }
    }

    /// Draws one 8x8 glyph with its top-left at `(x, y)`.
    ///
    /// `bg` fills the whole cell; `None` leaves existing pixels untouched, so
    /// text can be drawn over a scene. Unknown characters render as a blank
    /// cell.
    pub fn draw_char(&mut self, x: i32, y: i32, ch: char, fg: u32, bg: Option<u32>) {
        let bits = glyph(ch).unwrap_or([0u8; GLYPH_HEIGHT as usize]);
        for row in 0..GLYPH_HEIGHT {
            let line = bits[row as usize];
            for col in 0..GLYPH_WIDTH {
                let color = if line & (1 << col) != 0 { Some(fg) } else { bg };
                if let Some(c) = color {
                    self.set(x + col as i32, y + row as i32, c);
                }
            }
        }
    }

    /// Draws a string, advancing one glyph cell per character.
    ///
    /// A newline returns to `x` and drops one line.
    pub fn draw_text(&mut self, x: i32, y: i32, text: &str, fg: u32, bg: Option<u32>) {
        let mut cx = x;
        let mut cy = y;
        for ch in text.chars() {
            if ch == '\n' {
                cx = x;
                cy += GLYPH_HEIGHT as i32;
                continue;
            }
            self.draw_char(cx, cy, ch, fg, bg);
            cx += GLYPH_WIDTH as i32;
        }
    }

    /// Serialises to a binary PPM (P6), row-major top-to-bottom.
    pub fn to_ppm(&self) -> Vec<u8> {
        let mut out = format!("P6\n{} {}\n255\n", self.width, self.height).into_bytes();
        out.reserve(self.pixels.len() * 3);
        for &px in &self.pixels {
            out.push((px >> 16) as u8);
            out.push((px >> 8) as u8);
            out.push(px as u8);
        }
        out
    }
}

/// Width of one glyph cell in pixels.
pub const GLYPH_WIDTH: u32 = 8;

/// Height of one glyph cell in pixels.
pub const GLYPH_HEIGHT: u32 = 8;

/// Bitmap for a printable ASCII character, or `None` outside `0x20..=0x7E`.
///
/// Each byte is one row from the top and bit 0 is the leftmost pixel.
pub fn glyph(ch: char) -> Option<[u8; 8]> {
    let c = ch as u32;
    if !(0x20..=0x7E).contains(&c) {
        return None;
    }
    Some(FONT8X8[(c - 0x20) as usize])
}

/// Width in pixels of the longest line of `text`.
pub fn text_width(text: &str) -> u32 {
    text.split('\n')
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0) as u32
        * GLYPH_WIDTH
}

/// The public-domain `font8x8_basic` set, ASCII `0x20..=0x7E`.
const FONT8X8: [[u8; 8]; 95] = [
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // space
    [0x18, 0x3C, 0x3C, 0x18, 0x18, 0x00, 0x18, 0x00], // !
    [0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // "
    [0x36, 0x36, 0x7F, 0x36, 0x7F, 0x36, 0x36, 0x00], // #
    [0x0C, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x0C, 0x00], // $
    [0x00, 0x63, 0x33, 0x18, 0x0C, 0x66, 0x63, 0x00], // %
    [0x1C, 0x36, 0x1C, 0x6E, 0x3B, 0x33, 0x6E, 0x00], // &
    [0x06, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00], // '
    [0x18, 0x0C, 0x06, 0x06, 0x06, 0x0C, 0x18, 0x00], // (
    [0x06, 0x0C, 0x18, 0x18, 0x18, 0x0C, 0x06, 0x00], // )
    [0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00], // *
    [0x00, 0x0C, 0x0C, 0x3F, 0x0C, 0x0C, 0x00, 0x00], // +
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x06], // ,
    [0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00], // -
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x00], // .
    [0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x01, 0x00], // /
    [0x3E, 0x63, 0x73, 0x7B, 0x6F, 0x67, 0x3E, 0x00], // 0
    [0x0C, 0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x3F, 0x00], // 1
    [0x1E, 0x33, 0x30, 0x1C, 0x06, 0x33, 0x3F, 0x00], // 2
    [0x1E, 0x33, 0x30, 0x1C, 0x30, 0x33, 0x1E, 0x00], // 3
    [0x38, 0x3C, 0x36, 0x33, 0x7F, 0x30, 0x78, 0x00], // 4
    [0x3F, 0x03, 0x1F, 0x30, 0x30, 0x33, 0x1E, 0x00], // 5
    [0x1C, 0x06, 0x03, 0x1F, 0x33, 0x33, 0x1E, 0x00], // 6
    [0x3F, 0x33, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x00], // 7
    [0x1E, 0x33, 0x33, 0x1E, 0x33, 0x33, 0x1E, 0x00], // 8
    [0x1E, 0x33, 0x33, 0x3F, 0x30, 0x18, 0x0E, 0x00], // 9
    [0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x00], // :
    [0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x06], // ;
    [0x18, 0x0C, 0x06, 0x03, 0x06, 0x0C, 0x18, 0x00], // <
    [0x00, 0x00, 0x3F, 0x00, 0x00, 0x3F, 0x00, 0x00], // =
    [0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00], // >
    [0x1E, 0x33, 0x30, 0x18, 0x0C, 0x00, 0x0C, 0x00], // ?
    [0x3E, 0x63, 0x7B, 0x7B, 0x7B, 0x03, 0x1E, 0x00], // @
    [0x0C, 0x1E, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x00], // A
    [0x3F, 0x66, 0x66, 0x3E, 0x66, 0x66, 0x3F, 0x00], // B
    [0x3C, 0x66, 0x03, 0x03, 0x03, 0x66, 0x3C, 0x00], // C
    [0x1F, 0x36, 0x66, 0x66, 0x66, 0x36, 0x1F, 0x00], // D
    [0x7F, 0x46, 0x16, 0x1E, 0x16, 0x46, 0x7F, 0x00], // E
    [0x7F, 0x46, 0x16, 0x1E, 0x16, 0x06, 0x0F, 0x00], // F
    [0x3C, 0x66, 0x03, 0x03, 0x73, 0x66, 0x7C, 0x00], // G
    [0x33, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x33, 0x00], // H
    [0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // I
    [0x78, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E, 0x00], // J
    [0x67, 0x66, 0x36, 0x1E, 0x36, 0x66, 0x67, 0x00], // K
    [0x0F, 0x06, 0x06, 0x06, 0x46, 0x66, 0x7F, 0x00], // L
    [0x63, 0x77, 0x7F, 0x7F, 0x6B, 0x63, 0x63, 0x00], // M
    [0x63, 0x67, 0x6F, 0x7B, 0x73, 0x63, 0x63, 0x00], // N
    [0x1C, 0x36, 0x63, 0x63, 0x63, 0x36, 0x1C, 0x00], // O
    [0x3F, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x0F, 0x00], // P
    [0x1E, 0x33, 0x33, 0x33, 0x3B, 0x1E, 0x38, 0x00], // Q
    [0x3F, 0x66, 0x66, 0x3E, 0x36, 0x66, 0x67, 0x00], // R
    [0x1E, 0x33, 0x07, 0x0E, 0x38, 0x33, 0x1E, 0x00], // S
    [0x3F, 0x2D, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // T
    [0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x3F, 0x00], // U
    [0x33, 0x33, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00], // V
    [0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00], // W
    [0x63, 0x63, 0x36, 0x1C, 0x1C, 0x36, 0x63, 0x00], // X
    [0x33, 0x33, 0x33, 0x1E, 0x0C, 0x0C, 0x1E, 0x00], // Y
    [0x7F, 0x63, 0x31, 0x18, 0x4C, 0x66, 0x7F, 0x00], // Z
    [0x1E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x1E, 0x00], // [
    [0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00], // backslash
    [0x1E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1E, 0x00], // ]
    [0x08, 0x1C, 0x36, 0x63, 0x00, 0x00, 0x00, 0x00], // ^
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF], // _
    [0x0C, 0x0C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00], // `
    [0x00, 0x00, 0x1E, 0x30, 0x3E, 0x33, 0x6E, 0x00], // a
    [0x07, 0x06, 0x06, 0x3E, 0x66, 0x66, 0x3B, 0x00], // b
    [0x00, 0x00, 0x1E, 0x33, 0x03, 0x33, 0x1E, 0x00], // c
    [0x38, 0x30, 0x30, 0x3E, 0x33, 0x33, 0x6E, 0x00], // d
    [0x00, 0x00, 0x1E, 0x33, 0x3F, 0x03, 0x1E, 0x00], // e
    [0x1C, 0x36, 0x06, 0x0F, 0x06, 0x06, 0x0F, 0x00], // f
    [0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x1F], // g
    [0x07, 0x06, 0x36, 0x6E, 0x66, 0x66, 0x67, 0x00], // h
    [0x0C, 0x00, 0x0E, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // i
    [0x30, 0x00, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E], // j
    [0x07, 0x06, 0x66, 0x36, 0x1E, 0x36, 0x67, 0x00], // k
    [0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // l
    [0x00, 0x00, 0x33, 0x7F, 0x7F, 0x6B, 0x63, 0x00], // m
    [0x00, 0x00, 0x1F, 0x33, 0x33, 0x33, 0x33, 0x00], // n
    [0x00, 0x00, 0x1E, 0x33, 0x33, 0x33, 0x1E, 0x00], // o
    [0x00, 0x00, 0x3B, 0x66, 0x66, 0x3E, 0x06, 0x0F], // p
    [0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x78], // q
    [0x00, 0x00, 0x3B, 0x6E, 0x66, 0x06, 0x0F, 0x00], // r
    [0x00, 0x00, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x00], // s
    [0x08, 0x0C, 0x3E, 0x0C, 0x0C, 0x2C, 0x18, 0x00], // t
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x33, 0x6E, 0x00], // u
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00], // v
    [0x00, 0x00, 0x63, 0x6B, 0x7F, 0x7F, 0x36, 0x00], // w
    [0x00, 0x00, 0x63, 0x36, 0x1C, 0x36, 0x63, 0x00], // x
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x3E, 0x30, 0x1F], // y
    [0x00, 0x00, 0x3F, 0x19, 0x0C, 0x26, 0x3F, 0x00], // z
    [0x38, 0x0C, 0x0C, 0x07, 0x0C, 0x0C, 0x38, 0x00], // {
    [0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00], // |
    [0x07, 0x0C, 0x0C, 0x38, 0x0C, 0x0C, 0x07, 0x00], // }
    [0x6E, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // ~
];

/// One window's placement on the display.
///
/// The pixels live in a guest-mapped buffer whose address is `buffer`; the model
/// only tracks where the buffer is and how it is composited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Window {
    /// Identifies the window for the guest's later calls.
    pub id: u32,
    /// Top-left position on the display.
    pub x: i32,
    pub y: i32,
    /// Size in pixels.
    pub width: u32,
    pub height: u32,
    /// Guest address of the pixel buffer, or 0 until mapped.
    pub buffer: u64,
    /// Whether the window is composited.
    pub visible: bool,
}

impl Window {
    /// Size of the pixel buffer in bytes.
    pub fn byte_len(&self) -> u64 {
        (self.width as u64)
            .saturating_mul(self.height as u64)
            .saturating_mul(4)
    }

    fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// Default display size when none is configured.
pub const DEFAULT_WIDTH: u32 = 640;
/// Default display height when none is configured.
pub const DEFAULT_HEIGHT: u32 = 480;

/// The window model: a display size and an ordered stack of windows.
///
/// Windows are stored back-to-front, so the last element is on top. `create`
/// and `raise` maintain that invariant, and compositing walks the list in order.
#[derive(Clone, Debug)]
pub struct Display {
    width: u32,
    height: u32,
    next_id: u32,
    windows: Vec<Window>,
}

impl Default for Display {
    fn default() -> Self {
        Display::new(DEFAULT_WIDTH, DEFAULT_HEIGHT)
    }
}

impl Display {
    /// Builds an empty display.
    pub fn new(width: u32, height: u32) -> Self {
        Display {
            width,
            height,
            next_id: 1,
            windows: Vec::new(),
        }
    }

    /// Display size in pixels.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Windows back-to-front.
    pub fn windows(&self) -> &[Window] {
        &self.windows
    }

    /// Looks a window up by id.
    pub fn get(&self, id: u32) -> Option<&Window> {
        self.windows.iter().find(|w| w.id == id)
    }

    fn index(&self, id: u32) -> Option<usize> {
        self.windows.iter().position(|w| w.id == id)
    }

    /// Creates an unmapped, invisible window on top of the stack.
    pub fn create(&mut self, width: u32, height: u32) -> Result<u32, Errno> {
        if width == 0 || height == 0 {
            return Err(Errno::Inval);
        }
        if (width as u64) * (height as u64) > MAX_WINDOW_PIXELS {
            return Err(Errno::Inval);
        }
        if self.next_id == u32::MAX {
            return Err(Errno::NoMem);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.windows.push(Window {
            id,
            x: 0,
            y: 0,
            width,
            height,
            buffer: 0,
            visible: false,
        });
        Ok(id)
    }

    /// Records the guest address of a window's pixel buffer.
    pub fn map(&mut self, id: u32, buffer: u64) -> Result<(), Errno> {
        if buffer == 0 {
            return Err(Errno::Inval);
        }
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        self.windows[i].buffer = buffer;
        Ok(())
    }

    /// Makes a window visible (composited on the next present).
    pub fn show(&mut self, id: u32) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        if self.windows[i].buffer == 0 {
            return Err(Errno::Inval);
        }
        self.windows[i].visible = true;
        Ok(())
    }

    /// Moves a window.
    pub fn move_to(&mut self, id: u32, x: i32, y: i32) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        self.windows[i].x = x;
        self.windows[i].y = y;
        Ok(())
    }

    /// Moves a window to the top of the stack.
    pub fn raise(&mut self, id: u32) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        let w = self.windows.remove(i);
        self.windows.push(w);
        Ok(())
    }

    /// Removes a window, returning its buffer address for unmapping.
    pub fn destroy(&mut self, id: u32) -> Result<u64, Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        Ok(self.windows.remove(i).buffer)
    }

    /// Composites visible windows onto a fresh background surface.
    ///
    /// `read_buffer` supplies the pixels for a window; returning `None` skips it.
    /// This keeps the model free of any host or guest memory access.
    pub fn composite<F>(&self, mut read_buffer: F) -> Result<Framebuffer, Errno>
    where
        F: FnMut(&Window) -> Result<Vec<u32>, Errno>,
    {
        let mut out = Framebuffer::new(self.width, self.height);
        out.clear(BACKGROUND);
        for win in &self.windows {
            if !win.visible || win.buffer == 0 || win.is_empty() {
                continue;
            }
            let px = read_buffer(win)?;
            out.blit_pixels(win.x, win.y, win.width, win.height, &px);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_and_get_round_trip() {
        let mut fb = Framebuffer::new(4, 3);
        assert_eq!(fb.len(), 12);
        fb.clear(rgb(1, 2, 3));
        assert_eq!(fb.get(0, 0), Some(rgb(1, 2, 3)));
        assert_eq!(fb.get(3, 2), Some(rgb(1, 2, 3)));
    }

    #[test]
    fn set_ignores_out_of_range_coordinates() {
        let mut fb = Framebuffer::new(2, 2);
        fb.set(-1, 0, 0xff0000);
        fb.set(0, 2, 0xff0000);
        fb.set(5, 5, 0xff0000);
        assert!(fb.pixels().iter().all(|p| *p == 0));
        assert_eq!(fb.get(-1, 0), None);
    }

    #[test]
    fn fill_rect_clips_to_the_surface() {
        let mut fb = Framebuffer::new(4, 4);
        fb.fill_rect(-1, -1, 3, 3, rgb(9, 9, 9));
        // The overlap is x in 0..2, y in 0..2.
        assert_eq!(fb.get(0, 0), Some(rgb(9, 9, 9)));
        assert_eq!(fb.get(1, 1), Some(rgb(9, 9, 9)));
        assert_eq!(fb.get(2, 2), Some(0));
    }

    #[test]
    fn blit_places_a_surface_at_an_offset() {
        let mut dst = Framebuffer::new(5, 5);
        let mut src = Framebuffer::new(2, 2);
        src.clear(rgb(200, 100, 50));
        dst.blit(1, 1, &src);
        assert_eq!(dst.get(1, 1), Some(rgb(200, 100, 50)));
        assert_eq!(dst.get(2, 2), Some(rgb(200, 100, 50)));
        assert_eq!(dst.get(0, 0), Some(0));
        assert_eq!(dst.get(3, 3), Some(0));
    }

    #[test]
    fn blit_pixels_rejects_a_short_source() {
        let mut dst = Framebuffer::new(2, 2);
        dst.blit_pixels(0, 0, 2, 2, &[1, 2, 3]);
        assert!(dst.pixels().iter().all(|p| *p == 0));
    }

    #[test]
    fn ppm_header_and_size_are_correct() {
        let mut fb = Framebuffer::new(2, 1);
        fb.set(0, 0, rgb(255, 0, 0));
        fb.set(1, 0, rgb(0, 255, 0));
        let ppm = fb.to_ppm();
        let header = b"P6\n2 1\n255\n";
        assert_eq!(&ppm[..header.len()], header);
        assert_eq!(&ppm[header.len()..], &[255, 0, 0, 0, 255, 0]);
    }

    #[test]
    fn create_rejects_degenerate_and_oversized_windows() {
        let mut d = Display::new(100, 100);
        assert_eq!(d.create(0, 10), Err(Errno::Inval));
        assert_eq!(d.create(10, 0), Err(Errno::Inval));
        assert_eq!(d.create(5000, 5000), Err(Errno::Inval));
        let id = d.create(10, 10).unwrap();
        assert_eq!(d.get(id).unwrap().width, 10);
    }

    #[test]
    fn show_requires_a_mapped_buffer() {
        let mut d = Display::new(100, 100);
        let id = d.create(4, 4).unwrap();
        assert_eq!(d.show(id), Err(Errno::Inval));
        d.map(id, 0x1000).unwrap();
        d.show(id).unwrap();
        assert!(d.get(id).unwrap().visible);
    }

    #[test]
    fn unknown_ids_are_rejected() {
        let mut d = Display::new(100, 100);
        assert_eq!(d.map(7, 0x1000), Err(Errno::NoEnt));
        assert_eq!(d.show(7), Err(Errno::NoEnt));
        assert_eq!(d.move_to(7, 0, 0), Err(Errno::NoEnt));
        assert_eq!(d.raise(7), Err(Errno::NoEnt));
        assert_eq!(d.destroy(7), Err(Errno::NoEnt));
    }

    #[test]
    fn raise_moves_a_window_to_the_top() {
        let mut d = Display::new(100, 100);
        let a = d.create(1, 1).unwrap();
        let b = d.create(1, 1).unwrap();
        d.map(a, 1).unwrap();
        d.map(b, 2).unwrap();
        assert_eq!(d.windows().last().unwrap().id, b);
        d.raise(a).unwrap();
        assert_eq!(d.windows().last().unwrap().id, a);
    }

    #[test]
    fn destroy_returns_the_buffer_to_unmap() {
        let mut d = Display::new(100, 100);
        let id = d.create(2, 2).unwrap();
        d.map(id, 0xdead_beef).unwrap();
        assert_eq!(d.destroy(id), Ok(0xdead_beef));
        assert!(d.get(id).is_none());
    }

    #[test]
    fn composite_draws_windows_back_to_front() {
        let mut d = Display::new(8, 8);
        let under = d.create(4, 4).unwrap();
        let over = d.create(2, 2).unwrap();
        d.map(under, 0x1000).unwrap();
        d.map(over, 0x2000).unwrap();
        d.move_to(under, 0, 0).unwrap();
        d.move_to(over, 0, 0).unwrap();
        d.show(under).unwrap();
        d.show(over).unwrap();

        let fb = d
            .composite(|w| {
                let c = if w.id == under {
                    rgb(10, 0, 0)
                } else {
                    rgb(0, 20, 0)
                };
                Ok(vec![c; (w.width * w.height) as usize])
            })
            .unwrap();
        assert_eq!(fb.get(0, 0), Some(rgb(0, 20, 0)), "top window wins");
        assert_eq!(
            fb.get(3, 3),
            Some(rgb(10, 0, 0)),
            "lower window shows through"
        );
        assert_eq!(fb.get(7, 7), Some(BACKGROUND));
    }

    #[test]
    fn composite_skips_invisible_and_unmapped_windows() {
        let mut d = Display::new(4, 4);
        let id = d.create(4, 4).unwrap();
        d.map(id, 0x1000).unwrap();
        // Mapped but not shown.
        let called = std::cell::Cell::new(false);
        let fb = d
            .composite(|_| {
                called.set(true);
                Ok(vec![0xff00ff; 16])
            })
            .unwrap();
        assert!(!called.get());
        assert_eq!(fb.get(0, 0), Some(BACKGROUND));
    }

    #[test]
    fn glyph_table_covers_printable_ascii() {
        assert_eq!(
            glyph('A'),
            Some([0x0C, 0x1E, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x00])
        );
        assert_eq!(glyph(' '), Some([0u8; 8]));
        assert!(glyph('\n').is_none());
        assert!(glyph('\u{7f}').is_none());
    }

    #[test]
    fn draw_char_sets_lit_pixels_and_background() {
        let mut fb = Framebuffer::new(8, 8);
        fb.draw_char(0, 0, 'A', rgb(255, 255, 255), Some(rgb(0, 0, 0)));
        // Row 0 of 'A' is 0x0C: columns 2 and 3 are lit.
        assert_eq!(fb.get(2, 0), Some(rgb(255, 255, 255)));
        assert_eq!(fb.get(3, 0), Some(rgb(255, 255, 255)));
        assert_eq!(fb.get(0, 0), Some(rgb(0, 0, 0)), "unlit pixel gets bg");
    }

    #[test]
    fn draw_char_transparent_leaves_existing_pixels() {
        let mut fb = Framebuffer::new(8, 8);
        fb.clear(rgb(200, 0, 0));
        fb.draw_char(0, 0, 'A', rgb(255, 255, 255), None);
        assert_eq!(fb.get(2, 0), Some(rgb(255, 255, 255)), "lit pixel");
        assert_eq!(fb.get(0, 0), Some(rgb(200, 0, 0)), "unlit pixel untouched");
    }

    #[test]
    fn draw_text_advances_and_wraps_lines() {
        let mut fb = Framebuffer::new(16, 16);
        fb.draw_text(0, 0, "AB\nCD", rgb(255, 255, 255), Some(rgb(0, 0, 0)));
        // 'A' at column 0, 'B' at column 8 on the first row.
        assert_eq!(fb.get(2, 0), Some(rgb(255, 255, 255)));
        // Row 0 of 'B' is 0x3F: column 5 (offset 8) is lit.
        assert_eq!(fb.get(13, 0), Some(rgb(255, 255, 255)));
        // Second line starts at y = 8.
        assert_eq!(fb.get(2, 8), Some(rgb(255, 255, 255)), "'C' after newline");
        assert_eq!(fb.get(10, 8), Some(rgb(255, 255, 255)), "'D' after newline");
        assert_eq!(text_width("AB\nCDE"), 24);
    }
}
