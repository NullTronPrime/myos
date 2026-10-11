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
/// Pixel format identifier: ARGB8888 (with alpha).
pub const FORMAT_ARGB8888: u32 = 1;

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
    /// If `alpha` is true, treats pixels as ARGB8888 and blends.
    pub fn blit(&mut self, x: i32, y: i32, src: &Framebuffer) {
        self.blit_pixels(x, y, src.width, src.height, src.pixels());
    }

    /// Copies a `w * h` block of pixels, clipped to the surface.
    ///
    /// The block is read row-major; `src` must hold at least `w * h` pixels.
    /// If `alpha` is true, treats pixels as ARGB8888 and blends them.
    pub fn blit_pixels(&mut self, x: i32, y: i32, w: u32, h: u32, src: &[u32]) {
        self.blit_pixels_alpha(x, y, w, h, src, false);
    }

    /// Copies a `w * h` block of pixels with optional alpha blending.
    pub fn blit_pixels_alpha(&mut self, x: i32, y: i32, w: u32, h: u32, src: &[u32], alpha: bool) {
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
                let src_px = src[row as usize * w as usize + col as usize];
                let dst_idx = dy as usize * self.width as usize + dx as usize;
                if alpha {
                    let a = (src_px >> 24) as u32;
                    if a == 0 {
                        continue; // fully transparent
                    }
                    if a == 255 {
                        self.pixels[dst_idx] = src_px;
                    } else {
                        let dst = self.pixels[dst_idx];
                        let sr = (src_px >> 16) & 0xff;
                        let sg = (src_px >> 8) & 0xff;
                        let sb = src_px & 0xff;
                        let dr = (dst >> 16) & 0xff;
                        let dg = (dst >> 8) & 0xff;
                        let db = dst & 0xff;
                        let inv_a = 255 - a;
                        let r = (sr * a + dr * inv_a) / 255;
                        let g = (sg * a + dg * inv_a) / 255;
                        let b = (sb * a + db * inv_a) / 255;
                        self.pixels[dst_idx] = (a << 24) | (r << 16) | (g << 8) | b;
                    }
                } else {
                    self.pixels[dst_idx] = src_px;
                }
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
    /// A newline returns to `x` and drops one line. If `max_width` is
    /// Some(w), wraps text at `w` pixels.
    pub fn draw_text(&mut self, x: i32, y: i32, text: &str, fg: u32, bg: Option<u32>) {
        self.draw_text_wrapped(x, y, text, fg, bg, None);
    }

    /// Draws a string with optional wrapping at `max_width` pixels.
    pub fn draw_text_wrapped(&mut self, x: i32, y: i32, text: &str, fg: u32, bg: Option<u32>, max_width: Option<u32>) {
        let mut cx = x;
        let mut cy = y;
        for ch in text.chars() {
            if ch == '\n' {
                cx = x;
                cy += GLYPH_HEIGHT as i32;
                continue;
            }
            if let Some(mw) = max_width {
                if cx + GLYPH_WIDTH as i32 > x + mw as i32 {
                    cx = x;
                    cy += GLYPH_HEIGHT as i32;
                }
            }
            self.draw_char(cx, cy, ch, fg, bg);
            cx += GLYPH_WIDTH as i32;
        }
    }

    /// Draws a text cursor (vertical bar) at the given position.
    pub fn draw_text_cursor(&mut self, x: i32, y: i32, fg: u32) {
        self.fill_rect(x, y, 2, GLYPH_HEIGHT, fg);
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

/// Default cursor dimensions.
pub const CURSOR_WIDTH: u32 = 12;
pub const CURSOR_HEIGHT: u32 = 18;

/// Draws a simple arrow cursor at (x, y).
pub fn draw_cursor(fb: &mut Framebuffer, x: i32, y: i32) {
    // Simple arrow cursor shape
    const CURSOR: [[u32; CURSOR_WIDTH as usize]; CURSOR_HEIGHT as usize] = [
        [0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
        [0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01],
        [0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x00],
        [0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x00, 0x00],
        [0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00],
        [0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x01, 0x02, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x01, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    for (row, row_data) in CURSOR.iter().enumerate() {
        for (col, _) in row_data.iter().enumerate() {
            let px = x + col as i32;
            let py = y + row as i32;
            if px >= 0 && px < fb.width() as i32 && py >= 0 && py < fb.height() as i32 {
                let color = CURSOR[row][col];
                if color == 0 {
                    // Transparent - skip
                } else if color == 1 {
                    fb.set(px, py, 0x00FFFFFF); // White
                } else {
                    fb.set(px, py, 0x00000000); // Black
                }
            }
        }
    }
}

/// Draws window decorations (title bar, border) for a window.
pub fn draw_decorations(fb: &mut Framebuffer, win: &Window) {
    if win.minimized {
        return;
    }
    const TITLE_BAR_HEIGHT: u32 = 20;
    const BORDER_WIDTH: u32 = 2;
    let body_h = win.height.saturating_sub(TITLE_BAR_HEIGHT);
    // Draw title bar background
    fb.fill_rect(win.x, win.y, win.width, TITLE_BAR_HEIGHT, 0x00303040);
    // Draw title text
    let title = std::str::from_utf8(&win.title[..win.title_len as usize]).unwrap_or("");
    fb.draw_text(win.x + 4, win.y + 4, title, 0x00FFFFFF, None);
    // Draw border
    fb.fill_rect(win.x, win.y + TITLE_BAR_HEIGHT as i32, BORDER_WIDTH, body_h, 0x00404050);
    fb.fill_rect(win.x + win.width as i32 - BORDER_WIDTH as i32, win.y + TITLE_BAR_HEIGHT as i32, BORDER_WIDTH, body_h, 0x00404050);
    fb.fill_rect(win.x, win.y + win.height as i32 - BORDER_WIDTH as i32, win.width, BORDER_WIDTH, 0x00404050);
    // Draw close button
    fb.fill_rect(win.x + win.width as i32 - 16, win.y + 2, 12, 12, 0x00FF4040);
    fb.draw_text(win.x + win.width as i32 - 14, win.y + 4, "X", 0x00FFFFFF, None);
}

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
    /// Z-order index (higher = more on top).
    pub z: u32,
    /// Whether the window has input focus.
    pub focused: bool,
    /// Whether the window is minimized.
    pub minimized: bool,
    /// Title text (for decorations).
    pub title: [u8; 64],
    /// Title length.
    pub title_len: u32,
    /// Dirty region: x, y, w, h. (0,0,0,0) = clean.
    pub dirty_x: i32,
    pub dirty_y: i32,
    pub dirty_w: u32,
    pub dirty_h: u32,
    /// Whether the window buffer has been modified since last composite.
    pub dirty: bool,
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
            z: self.windows.len() as u32,
            focused: false,
            minimized: false,
            title: [0u8; 64],
            title_len: 0,
            dirty_x: 0,
            dirty_y: 0,
            dirty_w: 0,
            dirty_h: 0,
            dirty: true,
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
        let max_z = self.windows.iter().map(|w| w.z).max().unwrap_or(0);
        self.windows[i].z = max_z + 1;
        let w = self.windows.remove(i);
        self.windows.push(w);
        Ok(())
    }

    /// Marks a window's entire buffer as dirty.
    pub fn mark_dirty(&mut self, id: u32) {
        if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
            w.dirty = true;
            w.dirty_x = w.x;
            w.dirty_y = w.y;
            w.dirty_w = w.width;
            w.dirty_h = w.height;
        }
    }

    /// Marks a sub-rectangle of a window as dirty.
    pub fn mark_dirty_rect(&mut self, id: u32, x: i32, y: i32, w: u32, h: u32) {
        if let Some(win) = self.windows.iter_mut().find(|w| w.id == id) {
            win.dirty = true;
            if win.dirty_w == 0 || win.dirty_h == 0 {
                win.dirty_x = x;
                win.dirty_y = y;
                win.dirty_w = w;
                win.dirty_h = h;
            } else {
                let x0 = win.dirty_x.min(x);
                let y0 = win.dirty_y.min(y);
                let x1 = (win.dirty_x + win.dirty_w as i32).max(x + w as i32);
                let y1 = (win.dirty_y + win.dirty_h as i32).max(y + h as i32);
                win.dirty_x = x0;
                win.dirty_y = y0;
                win.dirty_w = (x1 - x0) as u32;
                win.dirty_h = (y1 - y0) as u32;
            }
        }
    }

    /// Clears a window's dirty flag after compositing.
    pub fn clear_dirty(&mut self, id: u32) {
        if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
            w.dirty = false;
            w.dirty_w = 0;
            w.dirty_h = 0;
        }
    }

    /// Returns the topmost visible window at (x, y), or None.
    pub fn hit_test(&self, x: i32, y: i32) -> Option<u32> {
        let mut best_z: Option<u32> = None;
        let mut best_id: Option<u32> = None;
        for w in &self.windows {
            if !w.visible || w.minimized || w.buffer == 0 {
                continue;
            }
            if x >= w.x && x < w.x + w.width as i32 &&
               y >= w.y && y < w.y + w.height as i32 {
                if best_z.map_or(true, |z| w.z >= z) {
                    best_z = Some(w.z);
                    best_id = Some(w.id);
                }
            }
        }
        best_id
    }

    /// Sets a window's z-order index.
    pub fn set_z(&mut self, id: u32, z: u32) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        self.windows[i].z = z;
        Ok(())
    }

    /// Lowers a window below all others.
    pub fn lower(&mut self, id: u32) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        let min_z = self.windows.iter().map(|w| w.z).min().unwrap_or(0);
        self.windows[i].z = min_z.saturating_sub(1);
        // Move to front of vector (bottom of paint order)
        let w = self.windows.remove(i);
        self.windows.insert(0, w);
        Ok(())
    }

    /// Toggles a window's minimized state.
    pub fn toggle_minimize(&mut self, id: u32) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        self.windows[i].minimized = !self.windows[i].minimized;
        Ok(())
    }

    /// Sets a window's title.
    pub fn set_title(&mut self, id: u32, title: &str) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        let n = title.len().min(63);
        self.windows[i].title[..n].copy_from_slice(&title.as_bytes()[..n]);
        self.windows[i].title[n] = 0;
        self.windows[i].title_len = n as u32;
        Ok(())
    }

    /// Resizes a window and returns the new buffer address.
    pub fn resize(&mut self, id: u32, width: u32, height: u32) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        self.windows[i].width = width;
        self.windows[i].height = height;
        self.windows[i].dirty = true;
        self.windows[i].dirty_x = self.windows[i].x;
        self.windows[i].dirty_y = self.windows[i].y;
        self.windows[i].dirty_w = width;
        self.windows[i].dirty_h = height;
        Ok(())
    }

    /// Gives input focus to one window, clearing it from all others.
    ///
    /// Focus is what decides where routed keyboard events go in Phase 2.2.
    /// Focusing a minimized or invisible window is allowed: visibility
    /// controls compositing, not event routing.
    pub fn set_focus(&mut self, id: u32) -> Result<(), Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        for (k, w) in self.windows.iter_mut().enumerate() {
            w.focused = k == i;
        }
        Ok(())
    }

    /// Which window currently has input focus, if any.
    pub fn focused(&self) -> Option<u32> {
        self.windows.iter().find(|w| w.focused).map(|w| w.id)
    }

    /// Removes a window, returning its buffer address for unmapping.
    pub fn destroy(&mut self, id: u32) -> Result<u64, Errno> {
        let i = self.index(id).ok_or(Errno::NoEnt)?;
        let was_focused = self.windows[i].focused;
        let buf = self.windows.remove(i).buffer;
        // Destroying the focused window must not leave a dangling focus.
        // Hand focus to the new topmost window, if one remains.
        if was_focused {
            if let Some(top) = self.windows.last_mut() {
                top.focused = true;
            }
        }
        Ok(buf)
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

    #[test]
    fn draw_text_wrapped_wraps_at_max_width() {
        let mut fb = Framebuffer::new(32, 16);
        fb.draw_text_wrapped(0, 0, "ABCDEF", rgb(255, 255, 255), Some(rgb(0, 0, 0)), Some(24));
        // 'A' at (2,0), 'B' at (10,0), 'C' at (18,0) — 3 chars fit in 24px.
        assert_eq!(fb.get(2, 0), Some(rgb(255, 255, 255)), "'A' at x=2");
        assert_eq!(fb.get(10, 0), Some(rgb(255, 255, 255)), "'B' at x=10");
        assert_eq!(fb.get(18, 0), Some(rgb(255, 255, 255)), "'C' at x=18");
        // 'D' wraps to next line (y=8) because x=24 exceeds max_width=24.
        assert_eq!(fb.get(2, 8), Some(rgb(255, 255, 255)), "'D' wrapped to y=8");
    }

    #[test]
    fn draw_text_cursor_draws_vertical_bar() {
        let mut fb = Framebuffer::new(8, 8);
        fb.draw_text_cursor(2, 0, rgb(255, 255, 255));
        assert_eq!(fb.get(2, 0), Some(rgb(255, 255, 255)));
        assert_eq!(fb.get(3, 0), Some(rgb(255, 255, 255)));
        assert_eq!(fb.get(2, 7), Some(rgb(255, 255, 255)));
        assert_eq!(fb.get(4, 0), Some(0), "cursor is only 2px wide");
    }

    #[test]
    fn alpha_blending_works_correctly() {
        let mut dst = Framebuffer::new(2, 1);
        dst.set(0, 0, rgb(255, 0, 0)); // Red background
        let mut src = Framebuffer::new(1, 1);
        src.set(0, 0, 0x800000FF); // 50% opaque blue
        dst.blit_pixels_alpha(0, 0, 1, 1, src.pixels(), true);
        // 50% blend of red (255,0,0) and blue (0,0,255) = (127,0,127)
        let result = dst.get(0, 0).unwrap();
        let r = (result >> 16) & 0xff;
        let b = result & 0xff;
        assert!(r > 100 && r < 150, "red channel should be ~127, got {r}");
        assert!(b > 100 && b < 150, "blue channel should be ~127, got {b}");
    }

    #[test]
    fn hit_test_finds_topmost_window() {
        let mut d = Display::new(100, 100);
        let a = d.create(30, 30).unwrap();
        let b = d.create(30, 30).unwrap();
        d.map(a, 0x1000).unwrap();
        d.map(b, 0x2000).unwrap();
        d.move_to(a, 0, 0).unwrap();
        d.move_to(b, 0, 0).unwrap();
        d.show(a).unwrap();
        d.show(b).unwrap();
        // b is on top (created later, higher z)
        assert_eq!(d.hit_test(15, 15), Some(b));
        d.raise(a).unwrap();
        assert_eq!(d.hit_test(15, 15), Some(a));
    }

    #[test]
    fn hit_test_skips_invisible_and_minimized() {
        let mut d = Display::new(100, 100);
        let a = d.create(10, 10).unwrap();
        d.map(a, 0x1000).unwrap();
        d.show(a).unwrap();
        assert_eq!(d.hit_test(5, 5), Some(a));
        d.toggle_minimize(a).unwrap();
        assert_eq!(d.hit_test(5, 5), None, "minimized window should not be hit");
    }

    #[test]
    fn lower_moves_window_below_others() {
        let mut d = Display::new(100, 100);
        let a = d.create(10, 10).unwrap();
        let b = d.create(10, 10).unwrap();
        d.map(a, 0x1000).unwrap();
        d.map(b, 0x2000).unwrap();
        d.show(a).unwrap();
        d.show(b).unwrap();
        d.move_to(a, 0, 0).unwrap();
        d.move_to(b, 0, 0).unwrap();
        assert_eq!(d.hit_test(5, 5), Some(b));
        d.lower(a).unwrap();
        assert_eq!(d.hit_test(5, 5), Some(b));
        d.raise(a).unwrap();
        assert_eq!(d.hit_test(5, 5), Some(a));
    }

    #[test]
    fn damage_tracking_marks_and_clears() {
        let mut d = Display::new(100, 100);
        let id = d.create(10, 10).unwrap();
        assert!(d.get(id).unwrap().dirty, "new window starts dirty");
        d.clear_dirty(id);
        assert!(!d.get(id).unwrap().dirty);
        d.mark_dirty(id);
        assert!(d.get(id).unwrap().dirty);
        d.mark_dirty_rect(id, 2, 3, 4, 5);
        let w = d.get(id).unwrap();
        assert!(w.dirty);
    }

    #[test]
    fn resize_marks_window_dirty() {
        let mut d = Display::new(100, 100);
        let id = d.create(10, 10).unwrap();
        d.clear_dirty(id);
        d.resize(id, 20, 30).unwrap();
        let w = d.get(id).unwrap();
        assert_eq!(w.width, 20);
        assert_eq!(w.height, 30);
        assert!(w.dirty, "resize should mark dirty");
    }

    #[test]
    fn focus_moves_between_windows_and_follows_destroy() {
        let mut d = Display::new(100, 100);
        assert_eq!(d.focused(), None);
        let a = d.create(10, 10).unwrap();
        let b = d.create(10, 10).unwrap();
        d.set_focus(a).unwrap();
        assert_eq!(d.focused(), Some(a));
        assert!(d.get(a).unwrap().focused);
        assert!(!d.get(b).unwrap().focused);
        d.set_focus(b).unwrap();
        assert_eq!(d.focused(), Some(b));
        assert_eq!(d.set_focus(999), Err(Errno::NoEnt));
        // Destroying the focused window hands focus to the survivor.
        d.destroy(b).unwrap();
        assert_eq!(d.focused(), Some(a));
    }

    #[test]
    fn set_title_stores_a_nul_terminated_name() {
        let mut d = Display::new(100, 100);
        let id = d.create(10, 10).unwrap();
        d.set_title(id, "Terminal").unwrap();
        let w = d.get(id).unwrap();
        assert_eq!(w.title_len, 8);
        assert_eq!(&w.title[..8], b"Terminal");
        assert_eq!(w.title[8], 0);
        assert_eq!(d.set_title(999, "x"), Err(Errno::NoEnt));
    }
}
