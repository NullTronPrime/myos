//! Pure terminal screen model for Phase 2.5.
//!
//! The emulator itself runs as a guest (`guest/terminal.c`) and cannot run
//! under `cargo test`. This module is the host-testable mirror of its
//! semantics: a character grid with cursor, colors, scrollback, backspace,
//! and the ANSI CSI subset the guest handles (`A`/`B`/`C`/`D`/`E`/`F`/`G`/
//! `d`/`H`/`J`/`K`/`m`). Keeping the two in sync is a review duty, not a
//! build dependency; the tests here pin the behaviour both must show.

/// One terminal cell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TermCell {
    pub ch: u8,
    pub fg: u8,
    pub bg: u8,
}

impl Default for TermCell {
    fn default() -> Self {
        TermCell {
            ch: b' ',
            fg: 7,
            bg: 0,
        }
    }
}

/// A scrollback-capped character screen.
#[derive(Clone, Debug)]
pub struct TermScreen {
    cols: usize,
    rows: usize,
    cells: Vec<TermCell>,
    cursor_x: usize,
    cursor_y: usize,
    fg: u8,
    bg: u8,
    scrollback: Vec<Vec<TermCell>>,
    scrollback_cap: usize,
}

impl TermScreen {
    /// Builds a blank `cols` x `rows` screen.
    pub fn new(cols: usize, rows: usize) -> Self {
        TermScreen {
            cols: cols.max(1),
            rows: rows.max(1),
            cells: vec![TermCell::default(); cols.max(1) * rows.max(1)],
            cursor_x: 0,
            cursor_y: 0,
            fg: 7,
            bg: 0,
            scrollback: Vec::new(),
            scrollback_cap: 100,
        }
    }

    pub fn cursor(&self) -> (usize, usize) {
        (self.cursor_x, self.cursor_y)
    }

    pub fn colors(&self) -> (u8, u8) {
        (self.fg, self.bg)
    }

    /// Lines currently held in scrollback.
    pub fn scrollback_len(&self) -> usize {
        self.scrollback.len()
    }

    fn clamp(&mut self) {
        self.cursor_x = self.cursor_x.min(self.cols - 1);
        self.cursor_y = self.cursor_y.min(self.rows - 1);
    }

    fn cell_mut(&mut self, x: usize, y: usize) -> &mut TermCell {
        &mut self.cells[y * self.cols + x]
    }

    pub fn cell(&self, x: usize, y: usize) -> TermCell {
        self.cells[y * self.cols + x]
    }

    /// Clears the whole screen and homes the cursor.
    pub fn clear(&mut self) {
        for c in self.cells.iter_mut() {
            *c = TermCell::default();
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
    }

    fn scroll(&mut self) {
        if self.scrollback.len() >= self.scrollback_cap {
            self.scrollback.remove(0);
        }
        self.scrollback.push(self.cells[..self.cols].to_vec());
        self.cells.copy_within(self.cols.., 0);
        let n = self.cells.len() - self.cols;
        for c in self.cells[n..].iter_mut() {
            *c = TermCell::default();
        }
    }

    fn newline(&mut self) {
        self.cursor_x = 0;
        self.cursor_y += 1;
        if self.cursor_y >= self.rows {
            self.scroll();
            self.cursor_y = self.rows - 1;
        }
    }

    /// Erases one cell backwards, as backspace should.
    pub fn backspace(&mut self) {
        if self.cursor_x > 0 {
            self.cursor_x -= 1;
        } else if self.cursor_y > 0 {
            self.cursor_y -= 1;
            self.cursor_x = self.cols - 1;
        } else {
            return;
        }
        *self.cell_mut(self.cursor_x, self.cursor_y) = TermCell::default();
    }

    /// Writes one byte, honouring control characters.
    pub fn putc(&mut self, c: u8) {
        match c {
            b'\n' => self.newline(),
            b'\r' => self.cursor_x = 0,
            0x08 | 0x7f => self.backspace(),
            b'\t' => {
                self.cursor_x = (self.cursor_x + 8) & !7;
                if self.cursor_x >= self.cols {
                    self.cursor_x = self.cols - 1;
                }
            }
            0x20..=0x7e => {
                if self.cursor_x >= self.cols {
                    self.newline();
                }
                let (x, y) = (self.cursor_x, self.cursor_y);
                let (fg, bg) = (self.fg, self.bg);
                let cell = self.cell_mut(x, y);
                cell.ch = c;
                cell.fg = fg;
                cell.bg = bg;
                self.cursor_x += 1;
                if self.cursor_x >= self.cols {
                    self.newline();
                }
            }
            _ => {}
        }
    }

    /// Writes a byte string, parsing the ANSI CSI subset.
    pub fn write_ansi(&mut self, buf: &[u8]) {
        let mut i = 0;
        while i < buf.len() {
            if buf[i] == 0x1b && i + 1 < buf.len() && buf[i + 1] == b'[' {
                let mut j = i + 2;
                let mut params: [i64; 4] = [0; 4];
                let mut n = 0;
                let mut cur: i64 = 0;
                let mut digits = false;
                let mut any = false;
                while j < buf.len() && (buf[j].is_ascii_digit() || buf[j] == b';') {
                    any = true;
                    if buf[j] == b';' {
                        if n < 4 {
                            params[n] = if digits { cur } else { 0 };
                            n += 1;
                        }
                        cur = 0;
                        digits = false;
                    } else {
                        cur = cur * 10 + (buf[j] - b'0') as i64;
                        digits = true;
                    }
                    j += 1;
                }
                if any && n < 4 {
                    params[n] = cur;
                    n += 1;
                }
                if j >= buf.len() {
                    self.putc(buf[i]);
                    i += 1;
                    continue;
                }
                let cmd = buf[j] as char;
                i = j + 1;
                let p = |k: usize| {
                    if k < n {
                        params[k]
                    } else {
                        0
                    }
                };
                let n1 = if any && p(0) != 0 { p(0) } else { 1 };
                match cmd {
                    'A' => {
                        self.cursor_y = self.cursor_y.saturating_sub(n1 as usize);
                        self.clamp();
                    }
                    'B' => {
                        self.cursor_y = (self.cursor_y + n1 as usize).min(self.rows - 1);
                    }
                    'C' => {
                        self.cursor_x = (self.cursor_x + n1 as usize).min(self.cols - 1);
                    }
                    'D' => {
                        self.cursor_x = self.cursor_x.saturating_sub(n1 as usize);
                    }
                    'E' => {
                        self.cursor_x = 0;
                        self.cursor_y = (self.cursor_y + n1 as usize).min(self.rows - 1);
                    }
                    'F' => {
                        self.cursor_x = 0;
                        self.cursor_y = self.cursor_y.saturating_sub(n1 as usize);
                    }
                    'G' => {
                        self.cursor_x = n1.max(1) as usize - 1;
                        self.clamp();
                    }
                    'd' => {
                        self.cursor_y = n1.max(1) as usize - 1;
                        self.clamp();
                    }
                    'H' => {
                        let r = if n > 0 && p(0) != 0 { p(0) } else { 1 };
                        let c = if n > 1 && p(1) != 0 { p(1) } else { 1 };
                        self.cursor_y = r.max(1) as usize - 1;
                        self.cursor_x = c.max(1) as usize - 1;
                        self.clamp();
                    }
                    'J' => {
                        if !any || p(0) == 0 {
                            for y in self.cursor_y..self.rows {
                                let from = if y == self.cursor_y {
                                    self.cursor_x
                                } else {
                                    0
                                };
                                for x in from..self.cols {
                                    *self.cell_mut(x, y) = TermCell::default();
                                }
                            }
                        } else {
                            self.clear();
                        }
                    }
                    'K' => {
                        let mode = if any { p(0) } else { 0 };
                        if mode == 0 {
                            for x in self.cursor_x..self.cols {
                                *self.cell_mut(x, self.cursor_y) = TermCell::default();
                            }
                        } else if mode == 1 {
                            for x in 0..=self.cursor_x.min(self.cols - 1) {
                                *self.cell_mut(x, self.cursor_y) = TermCell::default();
                            }
                        } else {
                            for x in 0..self.cols {
                                *self.cell_mut(x, self.cursor_y) = TermCell::default();
                            }
                        }
                    }
                    'm' => {
                        if !any {
                            self.fg = 7;
                            self.bg = 0;
                        }
                        for k in 0..n {
                            match params[k] {
                                0 => {
                                    self.fg = 7;
                                    self.bg = 0;
                                }
                                30..=37 => self.fg = (params[k] - 30) as u8,
                                40..=47 => self.bg = (params[k] - 40) as u8,
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                self.putc(buf[i]);
                i += 1;
            }
        }
    }

    /// Row `y` as a string, trailing blanks trimmed.
    pub fn row_text(&self, y: usize) -> String {
        let mut end = 0;
        for x in 0..self.cols {
            if self.cell(x, y).ch != b' ' {
                end = x + 1;
            }
        }
        self.cells[y * self.cols..y * self.cols + end]
            .iter()
            .map(|c| c.ch as char)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_wraps_and_scrolls_into_scrollback() {
        let mut t = TermScreen::new(4, 2);
        t.write_ansi(b"abcdefghi");
        assert_eq!(t.row_text(0), "efgh");
        assert_eq!(t.row_text(1), "i");
        assert_eq!(t.scrollback_len(), 1);
        assert_eq!(t.cursor(), (1, 1));
    }

    #[test]
    fn backspace_erases_backwards() {
        let mut t = TermScreen::new(8, 2);
        t.write_ansi(b"ab");
        t.write_ansi(&[0x7f]);
        t.write_ansi(b"c");
        assert_eq!(t.row_text(0), "ac");
    }

    #[test]
    fn cursor_movement_and_home() {
        let mut t = TermScreen::new(10, 5);
        t.write_ansi(b"\x1b[3;4H");
        assert_eq!(t.cursor(), (3, 2));
        t.write_ansi(b"\x1b[2A\x1b[1B\x1b[2C\x1b[1D");
        assert_eq!(t.cursor(), (4, 1));
        t.write_ansi(b"\x1b[H");
        assert_eq!(t.cursor(), (0, 0));
    }

    #[test]
    fn erase_line_modes() {
        let mut t = TermScreen::new(8, 2);
        t.write_ansi(b"hello");
        t.write_ansi(b"\x1b[1G\x1b[K");
        assert_eq!(t.row_text(0), "");
        t.write_ansi(b"world\x1b[1G\x1b[1K");
        assert_eq!(t.row_text(0), " orld", "EL 1 blanks start-through-cursor");
    }

    #[test]
    fn colors_apply_per_code_and_reset() {
        let mut t = TermScreen::new(8, 2);
        t.write_ansi(b"\x1b[31mR");
        assert_eq!(t.cell(0, 0).fg, 1);
        t.write_ansi(b"\x1b[0mN");
        assert_eq!(t.cell(1, 0).fg, 7);
        t.write_ansi(b"\x1b[32;44mX");
        assert_eq!((t.cell(2, 0).fg, t.cell(2, 0).bg), (2, 4));
    }

    #[test]
    fn clear_screen_erase_display() {
        let mut t = TermScreen::new(8, 2);
        t.write_ansi(b"hi\x1b[2J");
        assert_eq!(t.row_text(0), "");
        assert_eq!(t.cursor(), (0, 0));
    }
}
