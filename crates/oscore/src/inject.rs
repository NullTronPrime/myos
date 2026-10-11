//! Headless input injection: scripted events without a display server.
//!
//! Live input arrives from X11 in `osplat::display`; under `cargo test` or
//! in CI there is no server at all. This module parses a small line-based
//! script into [`crate::input::Event`]s so interaction (clicks, drags,
//! Alt-Tab, typing) can be driven deterministically. The trap layer feeds
//! `MYOS_INJECT` through this parser before entering the guest.
//!
//! Script lines (blank lines and `#` comments ignored):
//!
//! ```text
//! keydown Tab alt win=1      # press; mods: shift ctrl alt meta (or a+b)
//! keyup Tab alt win=1
//! key a win=1                # down+up pair
//! type hello win=1           # one down+up per char; \n is Return
//! mousedown 100 120 left
//! mousemove 150 170
//! mouseup 150 170 left
//! wheel 100 120 down
//! expose 1
//! close 2
//! resize 3 800 600
//! ```
//!
//! Coordinates and window ids are decimal integers. Keysyms mirror what the
//! live X11 path produces (`osplat::display::keysym`), including its
//! Up/Down and Left/Right aliases, so a script replays what a real server
//! would have sent.

use crate::input::{Button, Event, EventKind, Mods, MAX_QUEUE};

/// A script syntax error, with the 1-based offending line.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ParseError {
    pub line: usize,
    pub msg: String,
}

impl ParseError {
    fn at(line: usize, msg: impl Into<String>) -> Self {
        ParseError {
            line,
            msg: msg.into(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "inject line {}: {}", self.line, self.msg)
    }
}

/// Parses a whole script into input events, in order.
pub fn parse_script(text: &str) -> Result<Vec<Event>, ParseError> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut words: Vec<&str> = line.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        let verb = words.remove(0).to_lowercase();
        parse_line(&verb, &words, line_no, &mut out)?;
        if out.len() > MAX_QUEUE {
            return Err(ParseError::at(line_no, "script exceeds input queue capacity"));
        }
    }
    Ok(out)
}

fn parse_line(verb: &str, words: &[&str], line: usize, out: &mut Vec<Event>) -> Result<(), ParseError> {
    let err = |msg: String| ParseError::at(line, msg);
    match verb {
        "keydown" | "keyup" | "key" => {
            let down = verb != "keyup";
            let up = verb != "keydown";
            let (keysym, text, rest) = parse_key(words)
                .ok_or_else(|| err(format!("expected: {verb} <key> [mods] [win=N]")))?;
            let (mods, win) = parse_tail(rest, line)?;
            if down {
                out.push(Event::key_down(win, keysym, mods, text));
            }
            if up {
                out.push(Event::key_up(win, keysym, mods));
            }
            Ok(())
        }
        "type" => {
            let (win, text) = parse_type(words);
            for c in unescape(text).chars() {
                if c == '\n' {
                    out.push(Event::key_down(win, 0xff0d, Mods::default(), false));
                    out.push(Event::key_up(win, 0xff0d, Mods::default()));
                } else if c == '\t' {
                    out.push(Event::key_down(win, 0xff09, Mods::default(), false));
                    out.push(Event::key_up(win, 0xff09, Mods::default()));
                } else {
                    out.push(Event::key_down(win, c as i32, Mods::default(), true));
                    out.push(Event::key_up(win, c as i32, Mods::default()));
                }
            }
            Ok(())
        }
        "mousedown" | "mouseup" => {
            let kind = if verb == "mousedown" {
                EventKind::MouseDown
            } else {
                EventKind::MouseUp
            };
            let (x, y, rest) = parse_xy(words)
                .ok_or_else(|| err(format!("expected: {verb} <x> <y> [button] [win=N]")))?;
            let mut button = Button::Left;
            let mut tail = rest;
            if let Some((b, r)) = parse_button(tail) {
                button = b;
                tail = r;
            }
            let (mods, win) = parse_tail(tail, line)?;
            out.push(Event::pointer(kind, win, x, y, button, mods));
            Ok(())
        }
        "mousemove" => {
            let (x, y, rest) = parse_xy(words)
                .ok_or_else(|| err("expected: mousemove <x> <y> [win=N]".to_string()))?;
            let (mods, win) = parse_tail(rest, line)?;
            out.push(Event::pointer(
                EventKind::MouseMove,
                win,
                x,
                y,
                Button::Other(0),
                mods,
            ));
            Ok(())
        }
        "wheel" => {
            if words.len() < 3 {
                return Err(err("expected: wheel <x> <y> up|down [win=N]".to_string()));
            }
            let x: i32 = words[0].parse().map_err(|_| err("bad x".to_string()))?;
            let y: i32 = words[1].parse().map_err(|_| err("bad y".to_string()))?;
            let button = match words[2].to_lowercase().as_str() {
                "up" => Button::WheelUp,
                "down" => Button::WheelDown,
                _ => return Err(err("wheel needs up|down".to_string())),
            };
            let (mods, win) = parse_tail(&words[3..], line)?;
            out.push(Event::pointer(EventKind::MouseDown, win, x, y, button, mods));
            Ok(())
        }
        "expose" | "close" => {
            let win = parse_win_only(words).ok_or_else(|| err(format!("expected: {verb} <win>")))?;
            let kind = if verb == "expose" {
                EventKind::Expose
            } else {
                EventKind::Close
            };
            out.push(Event::simple(kind, win));
            Ok(())
        }
        "resize" => {
            if words.len() != 3 {
                return Err(err("expected: resize <win> <w> <h>".to_string()));
            }
            let win: u32 = words[0].parse().map_err(|_| err("bad window".to_string()))?;
            let w: u32 = words[1].parse().map_err(|_| err("bad width".to_string()))?;
            let h: u32 = words[2].parse().map_err(|_| err("bad height".to_string()))?;
            out.push(Event::resize(win, w, h));
            Ok(())
        }
        _ => Err(err(format!("unknown verb '{verb}'"))),
    }
}

/// Splits a `type` line into an optional leading `win=N` and the text.
/// The text is everything after the verb, with `win=N` stripped when first.
fn parse_type(words: &[&str]) -> (u32, String) {
    let mut win = 0u32;
    let mut rest = words;
    if let Some(first) = rest.first() {
        if let Some(n) = first.strip_prefix("win=") {
            if let Ok(w) = n.parse() {
                win = w;
            }
            rest = &rest[1..];
        }
    }
    (win, rest.join(" "))
}

/// Unescapes `\\`, `\n` and `\t` in `type` text.
fn unescape(s: String) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses `<key> [rest...]`, returning the keysym, whether it is text, and
/// the unconsumed words.
fn parse_key<'a>(words: &'a [&'a str]) -> Option<(i32, bool, &'a [&'a str])> {
    let name = *words.first()?;
    let lower = name.to_lowercase();
    let named: Option<i32> = match lower.as_str() {
        "tab" => Some(0xff09),
        "return" | "enter" => Some(0xff0d),
        "escape" | "esc" => Some(0xff1b),
        "backspace" | "back" => Some(0xff08),
        "space" => Some(0x20),
        "up" | "down" => Some(0xff51),
        "left" | "right" => Some(0xff52),
        "home" => Some(0xff50),
        "prior" | "pageup" => Some(0xff55),
        "next" | "pagedown" => Some(0xff54),
        "end" => Some(0xff57),
        _ => None,
    };
    if let Some(k) = named {
        return Some((k, false, &words[1..]));
    }
    let mut chars = name.chars();
    let c = chars.next()?;
    if chars.next().is_none() {
        return Some((c as i32, true, &words[1..]));
    }
    None
}

/// Parses trailing `win=N` and modifier tokens. Unknown tokens are an error.
fn parse_tail(words: &[&str], line: usize) -> Result<(Mods, u32), ParseError> {
    let mut mods = Mods::default();
    let mut win = 0u32;
    for w in words {
        if let Some(n) = w.strip_prefix("win=") {
            win = n
                .parse()
                .map_err(|_| ParseError::at(line, format!("bad window '{w}'")))?;
            continue;
        }
        let mut known = true;
        for m in w.split('+') {
            match m.to_lowercase().as_str() {
                "shift" => mods.shift = true,
                "ctrl" | "control" => mods.control = true,
                "alt" => mods.alt = true,
                "meta" | "super" => mods.meta = true,
                _ => known = false,
            }
        }
        if !known {
            return Err(ParseError::at(line, format!("unknown token '{w}'")));
        }
    }
    Ok((mods, win))
}

fn parse_xy<'a>(words: &'a [&'a str]) -> Option<(i32, i32, &'a [&'a str])> {
    if words.len() < 2 {
        return None;
    }
    Some((words[0].parse().ok()?, words[1].parse().ok()?, &words[2..]))
}

fn parse_button<'a>(words: &'a [&'a str]) -> Option<(Button, &'a [&'a str])> {
    let b = match words.first()?.to_lowercase().as_str() {
        "left" | "1" => Button::Left,
        "middle" | "2" => Button::Middle,
        "right" | "3" => Button::Right,
        _ => return None,
    };
    Some((b, &words[1..]))
}

fn parse_win_only(words: &[&str]) -> Option<u32> {
    if words.len() != 1 {
        return None;
    }
    words[0].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_blanks_and_unknown_verbs() {
        let evs = parse_script("# hello\n\n  \nkey a\n").unwrap();
        assert_eq!(evs.len(), 2);
        assert!(parse_script("frobnicate\n").is_err());
        let e = parse_script("frobnicate").unwrap_err();
        assert_eq!(e.line, 1);
    }

    #[test]
    fn key_down_up_mods_and_window() {
        let evs = parse_script("keydown Tab alt win=2").unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::KeyDown);
        assert_eq!((evs[0].x, evs[0].window), (0xff09, 2));
        assert!(evs[0].mods.alt);
        let evs = parse_script("key a ctrl+shift").unwrap();
        assert_eq!(evs.len(), 2);
        assert!(evs[0].mods.control && evs[0].mods.shift);
        assert_eq!(evs[0].x, b'a' as i32);
    }

    #[test]
    fn typing_expands_text_with_return() {
        let evs = parse_script("type hi\\n").unwrap();
        // h, i: down+up each; newline: Return down+up.
        assert_eq!(evs.len(), 6);
        assert_eq!(evs[4].x, 0xff0d);
        assert_eq!(evs[4].kind, EventKind::KeyDown);
    }

    #[test]
    fn pointer_verbs_carry_buttons_and_windows() {
        let evs = parse_script("mousedown 10 20 right win=3\nmousemove 11 21\nmouseup 10 20\nwheel 5 6 down").unwrap();
        assert_eq!(evs.len(), 4);
        assert_eq!(evs[0].button, Button::Right);
        assert_eq!(evs[0].window, 3);
        assert_eq!(evs[0].kind, EventKind::MouseDown);
        assert_eq!(evs[1].kind, EventKind::MouseMove);
        assert_eq!(evs[3].button, Button::WheelDown);
    }

    #[test]
    fn window_verbs() {
        let evs = parse_script("expose 1\nclose 2\nresize 3 800 600").unwrap();
        assert_eq!(evs[0].kind, EventKind::Expose);
        assert_eq!(evs[1].kind, EventKind::Close);
        assert_eq!((evs[2].width, evs[2].height), (800, 600));
    }

    #[test]
    fn bad_coordinates_are_line_numbered_errors() {
        let e = parse_script("mousedown 10\n").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(parse_script("mousedown x y").is_err());
    }
}
