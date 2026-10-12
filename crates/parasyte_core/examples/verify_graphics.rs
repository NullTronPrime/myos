//! Verifies the visual_test.ppm output pixel by pixel.
//!
//! Run: cargo run -p parasyte_core --example verify_graphics

use std::fs;

fn read_ppm(path: &str) -> (Vec<u8>, u32, u32) {
    let data = fs::read(path).expect("read ppm");
    let mut i = 2usize;
    let next = |i: &mut usize| -> u32 {
        while *i < data.len() && data[*i].is_ascii_whitespace() { *i += 1; }
        let start = *i;
        while *i < data.len() && data[*i].is_ascii_digit() { *i += 1; }
        std::str::from_utf8(&data[start..*i]).unwrap().parse().unwrap()
    };
    let w = next(&mut i);
    let h = next(&mut i);
    let _maxval = next(&mut i);
    i += 1;
    (data[i..].to_vec(), w, h)
}

fn px(rgb: &[u8], w: u32, x: u32, y: u32) -> (u8, u8, u8) {
    let at = ((y * w + x) * 3) as usize;
    (rgb[at], rgb[at + 1], rgb[at + 2])
}

fn main() {
    let (rgb, w, h) = read_ppm("target/visual_test.ppm");
    println!("visual_test.ppm: {}x{}", w, h);

    let mut pass = 0u32;
    let mut fail = 0u32;

    // Background at (0,0)
    let got = px(&rgb, w, 0, 0);
    if got == (16, 20, 24) { pass += 1; } else { fail += 1; println!("FAIL bg(0,0): got {got:?}"); }

    // Window A content (red) at (20, 35) — below title bar (y > 10+20)
    let got = px(&rgb, w, 20, 35);
    if got == (200, 50, 50) { pass += 1; } else { fail += 1; println!("FAIL winA(20,35): got {got:?}"); }

    // Window B content (green) at (50, 50) — below title bar (y > 30+20)
    let got = px(&rgb, w, 50, 50);
    if got == (50, 200, 50) { pass += 1; } else { fail += 1; println!("FAIL winB(50,50): got {got:?}"); }

    // Window A title bar at (12, 12) — should be dark
    let got = px(&rgb, w, 12, 12);
    if got.0 < 60 && got.1 < 60 && got.2 < 80 { pass += 1; } else { fail += 1; println!("FAIL title_bar(12,12): got {got:?}"); }

    // Cursor at (101, 5) — should be white (second column of cursor)
    let got = px(&rgb, w, 101, 5);
    if got == (255, 255, 255) || got == (0, 0, 0) { pass += 1; } else { fail += 1; println!("FAIL cursor(101,5): got {got:?}"); }

    // Text at (5, 80) — should be white
    let got = px(&rgb, w, 5, 80);
    if got.0 > 200 && got.1 > 200 && got.2 > 200 { pass += 1; } else { fail += 1; println!("FAIL text(5,80): got {got:?}"); }

    // Alpha test
    let (argb, aw, ah) = read_ppm("target/alpha_test.ppm");
    println!("\nalpha_test.ppm: {}x{}", aw, ah);
    let got = px(&argb, aw, 0, 0);
    if got == (255, 0, 0) { pass += 1; } else { fail += 1; println!("FAIL alpha_bg(0,0): got {got:?}"); }
    let got = px(&argb, aw, 32, 16);
    if got.0 > 100 && got.0 < 150 && got.2 > 100 && got.2 < 150 { pass += 1; } else { fail += 1; println!("FAIL alpha_blend(32,16): got {got:?}"); }

    println!("\n{pass} passed, {fail} failed");
    if fail > 0 {
        std::process::exit(1);
    }
}
