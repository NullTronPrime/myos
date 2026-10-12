//! Windows display server: shows the compositor output in a window.
//!
//! Run: cargo run --example win_display
//! The compositor writes PPM files to target/frame_*.ppm; this displays them.

#![cfg(windows)]

use std::fs;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;
const CLASS_NAME: &str = "parasyteos_display";
const WINDOW_TITLE: &str = "parasyteos desktop";

static RUNNING: AtomicBool = AtomicBool::new(true);

unsafe extern "system" fn wndproc(hwnd: *mut std::ffi::c_void, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        0x0010 => { RUNNING.store(false, Ordering::SeqCst); 0 }
        _ => winapi::um::winuser::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn main() {
    unsafe {
        let hinstance = winapi::um::libloaderapi::GetModuleHandleW(null_mut());
        let wc = winapi::um::winuser::WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: null_mut(),
            hCursor: null_mut(),
            hbrBackground: null_mut(),
            lpszMenuName: null_mut(),
            lpszClassName: wide_string(CLASS_NAME).as_ptr(),
        };
        winapi::um::winuser::RegisterClassW(&wc);

        let hwnd = winapi::um::winuser::CreateWindowExW(
            0,
            wide_string(CLASS_NAME).as_ptr(),
            wide_string(WINDOW_TITLE).as_ptr(),
            0x00CF0000,
            100, 100,
            WIDTH as i32, HEIGHT as i32,
            null_mut(), null_mut(), hinstance, null_mut(),
        );
        if hwnd.is_null() {
            println!("Failed to create window");
            return;
        }
        winapi::um::winuser::ShowWindow(hwnd, 1);
        winapi::um::winuser::UpdateWindow(hwnd);

        let hdc = winapi::um::winuser::GetDC(hwnd);
        let mut frame_count = 0u64;

        while RUNNING.load(Ordering::SeqCst) {
            let paths = ["target/frame_latest.ppm", "target/visual_test.ppm"];
            for path in &paths {
                if let Ok(data) = fs::read(path) {
                    if let Some((pixels, w, h)) = decode_ppm(&data) {
                        draw_pixels(hdc, &pixels, w, h);
                        frame_count += 1;
                        break;
                    }
                }
            }

            let mut msg: winapi::um::winuser::MSG = std::mem::zeroed();
            while winapi::um::winuser::PeekMessageW(&mut msg, null_mut(), 0, 0, 1) != 0 {
                winapi::um::winuser::TranslateMessage(&msg);
                winapi::um::winuser::DispatchMessageW(&msg);
            }

            std::thread::sleep(Duration::from_millis(16));
        }

        winapi::um::winuser::ReleaseDC(hwnd, hdc);
        println!("win_display: showed {frame_count} frames");
    }
}

unsafe fn draw_pixels(hdc: *mut std::ffi::c_void, rgb: &[u8], w: u32, h: u32) {
    use winapi::um::wingdi::*;
    let bmp = CreateBitmap(w as i32, h as i32, 1, 32, rgb.as_ptr() as *const _);
    if bmp.is_null() { return; }
    let mem_dc = CreateCompatibleDC(hdc);
    SelectObject(mem_dc, bmp as *mut _);
    BitBlt(hdc, 0, 0, w as i32, h as i32, mem_dc, 0, 0, 0x00CC0020);
    DeleteDC(mem_dc);
    DeleteObject(bmp as *mut _);
}

fn decode_ppm(data: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    if data.len() < 2 || &data[0..2] != b"P6" { return None; }
    let mut i = 2usize;
    let next = |i: &mut usize| -> u32 {
        while *i < data.len() && data[*i].is_ascii_whitespace() { *i += 1; }
        let start = *i;
        while *i < data.len() && data[*i].is_ascii_digit() { *i += 1; }
        std::str::from_utf8(&data[start..*i]).ok()?.parse().ok()
    };
    let w = next(&mut i);
    let h = next(&mut i);
    let _maxval = next(&mut i);
    i += 1;
    let want = (w as usize) * (h as usize) * 3;
    if data.len() < i + want { return None; }
    Some((data[i..i + want].to_vec(), w, h))
}

fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
