//! Windows display server: shows the compositor output in a window.
//!
//! Run: cargo run -p oscore --example win_display

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;
const CLASS_NAME: &str = "myos_display";
const WINDOW_TITLE: &str = "myos desktop";

static RUNNING: AtomicBool = AtomicBool::new(true);

unsafe extern "system" fn wndproc(hwnd: winapi::shared::windef::HWND, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        0x0010 => { RUNNING.store(false, Ordering::SeqCst); 0 }
        _ => winapi::um::winuser::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn main() {
    unsafe {
        let hinstance = winapi::um::libloaderapi::GetModuleHandleW(std::ptr::null_mut());
        let class_name = wide_string(CLASS_NAME);
        let window_title = wide_string(WINDOW_TITLE);
        let wc = winapi::um::winuser::WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null_mut(),
            lpszClassName: class_name.as_ptr(),
        };
        winapi::um::winuser::RegisterClassW(&wc);

        let hwnd = winapi::um::winuser::CreateWindowExW(
            0,
            class_name.as_ptr(),
            window_title.as_ptr(),
            0x00CF0000,
            100, 100,
            WIDTH as i32, HEIGHT as i32,
            std::ptr::null_mut(), std::ptr::null_mut(), hinstance, std::ptr::null_mut(),
        );
        if hwnd.is_null() {
            println!("Failed to create window");
            return;
        }
        winapi::um::winuser::ShowWindow(hwnd, 1);
        winapi::um::winuser::UpdateWindow(hwnd);

        let hdc = winapi::um::winuser::GetDC(hwnd);

        // Build a demo frame: gradient background + colored rectangles
        let mut pixels = vec![0u8; (WIDTH * HEIGHT * 3) as usize];
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let at = ((y * WIDTH + x) * 3) as usize;
                pixels[at] = (y * 255 / HEIGHT) as u8;
                pixels[at + 1] = (x * 255 / WIDTH) as u8;
                pixels[at + 2] = 128u8;
            }
        }
        for y in 50..150 {
            for x in 50..200 {
                let at = ((y * WIDTH + x) * 3) as usize;
                pixels[at] = 255; pixels[at + 1] = 0; pixels[at + 2] = 0;
            }
        }
        for y in 100..200 {
            for x in 250..400 {
                let at = ((y * WIDTH + x) * 3) as usize;
                pixels[at] = 0; pixels[at + 1] = 255; pixels[at + 2] = 0;
            }
        }
        for y in 250..350 {
            for x in 100..300 {
                let at = ((y * WIDTH + x) * 3) as usize;
                pixels[at] = 0; pixels[at + 1] = 0; pixels[at + 2] = 255;
            }
        }

        let mut frame_count = 0u64;
        while RUNNING.load(Ordering::SeqCst) {
            draw_pixels(hdc, &pixels, WIDTH, HEIGHT);
            frame_count += 1;

            let mut msg: winapi::um::winuser::MSG = std::mem::zeroed();
            while winapi::um::winuser::PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, 1) != 0 {
                winapi::um::winuser::TranslateMessage(&msg);
                winapi::um::winuser::DispatchMessageW(&msg);
            }
            std::thread::sleep(Duration::from_millis(16));
        }

        winapi::um::winuser::ReleaseDC(hwnd, hdc);
        println!("win_display: showed {frame_count} frames");
    }
}

unsafe fn draw_pixels(hdc: winapi::shared::windef::HDC, rgb: &[u8], w: u32, h: u32) {
    use winapi::um::wingdi::*;
    use winapi::shared::windef::*;

    let mut bmi: BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = w as i32;
    bmi.bmiHeader.biHeight = -(h as i32);
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 24;
    bmi.bmiHeader.biCompression = BI_RGB;

    StretchDIBits(
        hdc,
        0, 0, w as i32, h as i32,
        0, 0, w as i32, h as i32,
        rgb.as_ptr() as *const _,
        &bmi,
        DIB_RGB_COLORS,
        SRCCOPY,
    );
}

fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
