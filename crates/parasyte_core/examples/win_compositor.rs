//! Windows compositor: runs the parasyteos compositor natively on Windows.
//!
//! Creates a window, manages windows with decorations, routes mouse input,
//! and composites at 60fps. This is the desktop shell running without Linux.
//!
//! Run: cargo run -p parasyte_core --example win_compositor

#![cfg(windows)]

use parasyte_core::gfx::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const WIDTH: u32 = 800;
const HEIGHT: u32 = 600;
const CLASS_NAME: &str = "parasyteos_compositor";
const WINDOW_TITLE: &str = "parasyteos desktop";

static RUNNING: AtomicBool = AtomicBool::new(true);

unsafe extern "system" fn wndproc(hwnd: winapi::shared::windef::HWND, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        0x0010 => { RUNNING.store(false, Ordering::SeqCst); 0 }
        _ => winapi::um::winuser::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

struct DesktopWindow {
    id: u32,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    title: String,
    color: u32,
    z: u32,
    visible: bool,
    minimized: bool,
    focused: bool,
}

struct Desktop {
    windows: Vec<DesktopWindow>,
    next_id: u32,
    mouse_x: i32,
    mouse_y: i32,
    focused_id: Option<u32>,
}

impl Desktop {
    fn new() -> Self {
        Desktop {
            windows: Vec::new(),
            next_id: 1,
            mouse_x: 0,
            mouse_y: 0,
            focused_id: None,
        }
    }

    fn create_window(&mut self, x: i32, y: i32, w: u32, h: u32, title: &str, color: u32) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let max_z = self.windows.iter().map(|w| w.z).max().unwrap_or(0);
        self.windows.push(DesktopWindow {
            id, x, y, w, h,
            title: title.to_string(),
            color,
            z: max_z + 1,
            visible: true,
            minimized: false,
            focused: false,
        });
        self.focused_id = Some(id);
        id
    }

    fn raise(&mut self, id: u32) {
        let max_z = self.windows.iter().map(|w| w.z).max().unwrap_or(0);
        if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
            w.z = max_z + 1;
            self.focused_id = Some(id);
        }
    }

    fn hit_test(&self, x: i32, y: i32) -> Option<u32> {
        let mut best_z = 0u32;
        let mut best_id = None;
        for w in &self.windows {
            if !w.visible || w.minimized { continue; }
            if x >= w.x && x < w.x + w.w as i32 && y >= w.y && y < w.y + w.h as i32 {
                if w.z >= best_z {
                    best_z = w.z;
                    best_id = Some(w.id);
                }
            }
        }
        best_id
    }

    fn on_mouse_move(&mut self, x: i32, y: i32) {
        self.mouse_x = x;
        self.mouse_y = y;
    }

    fn on_click(&mut self, x: i32, y: i32) {
        if let Some(id) = self.hit_test(x, y) {
            self.raise(id);
        }
    }

    fn render(&self) -> Framebuffer {
        let mut fb = Framebuffer::new(WIDTH, HEIGHT);
        fb.clear(BACKGROUND);

        // Sort by z-order (back to front)
        let mut sorted: Vec<&DesktopWindow> = self.windows.iter().collect();
        sorted.sort_by_key(|w| w.z);

        for w in sorted {
            if !w.visible || w.minimized { continue; }
            // Window content
            fb.fill_rect(w.x, w.y, w.w, w.h, w.color);
            // Title bar
            fb.fill_rect(w.x, w.y, w.w, 20, 0x00303040);
            // Title text
            fb.draw_text(w.x + 4, w.y + 4, &w.title, 0x00FFFFFF, None);
            // Border
            fb.fill_rect(w.x, w.y, w.w, 2, 0x00404050);
            fb.fill_rect(w.x, w.y + w.h as i32 - 2, w.w, 2, 0x00404050);
            fb.fill_rect(w.x, w.y, 2, w.h, 0x00404050);
            fb.fill_rect(w.x + w.w as i32 - 2, w.y, 2, w.h, 0x00404050);
            // Close button
            fb.fill_rect(w.x + w.w as i32 - 16, w.y + 2, 12, 12, 0x00FF4040);
            fb.draw_text(w.x + w.w as i32 - 14, w.y + 4, "X", 0x00FFFFFF, None);
            // Focus indicator
            if self.focused_id == Some(w.id) {
                fb.fill_rect(w.x, w.y, w.w, 2, 0x008080FF);
            }
        }

        // Draw cursor
        draw_cursor(&mut fb, self.mouse_x, self.mouse_y);

        fb
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

        let mut desktop = Desktop::new();
        desktop.create_window(50, 50, 300, 200, "Terminal", rgb(30, 30, 30));
        desktop.create_window(200, 150, 250, 180, "Shell", rgb(40, 60, 40));
        desktop.create_window(400, 100, 200, 150, "Editor", rgb(60, 40, 40));

        let mut frame_count = 0u64;
        while RUNNING.load(Ordering::SeqCst) {
            // Handle mouse input
            let mut msg: winapi::um::winuser::MSG = std::mem::zeroed();
            while winapi::um::winuser::PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, 1) != 0 {
                match msg.message {
                    0x0200 => { // WM_MOUSEMOVE
                        let x = (msg.lParam & 0xffff) as i16 as i32;
                        let y = ((msg.lParam >> 16) & 0xffff) as i16 as i32;
                        desktop.on_mouse_move(x, y);
                    }
                    0x0201 => { // WM_LBUTTONDOWN
                        let x = (msg.lParam & 0xffff) as i16 as i32;
                        let y = ((msg.lParam >> 16) & 0xffff) as i16 as i32;
                        desktop.on_click(x, y);
                    }
                    _ => {}
                }
                winapi::um::winuser::TranslateMessage(&msg);
                winapi::um::winuser::DispatchMessageW(&msg);
            }

            // Render and present
            let fb = desktop.render();
            let ppm = fb.to_ppm();
            draw_pixels(hdc, &ppm[13..], WIDTH, HEIGHT);
            frame_count += 1;

            std::thread::sleep(Duration::from_millis(16));
        }

        winapi::um::winuser::ReleaseDC(hwnd, hdc);
        println!("win_compositor: showed {frame_count} frames");
    }
}

unsafe fn draw_pixels(hdc: winapi::shared::windef::HDC, rgb: &[u8], w: u32, h: u32) {
    use winapi::um::wingdi::*;

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
