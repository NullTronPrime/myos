//! Visual test: exercises all Phase 1 graphics features and outputs a PPM.
//!
//! Run: cargo run -p parasyte_core --example visual_test
//! Output: target/visual_test.ppm

use parasyte_core::gfx::*;

fn main() {
    let mut fb = Framebuffer::new(128, 96);
    fb.clear(BACKGROUND);

    // Draw two overlapping windows with decorations
    let mut win_a = Window {
        id: 1, x: 10, y: 10, width: 60, height: 40, buffer: 0,
        visible: true, z: 0, focused: false, minimized: false,
        title: { let mut t = [0u8; 64]; t[..8].copy_from_slice(b"Window A"); t }, title_len: 8,
        dirty_x: 0, dirty_y: 0, dirty_w: 0, dirty_h: 0, dirty: true,
    };
    let mut win_b = Window {
        id: 2, x: 40, y: 30, width: 50, height: 35, buffer: 0,
        visible: true, z: 1, focused: true, minimized: false,
        title: { let mut t = [0u8; 64]; t[..8].copy_from_slice(b"Window B"); t }, title_len: 8,
        dirty_x: 0, dirty_y: 0, dirty_w: 0, dirty_h: 0, dirty: true,
    };

    // Draw window A content (red)
    let mut content_a = Framebuffer::new(60, 40);
    content_a.clear(rgb(200, 50, 50));
    fb.blit_pixels(win_a.x, win_a.y, content_a.width(), content_a.height(), content_a.pixels());

    // Draw window B content (green) with alpha blending
    let mut content_b = Framebuffer::new(50, 35);
    content_b.clear(rgb(50, 200, 50));
    fb.blit_pixels_alpha(win_b.x, win_b.y, content_b.width(), content_b.height(), content_b.pixels(), false);

    // Draw decorations
    draw_decorations(&mut fb, &win_a);
    draw_decorations(&mut fb, &win_b);

    // Draw cursor (in empty area, top-right)
    draw_cursor(&mut fb, 100, 5);

    // Draw wrapped text
    fb.draw_text_wrapped(5, 80, "Hello Phase 1! This is a wrapped text test.", rgb(255, 255, 255), None, Some(120));

    // Draw text cursor
    fb.draw_text_cursor(100, 80, rgb(255, 255, 0));

    // Output PPM
    let ppm = fb.to_ppm();
    std::fs::write("target/visual_test.ppm", &ppm).unwrap();
    println!("Wrote target/visual_test.ppm ({} bytes)", ppm.len());

    // Also test alpha blending visually
    let mut alpha_test = Framebuffer::new(64, 32);
    alpha_test.clear(rgb(255, 0, 0)); // Red background
    let mut blue = Framebuffer::new(32, 16);
    blue.clear(0x800000FF); // 50% opaque blue
    alpha_test.blit_pixels_alpha(16, 8, blue.width(), blue.height(), blue.pixels(), true);
    let alpha_ppm = alpha_test.to_ppm();
    std::fs::write("target/alpha_test.ppm", &alpha_ppm).unwrap();
    println!("Wrote target/alpha_test.ppm ({} bytes)", alpha_ppm.len());
}
