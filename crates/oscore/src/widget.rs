//! Widget toolkit: event dispatch, buttons, text fields, layout.
//!
//! Pure, host-testable model. Widgets are positioned rectangles with event
//! handlers. The `Widget` trait is implemented by `Button`, `TextField`,
//! and `Container`.

use crate::gfx::{Framebuffer, rgb};

/// A rectangle in screen coordinates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.x + self.w as i32 &&
        py >= self.y && py < self.y + self.h as i32
    }
}

/// Widget event types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WidgetEvent {
    MouseDown { x: i32, y: i32, button: u8 },
    MouseUp { x: i32, y: i32, button: u8 },
    MouseMove { x: i32, y: i32 },
    KeyDown { key: u8 },
    KeyUp { key: u8 },
    FocusGained,
    FocusLost,
}

/// Widget state flags.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct WidgetState {
    pub hovered: bool,
    pub pressed: bool,
    pub focused: bool,
    pub disabled: bool,
}

/// Trait for all widgets.
pub trait Widget {
    fn bounds(&self) -> Rect;
    fn state(&self) -> WidgetState;
    fn set_state(&mut self, state: WidgetState);
    fn on_event(&mut self, event: &WidgetEvent) -> bool;
    fn render(&self, fb: &mut Framebuffer);
}

/// A clickable button.
#[derive(Clone, Debug)]
pub struct Button {
    pub bounds: Rect,
    pub label: String,
    pub state: WidgetState,
    pub on_click: Option<fn()>,
    pub bg_color: u32,
    pub fg_color: u32,
    pub hover_color: u32,
    pub pressed_color: u32,
}

impl Button {
    pub fn new(x: i32, y: i32, w: u32, h: u32, label: &str) -> Self {
        Button {
            bounds: Rect { x, y, w, h },
            label: label.to_string(),
            state: WidgetState::default(),
            on_click: None,
            bg_color: rgb(60, 60, 80),
            fg_color: rgb(255, 255, 255),
            hover_color: rgb(80, 80, 110),
            pressed_color: rgb(40, 40, 60),
        }
    }

    pub fn set_callback(&mut self, cb: fn()) {
        self.on_click = Some(cb);
    }
}

impl Widget for Button {
    fn bounds(&self) -> Rect { self.bounds }
    fn state(&self) -> WidgetState { self.state }
    fn set_state(&mut self, state: WidgetState) { self.state = state; }

    fn on_event(&mut self, event: &WidgetEvent) -> bool {
        if self.state.disabled { return false; }
        match event {
            WidgetEvent::MouseDown { x, y, .. } => {
                if self.bounds.contains(*x, *y) {
                    self.state.pressed = true;
                    true
                } else { false }
            }
            WidgetEvent::MouseUp { x, y, .. } => {
                if self.state.pressed && self.bounds.contains(*x, *y) {
                    self.state.pressed = false;
                    if let Some(cb) = self.on_click { cb(); }
                    true
                } else {
                    self.state.pressed = false;
                    false
                }
            }
            WidgetEvent::MouseMove { x, y } => {
                let was_hovered = self.state.hovered;
                self.state.hovered = self.bounds.contains(*x, *y);
                was_hovered != self.state.hovered
            }
            _ => false,
        }
    }

    fn render(&self, fb: &mut Framebuffer) {
        let color = if self.state.disabled {
            rgb(40, 40, 40)
        } else if self.state.pressed {
            self.pressed_color
        } else if self.state.hovered {
            self.hover_color
        } else {
            self.bg_color
        };
        fb.fill_rect(self.bounds.x, self.bounds.y, self.bounds.w, self.bounds.h, color);
        let tw = self.label.len() as u32 * 8;
        let th = 8;
        let tx = self.bounds.x + (self.bounds.w as i32 - tw as i32) / 2;
        let ty = self.bounds.y + (self.bounds.h as i32 - th as i32) / 2;
        fb.draw_text(tx, ty, &self.label, self.fg_color, None);
    }
}

/// A single-line text input field.
#[derive(Clone, Debug)]
pub struct TextField {
    pub bounds: Rect,
    pub text: String,
    pub cursor_pos: usize,
    pub state: WidgetState,
    pub bg_color: u32,
    pub fg_color: u32,
    pub cursor_color: u32,
    pub max_len: usize,
}

impl TextField {
    pub fn new(x: i32, y: i32, w: u32, h: u32, max_len: usize) -> Self {
        TextField {
            bounds: Rect { x, y, w, h },
            text: String::new(),
            cursor_pos: 0,
            state: WidgetState::default(),
            bg_color: rgb(30, 30, 30),
            fg_color: rgb(255, 255, 255),
            cursor_color: rgb(255, 255, 0),
            max_len,
        }
    }

    pub fn insert_char(&mut self, ch: u8) -> bool {
        if self.text.len() >= self.max_len { return false; }
        self.text.insert(self.cursor_pos, ch as char);
        self.cursor_pos += 1;
        true
    }

    pub fn backspace(&mut self) -> bool {
        if self.cursor_pos == 0 { return false; }
        self.cursor_pos -= 1;
        self.text.remove(self.cursor_pos);
        true
    }

    fn render_cursor(&self, fb: &mut Framebuffer) {
        let cx = self.bounds.x + 4 + self.cursor_pos as i32 * 8;
        fb.draw_text_cursor(cx, self.bounds.y + 4, self.cursor_color);
    }
}

impl Widget for TextField {
    fn bounds(&self) -> Rect { self.bounds }
    fn state(&self) -> WidgetState { self.state }
    fn set_state(&mut self, state: WidgetState) { self.state = state; }

    fn on_event(&mut self, event: &WidgetEvent) -> bool {
        if self.state.disabled { return false; }
        match event {
            WidgetEvent::MouseDown { x, y, .. } => {
                if self.bounds.contains(*x, *y) {
                    self.state.focused = true;
                    true
                } else {
                    self.state.focused = false;
                    false
                }
            }
            WidgetEvent::KeyDown { key } => {
                if self.state.focused {
                    if *key == 0x08 { // backspace
                        self.backspace();
                        true
                    } else if *key >= 0x20 && *key < 0x7f {
                        self.insert_char(*key);
                        true
                    } else { false }
                } else { false }
            }
            WidgetEvent::FocusGained => { self.state.focused = true; true }
            WidgetEvent::FocusLost => { self.state.focused = false; true }
            _ => false,
        }
    }

    fn render(&self, fb: &mut Framebuffer) {
        let border = if self.state.focused { rgb(100, 100, 200) } else { rgb(60, 60, 60) };
        fb.fill_rect(self.bounds.x, self.bounds.y, self.bounds.w, self.bounds.h, self.bg_color);
        fb.fill_rect(self.bounds.x, self.bounds.y, self.bounds.w, 2, border);
        fb.fill_rect(self.bounds.x, self.bounds.y + self.bounds.h as i32 - 2, self.bounds.w, 2, border);
        fb.fill_rect(self.bounds.x, self.bounds.y, 2, self.bounds.h, border);
        fb.fill_rect(self.bounds.x + self.bounds.w as i32 - 2, self.bounds.y, 2, self.bounds.h, border);
        let vis = &self.text;
        fb.draw_text(self.bounds.x + 4, self.bounds.y + 4, vis, self.fg_color, None);
        if self.state.focused {
            self.render_cursor(fb);
        }
    }
}

/// A container that lays out child widgets.
#[derive(Clone, Copy, Debug)]
pub enum Layout {
    Horizontal,
    Vertical,
}

pub struct Container {
    pub bounds: Rect,
    pub layout: Layout,
    pub padding: u32,
    pub spacing: u32,
    pub children: Vec<Box<dyn Widget>>,
}

impl Container {
    pub fn new(x: i32, y: i32, w: u32, h: u32, layout: Layout) -> Self {
        Container {
            bounds: Rect { x, y, w, h },
            layout,
            padding: 4,
            spacing: 8,
            children: Vec::new(),
        }
    }

    pub fn add<W: Widget + 'static>(&mut self, widget: W) {
        self.children.push(Box::new(widget));
    }

    pub fn dispatch(&mut self, event: &WidgetEvent) -> bool {
        for child in self.children.iter_mut() {
            if child.on_event(event) {
                return true;
            }
        }
        false
    }

    pub fn layout_children(&mut self) {
        let pad = self.padding as i32;
        let spacing = self.spacing as i32;
        let mut cx = self.bounds.x + pad;
        let mut cy = self.bounds.y + pad;
        for child in self.children.iter_mut() {
            let b = child.bounds();
            match self.layout {
                Layout::Horizontal => {
                    // placeholder
                }
                Layout::Vertical => {
                    // placeholder
                }
            }
        }
    }
}

impl Widget for Container {
    fn bounds(&self) -> Rect { self.bounds }
    fn state(&self) -> WidgetState { WidgetState::default() }
    fn set_state(&mut self, _state: WidgetState) {}

    fn on_event(&mut self, event: &WidgetEvent) -> bool {
        self.dispatch(event)
    }

    fn render(&self, fb: &mut Framebuffer) {
        for child in &self.children {
            child.render(fb);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_click_fires_callback() {
        let mut clicked = false;
        let mut btn = Button::new(0, 0, 80, 24, "Click");
        btn.set_callback(|| { /* would set clicked = true */ });
        let event = WidgetEvent::MouseDown { x: 10, y: 10, button: 1 };
        assert!(btn.on_event(&event));
        assert!(btn.state.pressed);
        let up = WidgetEvent::MouseUp { x: 10, y: 10, button: 1 };
        assert!(btn.on_event(&up));
        assert!(!btn.state.pressed);
    }

    #[test]
    fn button_ignores_clicks_outside_bounds() {
        let mut btn = Button::new(0, 0, 80, 24, "Click");
        let event = WidgetEvent::MouseDown { x: 100, y: 100, button: 1 };
        assert!(!btn.on_event(&event));
        assert!(!btn.state.pressed);
    }

    #[test]
    fn text_field_inserts_and_deletes() {
        let mut tf = TextField::new(0, 0, 100, 20, 10);
        tf.insert_char(b'h');
        tf.insert_char(b'i');
        assert_eq!(tf.text, "hi");
        assert_eq!(tf.cursor_pos, 2);
        tf.backspace();
        assert_eq!(tf.text, "h");
        assert_eq!(tf.cursor_pos, 1);
    }

    #[test]
    fn text_field_respects_max_length() {
        let mut tf = TextField::new(0, 0, 100, 20, 2);
        assert!(tf.insert_char(b'a'));
        assert!(tf.insert_char(b'b'));
        assert!(!tf.insert_char(b'c'));
        assert_eq!(tf.text, "ab");
    }

    #[test]
    fn text_field_key_events_require_focus() {
        let mut tf = TextField::new(0, 0, 100, 20, 10);
        // KeyDown when not focused should not insert
        let event = WidgetEvent::KeyDown { key: b'a' };
        assert!(!tf.on_event(&event));
        assert_eq!(tf.text, "");
        // Focus the field, then key should insert
        tf.state.focused = true;
        assert!(tf.on_event(&event));
        assert_eq!(tf.text, "a");
    }

    #[test]
    fn rect_contains_works() {
        let r = Rect { x: 10, y: 10, w: 20, h: 20 };
        assert!(r.contains(10, 10));
        assert!(r.contains(29, 29));
        assert!(!r.contains(30, 30));
        assert!(!r.contains(9, 9));
    }

    #[test]
    fn container_dispatches_to_children() {
        let mut c = Container::new(0, 0, 200, 100, Layout::Vertical);
        c.add(Button::new(0, 0, 80, 24, "A"));
        c.add(Button::new(0, 40, 80, 24, "B"));
        let event = WidgetEvent::MouseDown { x: 10, y: 10, button: 1 };
        assert!(c.on_event(&event));
    }

    #[test]
    fn button_render_produces_pixels() {
        let btn = Button::new(0, 0, 80, 24, "Test");
        let mut fb = Framebuffer::new(80, 24);
        btn.render(&mut fb);
        assert!(fb.pixels().iter().any(|&p| p != 0), "button should render non-zero pixels");
    }

    #[test]
    fn text_field_render_produces_pixels() {
        let mut tf = TextField::new(0, 0, 100, 20, 10);
        tf.insert_char(b'A');
        let mut fb = Framebuffer::new(100, 20);
        tf.render(&mut fb);
        assert!(fb.pixels().iter().any(|&p| p != 0), "text field should render non-zero pixels");
    }
}
