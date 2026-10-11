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
    /// Moves the widget, preserving its size unless the layout overrides it.
    ///
    /// Default keeps bounds unchanged, so third-party widgets that do not
    /// participate in layout still work inside a `Container`.
    fn move_to(&mut self, _x: i32, _y: i32) {}
    /// Resizes the widget. Default keeps the current size.
    fn resize(&mut self, _w: u32, _h: u32) {}
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
    fn move_to(&mut self, x: i32, y: i32) {
        self.bounds.x = x;
        self.bounds.y = y;
    }
    fn resize(&mut self, w: u32, h: u32) {
        self.bounds.w = w;
        self.bounds.h = h;
    }

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
    /// Selection anchor (byte index), if a range is selected. A click-drag
    /// from the anchor to the cursor defines the range; typing or
    /// backspacing replaces/deletes it first, as in any text box.
    pub sel_anchor: Option<usize>,
    pub state: WidgetState,
    pub bg_color: u32,
    pub fg_color: u32,
    pub cursor_color: u32,
    pub sel_color: u32,
    pub max_len: usize,
}

impl TextField {
    pub fn new(x: i32, y: i32, w: u32, h: u32, max_len: usize) -> Self {
        TextField {
            bounds: Rect { x, y, w, h },
            text: String::new(),
            cursor_pos: 0,
            sel_anchor: None,
            state: WidgetState::default(),
            bg_color: rgb(30, 30, 30),
            fg_color: rgb(255, 255, 255),
            cursor_color: rgb(255, 255, 0),
            sel_color: rgb(60, 80, 160),
            max_len,
        }
    }

    /// Character index under window-local x (8px per cell, 4px inset).
    fn pos_from_x(&self, x: i32) -> usize {
        let rel = x - self.bounds.x - 4;
        if rel <= 0 {
            return 0;
        }
        ((rel / 8) as usize).min(self.text.len())
    }

    /// Ordered selected byte range, if a non-empty selection exists.
    pub fn selected_range(&self) -> Option<(usize, usize)> {
        let a = self.sel_anchor?;
        let (lo, hi) = if a < self.cursor_pos {
            (a, self.cursor_pos)
        } else {
            (self.cursor_pos, a)
        };
        if lo == hi {
            None
        } else {
            Some((lo.min(self.text.len()), hi.min(self.text.len())))
        }
    }

    /// Selected text, if any.
    pub fn selected_text(&self) -> Option<&str> {
        let (lo, hi) = self.selected_range()?;
        self.text.get(lo..hi)
    }

    /// Selects the whole contents.
    pub fn select_all(&mut self) {
        if self.text.is_empty() {
            self.sel_anchor = None;
        } else {
            self.sel_anchor = Some(0);
            self.cursor_pos = self.text.len();
        }
    }

    /// Clears any selection, keeping the cursor where it is.
    pub fn clear_selection(&mut self) {
        self.sel_anchor = None;
    }

    /// Deletes the selected range, placing the cursor at its start.
    pub fn delete_selection(&mut self) -> bool {
        let Some((lo, hi)) = self.selected_range() else {
            return false;
        };
        self.text.drain(lo..hi);
        self.cursor_pos = lo;
        self.sel_anchor = None;
        true
    }

    pub fn insert_char(&mut self, ch: u8) -> bool {
        self.delete_selection();
        if self.text.len() >= self.max_len { return false; }
        self.text.insert(self.cursor_pos, ch as char);
        self.cursor_pos += 1;
        true
    }

    pub fn backspace(&mut self) -> bool {
        if self.delete_selection() {
            return true;
        }
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
    fn move_to(&mut self, x: i32, y: i32) {
        self.bounds.x = x;
        self.bounds.y = y;
    }
    fn resize(&mut self, w: u32, h: u32) {
        self.bounds.w = w;
        self.bounds.h = h;
    }

    fn on_event(&mut self, event: &WidgetEvent) -> bool {
        if self.state.disabled { return false; }
        match event {
            WidgetEvent::MouseDown { x, y, .. } => {
                if self.bounds.contains(*x, *y) {
                    self.state.focused = true;
                    // Click-drag selection starts here; MouseUp completes it.
                    self.cursor_pos = self.pos_from_x(*x);
                    self.sel_anchor = Some(self.cursor_pos);
                    true
                } else {
                    self.state.focused = false;
                    self.sel_anchor = None;
                    false
                }
            }
            WidgetEvent::MouseUp { x, y, .. } => {
                if !self.state.focused {
                    return false;
                }
                if self.bounds.contains(*x, *y) {
                    self.cursor_pos = self.pos_from_x(*x);
                    // A plain click leaves an empty range, which reads as
                    // no selection; a real drag keeps the anchor-to-cursor
                    // range alive.
                    if self.selected_range().is_none() {
                        self.sel_anchor = None;
                    }
                    true
                } else {
                    self.sel_anchor = None;
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
        if let Some((lo, hi)) = self.selected_range() {
            let x0 = self.bounds.x + 4 + lo as i32 * 8;
            let w = (hi - lo) as u32 * 8;
            fb.fill_rect(x0, self.bounds.y + 4, w, 8, self.sel_color);
        }
        let vis = &self.text;
        fb.draw_text(self.bounds.x + 4, self.bounds.y + 4, vis, self.fg_color, None);
        if self.state.focused {
            self.render_cursor(fb);
        }
    }
}

/// A container that lays out child widgets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    Horizontal,
    Vertical,
    /// Fixed grid: `cols` columns, rows derived from child count.
    Grid { cols: u32 },
}

pub struct Container {
    pub bounds: Rect,
    pub layout: Layout,
    pub padding: u32,
    pub spacing: u32,
    pub children: Vec<Box<dyn Widget>>,
    /// Index of the child holding keyboard focus, if any.
    pub focused_idx: Option<usize>,
}

impl Container {
    pub fn new(x: i32, y: i32, w: u32, h: u32, layout: Layout) -> Self {
        Container {
            bounds: Rect { x, y, w, h },
            layout,
            padding: 4,
            spacing: 8,
            children: Vec::new(),
            focused_idx: None,
        }
    }

    pub fn add<W: Widget + 'static>(&mut self, widget: W) {
        self.children.push(Box::new(widget));
        if self.focused_idx.is_none() {
            self.focused_idx = Some(0);
        }
    }

    /// Topmost-first dispatch for mouse, focused-first for keys.
    pub fn dispatch(&mut self, event: &WidgetEvent) -> bool {
        match event {
            WidgetEvent::KeyDown { .. } | WidgetEvent::KeyUp { .. } => {
                // Keys go to the focused child only, so two text fields do
                // not both type the same keystroke.
                if let Some(idx) = self.focused_idx {
                    if let Some(child) = self.children.get_mut(idx) {
                        if !child.state().disabled {
                            return child.on_event(event);
                        }
                    }
                }
                false
            }
            WidgetEvent::MouseDown { x, y, .. }
            | WidgetEvent::MouseUp { x, y, .. }
            | WidgetEvent::MouseMove { x, y } => {
                // Hit-test topmost last: children later in the vec paint
                // on top, so they get first refusal on the pointer.
                for (idx, child) in self.children.iter_mut().enumerate().rev() {
                    if child.state().disabled {
                        continue;
                    }
                    let hit = child.bounds().contains(*x, *y);
                    if hit && child.on_event(event) {
                        self.set_focus(idx);
                        return true;
                    }
                }
                false
            }
            WidgetEvent::FocusGained | WidgetEvent::FocusLost => false,
        }
    }

    /// Moves keyboard focus, skipping disabled children with wraparound.
    pub fn focus_next(&mut self) {
        if self.children.is_empty() {
            self.focused_idx = None;
            return;
        }
        let n = self.children.len();
        let start = self.focused_idx.map(|i| (i + 1) % n).unwrap_or(0);
        for k in 0..n {
            let idx = (start + k) % n;
            if !self.children[idx].state().disabled {
                self.set_focus(idx);
                return;
            }
        }
    }

    /// Moves keyboard focus backwards, skipping disabled children.
    pub fn focus_prev(&mut self) {
        if self.children.is_empty() {
            self.focused_idx = None;
            return;
        }
        let n = self.children.len();
        let start = self
            .focused_idx
            .map(|i| (i + n - 1) % n)
            .unwrap_or(n - 1);
        for k in 0..n {
            let idx = (start + n - k) % n;
            if !self.children[idx].state().disabled {
                self.set_focus(idx);
                return;
            }
        }
    }

    fn set_focus(&mut self, idx: usize) {
        if let Some(old) = self.focused_idx {
            if old != idx {
                if let Some(child) = self.children.get_mut(old) {
                    let mut st = child.state();
                    st.focused = false;
                    child.set_state(st);
                }
            }
        }
        self.focused_idx = Some(idx);
        if let Some(child) = self.children.get_mut(idx) {
            let mut st = child.state();
            st.focused = true;
            child.set_state(st);
        }
    }

    /// Positions children inside the container rect.
    ///
    /// Horizontal packs left-to-right, vertical top-to-bottom, grid fills
    /// row-major with equal cells. Children keep their own size; the
    /// container only assigns their top-left corner via `Widget::move_to`.
    pub fn layout_children(&mut self) {
        let pad = self.padding as i32;
        let spacing = self.spacing as i32;
        match self.layout {
            Layout::Horizontal => {
                let mut cx = self.bounds.x + pad;
                for child in self.children.iter_mut() {
                    let b = child.bounds();
                    child.move_to(cx, self.bounds.y + pad);
                    cx += b.w as i32 + spacing;
                }
            }
            Layout::Vertical => {
                let mut cy = self.bounds.y + pad;
                for child in self.children.iter_mut() {
                    let b = child.bounds();
                    child.move_to(self.bounds.x + pad, cy);
                    cy += b.h as i32 + spacing;
                }
            }
            Layout::Grid { cols } => {
                let cols = cols.max(1) as usize;
                let cell_w = if self.bounds.w > 2 * self.padding {
                    (self.bounds.w - 2 * self.padding) / cols as u32
                } else {
                    self.bounds.w
                };
                for (i, child) in self.children.iter_mut().enumerate() {
                    let b = child.bounds();
                    let col = (i % cols) as i32;
                    let row = (i / cols) as i32;
                    // Row height follows the child's own height; grid only
                    // aligns columns, it does not stretch rows.
                    let nx = self.bounds.x + pad + col * (cell_w as i32 + spacing);
                    let ny = self.bounds.y + pad + row * (b.h as i32 + spacing);
                    child.move_to(nx, ny);
                    if b.w > cell_w {
                        child.resize(cell_w, b.h);
                    }
                }
            }
        }
    }
}

impl Widget for Container {
    fn bounds(&self) -> Rect { self.bounds }
    fn state(&self) -> WidgetState { WidgetState::default() }
    fn set_state(&mut self, _state: WidgetState) {}
    fn move_to(&mut self, x: i32, y: i32) {
        let dx = x - self.bounds.x;
        let dy = y - self.bounds.y;
        self.bounds.x = x;
        self.bounds.y = y;
        // Keep children glued to the container when it moves.
        for child in self.children.iter_mut() {
            let b = child.bounds();
            child.move_to(b.x + dx, b.y + dy);
        }
    }
    fn resize(&mut self, w: u32, h: u32) {
        self.bounds.w = w;
        self.bounds.h = h;
    }

    fn on_event(&mut self, event: &WidgetEvent) -> bool {
        self.dispatch(event)
    }

    fn render(&self, fb: &mut Framebuffer) {
        for child in &self.children {
            child.render(fb);
        }
    }
}

/// One tab in a `TabStrip`: a stable id plus its label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tab {
    pub id: u32,
    pub title: String,
}

/// A tab strip: the header row of a tabbed window (terminal tabs, editor
/// tabs, window-switcher lists). Tabs share the strip width evenly; each
/// carries a small close box on its right edge.
#[derive(Clone, Debug)]
pub struct TabStrip {
    pub bounds: Rect,
    pub tabs: Vec<Tab>,
    /// Index into `tabs` of the visible tab, if any.
    pub selected: Option<usize>,
    pub state: WidgetState,
    next_id: u32,
    /// Header height in pixels.
    pub tab_h: u32,
    /// Close-box width in pixels at each tab's right edge.
    pub close_w: u32,
    bg_color: u32,
    sel_color: u32,
    fg_color: u32,
}

impl TabStrip {
    pub fn new(x: i32, y: i32, w: u32, h: u32) -> Self {
        TabStrip {
            bounds: Rect { x, y, w, h },
            tabs: Vec::new(),
            selected: None,
            state: WidgetState::default(),
            next_id: 1,
            tab_h: 20,
            close_w: 16,
            bg_color: rgb(45, 45, 60),
            sel_color: rgb(70, 70, 100),
            fg_color: rgb(255, 255, 255),
        }
    }

    /// Appends a tab and selects it when nothing is selected.
    pub fn add_tab(&mut self, title: &str) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.tabs.push(Tab {
            id,
            title: title.to_string(),
        });
        if self.selected.is_none() {
            self.selected = Some(0);
        }
        id
    }

    /// Removes a tab, keeping the selection on a live neighbour.
    pub fn close_tab(&mut self, id: u32) -> bool {
        let Some(idx) = self.tabs.iter().position(|t| t.id == id) else {
            return false;
        };
        self.tabs.remove(idx);
        self.selected = match self.selected {
            None => None,
            Some(s) if self.tabs.is_empty() => None,
            Some(s) if s == idx => Some(idx.min(self.tabs.len() - 1)),
            Some(s) if s > idx => Some(s - 1),
            Some(s) => Some(s),
        };
        true
    }

    /// Selects a tab. Returns false for an unknown id.
    pub fn select(&mut self, id: u32) -> bool {
        match self.tabs.iter().position(|t| t.id == id) {
            Some(idx) => {
                self.selected = Some(idx);
                true
            }
            None => false,
        }
    }

    /// Id of the visible tab, if any.
    pub fn selected_id(&self) -> Option<u32> {
        self.selected.and_then(|i| self.tabs.get(i)).map(|t| t.id)
    }

    fn cell_w(&self) -> u32 {
        if self.tabs.is_empty() {
            self.bounds.w
        } else {
            self.bounds.w / self.tabs.len() as u32
        }
    }

    /// Tab index under `(x, y)`, header row only.
    pub fn tab_at(&self, x: i32, y: i32) -> Option<usize> {
        if self.tabs.is_empty() || !self.bounds.contains(x, y) {
            return None;
        }
        if y >= self.bounds.y + self.tab_h as i32 {
            return None;
        }
        let idx = ((x - self.bounds.x) as u32 / self.cell_w().max(1)) as usize;
        if idx < self.tabs.len() {
            Some(idx)
        } else {
            None
        }
    }

    /// Whether `(x, y)` lands in tab `idx`'s close box.
    fn close_at(&self, idx: usize, x: i32, y: i32) -> bool {
        let cw = self.cell_w() as i32;
        let x0 = self.bounds.x + idx as i32 * cw;
        x >= x0 + cw - self.close_w as i32
            && x < x0 + cw
            && y >= self.bounds.y + 2
            && y < self.bounds.y + 2 + 12
    }
}

impl Widget for TabStrip {
    fn bounds(&self) -> Rect {
        self.bounds
    }
    fn state(&self) -> WidgetState {
        self.state
    }
    fn set_state(&mut self, state: WidgetState) {
        self.state = state;
    }
    fn move_to(&mut self, x: i32, y: i32) {
        self.bounds.x = x;
        self.bounds.y = y;
    }
    fn resize(&mut self, w: u32, h: u32) {
        self.bounds.w = w;
        self.bounds.h = h;
    }

    fn on_event(&mut self, event: &WidgetEvent) -> bool {
        if self.state.disabled {
            return false;
        }
        match event {
            WidgetEvent::MouseDown { x, y, .. } => {
                let Some(idx) = self.tab_at(*x, *y) else {
                    return false;
                };
                let id = self.tabs[idx].id;
                if self.close_at(idx, *x, *y) {
                    self.close_tab(id);
                } else {
                    self.selected = Some(idx);
                }
                true
            }
            _ => false,
        }
    }

    fn render(&self, fb: &mut Framebuffer) {
        if self.tabs.is_empty() {
            return;
        }
        let cw = self.cell_w();
        for (i, tab) in self.tabs.iter().enumerate() {
            let x = self.bounds.x + i as i32 * cw as i32;
            let color = if Some(i) == self.selected {
                self.sel_color
            } else {
                self.bg_color
            };
            fb.fill_rect(x, self.bounds.y, cw, self.tab_h, color);
            // Room for the close box plus insets, in characters.
            let max_chars = (cw.saturating_sub(self.close_w + 8) / 8).max(1) as usize;
            let label: String = tab.title.chars().take(max_chars).collect();
            fb.draw_text(x + 4, self.bounds.y + 6, &label, self.fg_color, None);
            fb.draw_text(
                x + cw as i32 - self.close_w as i32 + 4,
                self.bounds.y + 6,
                "x",
                self.fg_color,
                None,
            );
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

    #[test]
    fn horizontal_layout_packs_left_to_right() {
        let mut c = Container::new(10, 20, 200, 100, Layout::Horizontal);
        c.padding = 4;
        c.spacing = 8;
        c.add(Button::new(0, 0, 40, 24, "A"));
        c.add(Button::new(0, 0, 30, 24, "B"));
        c.layout_children();
        assert_eq!(c.children[0].bounds(), Rect { x: 14, y: 24, w: 40, h: 24 });
        assert_eq!(c.children[1].bounds(), Rect { x: 62, y: 24, w: 30, h: 24 });
    }

    #[test]
    fn vertical_layout_packs_top_to_bottom() {
        let mut c = Container::new(10, 20, 200, 100, Layout::Vertical);
        c.padding = 4;
        c.spacing = 8;
        c.add(Button::new(0, 0, 80, 24, "A"));
        c.add(Button::new(0, 0, 80, 24, "B"));
        c.layout_children();
        assert_eq!(c.children[0].bounds(), Rect { x: 14, y: 24, w: 80, h: 24 });
        assert_eq!(c.children[1].bounds(), Rect { x: 14, y: 56, w: 80, h: 24 });
    }

    #[test]
    fn grid_layout_fills_row_major_with_equal_cells() {
        let mut c = Container::new(0, 0, 100, 100, Layout::Grid { cols: 2 });
        c.padding = 0;
        c.spacing = 0;
        for _ in 0..4 {
            c.add(Button::new(0, 0, 20, 10, "x"));
        }
        c.layout_children();
        assert_eq!(c.children[0].bounds().x, 0);
        assert_eq!(c.children[1].bounds().x, 50);
        assert_eq!(c.children[2].bounds().x, 0);
        assert_eq!(c.children[2].bounds().y, 10);
    }

    #[test]
    fn keys_go_to_the_focused_child_only() {
        let mut c = Container::new(0, 0, 200, 100, Layout::Vertical);
        c.add(TextField::new(0, 0, 100, 20, 10));
        c.add(TextField::new(0, 0, 100, 20, 10));
        // First child starts focused.
        assert_eq!(c.focused_idx, Some(0));
        c.on_event(&WidgetEvent::KeyDown { key: b'a' });
        // Disabled child is skipped by focus navigation.
        c.children[1].set_state(WidgetState { disabled: true, ..WidgetState::default() });
        c.focus_next();
        assert_eq!(c.focused_idx, Some(0), "disabled child must be skipped");
        c.children[1].set_state(WidgetState::default());
        c.focus_next();
        assert_eq!(c.focused_idx, Some(1));
        c.focus_prev();
        assert_eq!(c.focused_idx, Some(0));
    }

    #[test]
    fn disabled_children_never_handle_events() {
        let mut c = Container::new(0, 0, 200, 100, Layout::Vertical);
        let mut b = Button::new(0, 0, 80, 24, "A");
        b.state.disabled = true;
        c.add(b);
        let event = WidgetEvent::MouseDown { x: 10, y: 10, button: 1 };
        assert!(!c.on_event(&event));
    }

    #[test]
    fn click_drag_selects_typing_replaces_and_backspace_deletes() {
        let mut tf = TextField::new(0, 0, 100, 20, 10);
        for b in b"hello" {
            tf.insert_char(*b);
        }
        // Drag from the second cell to the fourth.
        assert!(tf.on_event(&WidgetEvent::MouseDown { x: 4 + 8, y: 10, button: 1 }));
        assert!(tf.on_event(&WidgetEvent::MouseUp { x: 4 + 3 * 8, y: 10, button: 1 }));
        assert_eq!(tf.selected_text(), Some("el"));
        // Typing replaces the selection.
        tf.state.focused = true;
        assert!(tf.on_event(&WidgetEvent::KeyDown { key: b'X' }));
        assert_eq!(tf.text, "hXlo");
        assert_eq!(tf.selected_text(), None);
        // A plain click clears any selection.
        assert!(tf.on_event(&WidgetEvent::MouseDown { x: 4, y: 10, button: 1 }));
        assert!(tf.on_event(&WidgetEvent::MouseUp { x: 4, y: 10, button: 1 }));
        assert_eq!(tf.selected_text(), None);
    }

    #[test]
    fn select_all_and_delete_selection() {
        let mut tf = TextField::new(0, 0, 100, 20, 10);
        tf.select_all();
        assert_eq!(tf.selected_text(), None, "empty field selects nothing");
        for b in b"abc" {
            tf.insert_char(*b);
        }
        tf.select_all();
        assert_eq!(tf.selected_text(), Some("abc"));
        assert!(tf.delete_selection());
        assert_eq!(tf.text, "");
        assert!(!tf.delete_selection(), "nothing left to delete");
    }

    #[test]
    fn tabstrip_selects_and_closes_tabs() {
        let mut ts = TabStrip::new(0, 0, 200, 20);
        assert_eq!(ts.selected_id(), None);
        let a = ts.add_tab("sh");
        let b = ts.add_tab("edit");
        assert_eq!(ts.selected_id(), Some(a), "first tab auto-selects");
        assert!(ts.select(b));
        assert_eq!(ts.selected_id(), Some(b));
        assert!(!ts.select(999));
        // Clicking the second tab's body selects it (already selected).
        assert!(ts.on_event(&WidgetEvent::MouseDown { x: 110, y: 10, button: 1 }));
        assert_eq!(ts.selected_id(), Some(b));
        // Clicking the first tab selects it.
        assert!(ts.on_event(&WidgetEvent::MouseDown { x: 10, y: 10, button: 1 }));
        assert_eq!(ts.selected_id(), Some(a));
        // Closing the selected tab moves selection to the neighbour.
        assert!(ts.close_tab(a));
        assert_eq!(ts.selected_id(), Some(b));
        assert!(!ts.close_tab(a));
        assert!(ts.close_tab(b));
        assert_eq!(ts.selected_id(), None);
    }

    #[test]
    fn tabstrip_close_box_removes_without_selecting() {
        let mut ts = TabStrip::new(0, 0, 200, 20);
        let a = ts.add_tab("sh");
        let b = ts.add_tab("edit");
        ts.select(a);
        // Close box: last 16px of the second tab (x in 184..200, y in 2..14).
        assert!(ts.on_event(&WidgetEvent::MouseDown { x: 190, y: 8, button: 1 }));
        assert_eq!(ts.tabs.len(), 1);
        assert_eq!(ts.selected_id(), Some(a), "selection stays on the survivor");
        assert_eq!(ts.tabs[0].id, a);
        let _ = b;
    }

    #[test]
    fn tabstrip_ignores_misses_and_disabled() {
        let mut ts = TabStrip::new(0, 0, 200, 20);
        ts.add_tab("sh");
        assert!(!ts.on_event(&WidgetEvent::MouseDown { x: 10, y: 40, button: 1 }));
        assert!(!ts.on_event(&WidgetEvent::MouseDown { x: 500, y: 10, button: 1 }));
        ts.state.disabled = true;
        assert!(!ts.on_event(&WidgetEvent::MouseDown { x: 10, y: 10, button: 1 }));
    }

    #[test]
    fn tabstrip_render_produces_pixels() {
        let mut ts = TabStrip::new(0, 0, 200, 20);
        ts.add_tab("sh");
        ts.add_tab("edit");
        let mut fb = Framebuffer::new(200, 20);
        ts.render(&mut fb);
        assert!(fb.pixels().iter().any(|&p| p != 0));
    }
}
