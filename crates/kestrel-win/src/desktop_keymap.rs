//! Pure input mapping for remote desktop: browser `KeyboardEvent.code` →
//! (virtual key, set-1 scan code, extended flag), text → key events,
//! normalised coordinates → `SendInput` absolute coordinates, wheel notches.
//! Platform independent and unit-tested everywhere.
//!
//! Scan codes are the PC/AT set-1 make codes (Microsoft "Keyboard Scan Code
//! Specification"); keys with an `E0` prefix are sent with
//! `KEYEVENTF_EXTENDEDKEY`. Microsoft's "About Keyboard Input" lists the
//! extended keys: right Alt/Ctrl, Insert/Delete/Home/End/PageUp/PageDown and
//! the arrows in the clusters left of the numeric keypad, NumLock, Break,
//! PrintScreen, and the keypad's divide and Enter keys. Keys with no usable
//! scan code (Pause = `E1 1D 45`) carry `scan == 0` and are injected by
//! virtual key only.

/// How to inject one physical key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySpec {
    pub vk: u16,
    /// Set-1 make code without the `E0` prefix; 0 = inject by `vk` only.
    pub scan: u16,
    pub extended: bool,
}

const fn k(vk: u16, scan: u16) -> KeySpec {
    KeySpec {
        vk,
        scan,
        extended: false,
    }
}

const fn x(vk: u16, scan: u16) -> KeySpec {
    KeySpec {
        vk,
        scan,
        extended: true,
    }
}

/// Map a browser `KeyboardEvent.code` (layout independent) to a key.
/// Unknown codes → `None` (the caller drops the event).
pub fn key_for_code(code: &str) -> Option<KeySpec> {
    // Letters: VK = ASCII upper-case, set-1 codes in QWERTY order.
    if let Some(l) = code.strip_prefix("Key") {
        let b = l.as_bytes();
        if b.len() == 1 && b[0].is_ascii_uppercase() {
            const SCAN: [u16; 26] = [
                0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31,
                0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
            ];
            return Some(k(b[0] as u16, SCAN[(b[0] - b'A') as usize]));
        }
        return None;
    }
    if let Some(d) = code.strip_prefix("Digit") {
        let b = d.as_bytes();
        if b.len() == 1 && b[0].is_ascii_digit() {
            let n = (b[0] - b'0') as u16;
            let scan = if n == 0 { 0x0B } else { 0x01 + n };
            return Some(k(b[0] as u16, scan));
        }
        return None;
    }
    if let Some(d) = code.strip_prefix("Numpad") {
        let b = d.as_bytes();
        if b.len() == 1 && b[0].is_ascii_digit() {
            const SCAN: [u16; 10] = [0x52, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49];
            let n = (b[0] - b'0') as usize;
            return Some(k(0x60 + n as u16, SCAN[n]));
        }
    }
    if let Some(f) = code.strip_prefix('F') {
        if let Ok(n) = f.parse::<u16>() {
            if f.len() <= 2 && !f.starts_with('0') {
                let scan = match n {
                    1..=10 => 0x3A + n,
                    11 => 0x57,
                    12 => 0x58,
                    13..=23 => 0x64 + (n - 13),
                    24 => 0x76,
                    _ => return None,
                };
                return Some(k(0x6F + n, scan)); // VK_F1 = 0x70
            }
            return None;
        }
    }
    Some(match code {
        "Escape" => k(0x1B, 0x01),
        "Minus" => k(0xBD, 0x0C),
        "Equal" => k(0xBB, 0x0D),
        "Backspace" => k(0x08, 0x0E),
        "Tab" => k(0x09, 0x0F),
        "BracketLeft" => k(0xDB, 0x1A),
        "BracketRight" => k(0xDD, 0x1B),
        "Enter" => k(0x0D, 0x1C),
        "ControlLeft" => k(0xA2, 0x1D),
        "Semicolon" => k(0xBA, 0x27),
        "Quote" => k(0xDE, 0x28),
        "Backquote" => k(0xC0, 0x29),
        "ShiftLeft" => k(0xA0, 0x2A),
        "Backslash" => k(0xDC, 0x2B),
        "Comma" => k(0xBC, 0x33),
        "Period" => k(0xBE, 0x34),
        "Slash" => k(0xBF, 0x35),
        "ShiftRight" => k(0xA1, 0x36),
        "NumpadMultiply" => k(0x6A, 0x37),
        "AltLeft" => k(0xA4, 0x38),
        "Space" => k(0x20, 0x39),
        "CapsLock" => k(0x14, 0x3A),
        "NumLock" => x(0x90, 0x45),
        "ScrollLock" => k(0x91, 0x46),
        "NumpadSubtract" => k(0x6D, 0x4A),
        "NumpadAdd" => k(0x6B, 0x4E),
        "NumpadDecimal" => k(0x6E, 0x53),
        "IntlBackslash" => k(0xE2, 0x56),
        "NumpadEnter" => x(0x0D, 0x1C),
        "ControlRight" => x(0xA3, 0x1D),
        "NumpadDivide" => x(0x6F, 0x35),
        "PrintScreen" => x(0x2C, 0x37),
        "AltRight" => x(0xA5, 0x38),
        "Home" => x(0x24, 0x47),
        "ArrowUp" => x(0x26, 0x48),
        "PageUp" => x(0x21, 0x49),
        "ArrowLeft" => x(0x25, 0x4B),
        "ArrowRight" => x(0x27, 0x4D),
        "End" => x(0x23, 0x4F),
        "ArrowDown" => x(0x28, 0x50),
        "PageDown" => x(0x22, 0x51),
        "Insert" => x(0x2D, 0x52),
        "Delete" => x(0x2E, 0x53),
        "MetaLeft" | "OSLeft" => x(0x5B, 0x5B),
        "MetaRight" | "OSRight" => x(0x5C, 0x5C),
        "ContextMenu" => x(0x5D, 0x5D),
        "AudioVolumeMute" | "VolumeMute" => x(0xAD, 0x20),
        "AudioVolumeDown" | "VolumeDown" => x(0xAE, 0x2E),
        "AudioVolumeUp" | "VolumeUp" => x(0xAF, 0x30),
        "Pause" => k(0x13, 0),
        _ => return None,
    })
}

/// One injected key for `InputEvent::Text`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKey {
    /// `KEYEVENTF_UNICODE` with this UTF-16 code unit (down + up).
    Unicode(u16),
    /// A real key press (Enter for line breaks, Tab).
    Key(KeySpec),
}

/// Text → key events: line breaks (`\r\n`, `\n`, `\r`) become Enter, `\t`
/// becomes Tab, other control characters are dropped, everything else is
/// sent as UTF-16 code units (surrogate pairs as two units, in order).
pub fn text_keys(text: &str) -> Vec<TextKey> {
    let enter = key_for_code("Enter").map(TextKey::Key);
    let tab = key_for_code("Tab").map(TextKey::Key);
    let mut out = Vec::with_capacity(text.len());
    let mut prev_cr = false;
    for c in text.chars() {
        match c {
            '\r' => out.extend(enter),
            '\n' if prev_cr => {}
            '\n' => out.extend(enter),
            '\t' => out.extend(tab),
            c if c.is_control() => {}
            c => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    out.push(TextKey::Unicode(*u));
                }
            }
        }
        prev_cr = c == '\r';
    }
    out
}

/// The captured virtual screen in physical pixels (origin may be negative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualScreen {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// Normalised `0..=1` → pixel offset inside a span of `len` pixels.
fn norm_to_px(v: f32, len: i32) -> i64 {
    let len = len.max(1) as i64;
    let v = if v.is_finite() {
        v.clamp(0.0, 1.0)
    } else {
        0.0
    } as f64;
    ((v * (len - 1) as f64).round() as i64).clamp(0, len - 1)
}

/// Pixel offset → `SendInput` absolute coordinate (0..=65535 over the span,
/// `MOUSEEVENTF_VIRTUALDESK`). Windows maps an absolute coordinate `a` to
/// pixel `floor(a * len / 65536)`; `ceil(px * 65536 / len)` is the smallest
/// `a` that lands exactly on `px`.
fn px_to_abs(px: i64, len: i32) -> i32 {
    let len = len.max(1) as i64;
    (((px * 65_536) + len - 1) / len).clamp(0, 65_535) as i32
}

/// Normalised coordinates → `MOUSEINPUT.dx/dy` for
/// `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`.
pub fn to_absolute(x: f32, y: f32, vs: &VirtualScreen) -> (i32, i32) {
    (
        px_to_abs(norm_to_px(x, vs.w), vs.w),
        px_to_abs(norm_to_px(y, vs.h), vs.h),
    )
}

/// Normalised coordinates → desktop pixel (virtual-screen coordinates; for
/// logs and tests).
pub fn to_pixel(x: f32, y: f32, vs: &VirtualScreen) -> (i32, i32) {
    (
        vs.x + norm_to_px(x, vs.w) as i32,
        vs.y + norm_to_px(y, vs.h) as i32,
    )
}

/// Pixel Windows lands on for absolute coordinate `a` over a span of `len`.
pub fn abs_to_px(a: i32, len: i32) -> i32 {
    ((a as i64 * len.max(1) as i64) / 65_536) as i32
}

/// Wheel notches → `mouseData` (multiples of `WHEEL_DELTA` = 120; positive =
/// away from the user / right). `None` when the delta rounds to zero.
pub fn wheel_data(notches: f32) -> Option<i32> {
    if !notches.is_finite() {
        return None;
    }
    let v = (notches.clamp(-50.0, 50.0) * 120.0).round() as i32;
    (v != 0).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_digits_function_keys() {
        assert_eq!(key_for_code("KeyA"), Some(k(0x41, 0x1E)));
        assert_eq!(key_for_code("KeyQ"), Some(k(0x51, 0x10)));
        assert_eq!(key_for_code("KeyZ"), Some(k(0x5A, 0x2C)));
        assert_eq!(key_for_code("KeyM"), Some(k(0x4D, 0x32)));
        assert_eq!(key_for_code("Digit1"), Some(k(0x31, 0x02)));
        assert_eq!(key_for_code("Digit9"), Some(k(0x39, 0x0A)));
        assert_eq!(key_for_code("Digit0"), Some(k(0x30, 0x0B)));
        assert_eq!(key_for_code("F1"), Some(k(0x70, 0x3B)));
        assert_eq!(key_for_code("F10"), Some(k(0x79, 0x44)));
        assert_eq!(key_for_code("F11"), Some(k(0x7A, 0x57)));
        assert_eq!(key_for_code("F12"), Some(k(0x7B, 0x58)));
        assert_eq!(key_for_code("F13"), Some(k(0x7C, 0x64)));
        assert_eq!(key_for_code("F24"), Some(k(0x87, 0x76)));
        assert_eq!(key_for_code("Numpad0"), Some(k(0x60, 0x52)));
        assert_eq!(key_for_code("Numpad7"), Some(k(0x67, 0x47)));
        // Every letter maps to a distinct scan code.
        let mut seen = std::collections::HashSet::new();
        for c in b'A'..=b'Z' {
            let s = key_for_code(&format!("Key{}", c as char)).unwrap();
            assert_eq!(s.vk, c as u16);
            assert!(!s.extended);
            assert!(seen.insert(s.scan));
        }
    }

    #[test]
    fn editing_and_modifiers() {
        assert_eq!(key_for_code("Enter"), Some(k(0x0D, 0x1C)));
        assert_eq!(key_for_code("Backspace"), Some(k(0x08, 0x0E)));
        assert_eq!(key_for_code("Tab"), Some(k(0x09, 0x0F)));
        assert_eq!(key_for_code("Escape"), Some(k(0x1B, 0x01)));
        assert_eq!(key_for_code("ShiftLeft"), Some(k(0xA0, 0x2A)));
        assert_eq!(key_for_code("ShiftRight"), Some(k(0xA1, 0x36)));
        assert_eq!(key_for_code("ControlLeft"), Some(k(0xA2, 0x1D)));
        assert_eq!(key_for_code("ControlRight"), Some(x(0xA3, 0x1D)));
        assert_eq!(key_for_code("AltLeft"), Some(k(0xA4, 0x38)));
        assert_eq!(key_for_code("AltRight"), Some(x(0xA5, 0x38)));
        assert_eq!(key_for_code("MetaLeft"), Some(x(0x5B, 0x5B)));
        assert_eq!(key_for_code("MetaRight"), Some(x(0x5C, 0x5C)));
        assert_eq!(key_for_code("OSLeft"), key_for_code("MetaLeft"));
    }

    #[test]
    fn extended_keys() {
        for (code, vk, scan) in [
            ("ArrowUp", 0x26, 0x48),
            ("ArrowDown", 0x28, 0x50),
            ("ArrowLeft", 0x25, 0x4B),
            ("ArrowRight", 0x27, 0x4D),
            ("Delete", 0x2E, 0x53),
            ("Insert", 0x2D, 0x52),
            ("Home", 0x24, 0x47),
            ("End", 0x23, 0x4F),
            ("PageUp", 0x21, 0x49),
            ("PageDown", 0x22, 0x51),
            ("NumpadEnter", 0x0D, 0x1C),
            ("NumpadDivide", 0x6F, 0x35),
            ("NumLock", 0x90, 0x45),
            ("PrintScreen", 0x2C, 0x37),
        ] {
            assert_eq!(key_for_code(code), Some(x(vk, scan)), "{code}");
        }
        // Same scan code, non-extended: keypad navigation keys.
        assert_eq!(key_for_code("Numpad8"), Some(k(0x68, 0x48)));
        assert_eq!(key_for_code("Pause").unwrap().scan, 0);
    }

    #[test]
    fn unknown_codes() {
        for c in [
            "",
            "Key",
            "KeyAA",
            "Keya",
            "Digit",
            "Digit10",
            "F0",
            "F25",
            "F01",
            "Fn",
            "Numpad",
            "NumpadX",
            "Hyper",
            "Unidentified",
            "Lang1",
        ] {
            assert_eq!(key_for_code(c), None, "{c:?}");
        }
    }

    #[test]
    fn text_to_keys() {
        let enter = TextKey::Key(key_for_code("Enter").unwrap());
        let tab = TextKey::Key(key_for_code("Tab").unwrap());
        assert_eq!(
            text_keys("a\r\nb\nc\rd\te\u{7}"),
            vec![
                TextKey::Unicode('a' as u16),
                enter,
                TextKey::Unicode('b' as u16),
                enter,
                TextKey::Unicode('c' as u16),
                enter,
                TextKey::Unicode('d' as u16),
                tab,
                TextKey::Unicode('e' as u16),
            ]
        );
        // Astral plane → surrogate pair in order.
        assert_eq!(
            text_keys("😀é"),
            vec![
                TextKey::Unicode(0xD83D),
                TextKey::Unicode(0xDE00),
                TextKey::Unicode(0x00E9)
            ]
        );
        assert!(text_keys("").is_empty());
    }

    #[test]
    fn coordinates_hit_exact_pixels() {
        for (w, h) in [
            (1920, 1080),
            (3840, 2160),
            (5760, 1080),
            (1366, 768),
            (1, 1),
            (7, 3),
        ] {
            let vs = VirtualScreen { x: 0, y: 0, w, h };
            for px in [0, 1, w / 3, w / 2, w - 2, w - 1] {
                let px = px.clamp(0, w - 1);
                let nx = if w > 1 {
                    px as f32 / (w - 1) as f32
                } else {
                    0.0
                };
                let (ax, _) = to_absolute(nx, 0.0, &vs);
                assert!((0..=65_535).contains(&ax));
                assert_eq!(abs_to_px(ax, w), px, "w={w} px={px} a={ax}");
            }
        }
        let vs = VirtualScreen {
            x: 0,
            y: 0,
            w: 1920,
            h: 1080,
        };
        assert_eq!(to_absolute(0.0, 0.0, &vs), (0, 0));
        let (ax, ay) = to_absolute(1.0, 1.0, &vs);
        assert_eq!((abs_to_px(ax, 1920), abs_to_px(ay, 1080)), (1919, 1079));
        // Out-of-range and NaN are clamped.
        assert_eq!(to_absolute(-3.0, f32::NAN, &vs), (0, 0));
        assert_eq!(to_absolute(7.0, 2.0, &vs), (ax, ay));
    }

    #[test]
    fn multi_monitor_negative_origin() {
        // Secondary monitor left of and above the primary: virtual screen
        // starts at (-1920, -200), 3840 x 1280.
        let vs = VirtualScreen {
            x: -1920,
            y: -200,
            w: 3840,
            h: 1280,
        };
        assert_eq!(to_pixel(0.0, 0.0, &vs), (-1920, -200));
        assert_eq!(to_pixel(1.0, 1.0, &vs), (1919, 1079));
        let nx = 1920.0 / 3839.0; // primary's left edge (desktop x = 0)
        let ny = 200.0 / 1279.0; // primary's top edge (desktop y = 0)
        assert_eq!(to_pixel(nx, ny, &vs), (0, 0));
        // VIRTUALDESK absolute coordinates are relative to the virtual
        // screen's origin, so the origin does not change them.
        let (ax, ay) = to_absolute(nx, ny, &vs);
        assert_eq!(vs.x + abs_to_px(ax, vs.w), 0);
        assert_eq!(vs.y + abs_to_px(ay, vs.h), 0);
    }

    #[test]
    fn wheel() {
        assert_eq!(wheel_data(1.0), Some(120));
        assert_eq!(wheel_data(-2.0), Some(-240));
        assert_eq!(wheel_data(0.5), Some(60));
        assert_eq!(wheel_data(0.001), None);
        assert_eq!(wheel_data(f32::INFINITY), None);
        assert_eq!(wheel_data(1000.0), Some(6000));
    }
}
