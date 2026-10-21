//! Input injection thread of the helper (`SendInput`), following the input
//! desktop like the capture thread.
//!
//! Mouse: `MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`
//! with 0..65535 over the virtual screen (`desktop_keymap::to_absolute`),
//! buttons incl. X1/X2 (`MOUSEEVENTF_XDOWN/XUP` + `XBUTTON1/2`), wheel
//! (`MOUSEEVENTF_WHEEL` / `MOUSEEVENTF_HWHEEL`, multiples of `WHEEL_DELTA`).
//! Keys: set-1 scan codes with `KEYEVENTF_SCANCODE` (+ `KEYEVENTF_EXTENDEDKEY`),
//! text with `KEYEVENTF_UNICODE`. Everything this session pressed is tracked
//! and released on `ReleaseAll` and at the end of the session.

use super::capture::virtual_screen;
use super::deskfollow::DesktopFollower;
use crate::desktop_keymap::{key_for_code, text_keys, to_absolute, wheel_data, KeySpec, TextKey};
use kestrel_common::remote::{InputEvent, MouseButton};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::Receiver;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{XBUTTON1, XBUTTON2};

pub enum InputCmd {
    Event(InputEvent),
    Stop,
}

const ABS: u32 = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;

fn mouse(dx: i32, dy: i32, flags: u32, data: i32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data as u32,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn key(k: &KeySpec, up: bool) -> INPUT {
    let mut flags = if up { KEYEVENTF_KEYUP } else { 0 };
    if k.extended {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    let (vk, scan) = if k.scan == 0 {
        (k.vk, 0) // by virtual key only (Pause)
    } else {
        flags |= KEYEVENTF_SCANCODE;
        (0, k.scan)
    };
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn unicode(unit: u16, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: 0,
                wScan: unit,
                dwFlags: KEYEVENTF_UNICODE | if up { KEYEVENTF_KEYUP } else { 0 },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn button_flags(b: MouseButton, down: bool) -> (u32, i32) {
    match (b, down) {
        (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
        (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
        (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
        (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
        (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
        (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
        (MouseButton::X1, true) => (MOUSEEVENTF_XDOWN, XBUTTON1 as i32),
        (MouseButton::X1, false) => (MOUSEEVENTF_XUP, XBUTTON1 as i32),
        (MouseButton::X2, true) => (MOUSEEVENTF_XDOWN, XBUTTON2 as i32),
        (MouseButton::X2, false) => (MOUSEEVENTF_XUP, XBUTTON2 as i32),
    }
}

fn button_id(b: MouseButton) -> u8 {
    match b {
        MouseButton::Left => 0,
        MouseButton::Right => 1,
        MouseButton::Middle => 2,
        MouseButton::X1 => 3,
        MouseButton::X2 => 4,
    }
}

fn button_from_id(i: u8) -> MouseButton {
    match i {
        0 => MouseButton::Left,
        1 => MouseButton::Right,
        2 => MouseButton::Middle,
        3 => MouseButton::X1,
        _ => MouseButton::X2,
    }
}

#[derive(Default)]
struct Injector {
    keys: BTreeMap<String, KeySpec>,
    buttons: BTreeSet<u8>,
    failures: u32,
}

impl Injector {
    fn send(&mut self, inputs: &[INPUT]) {
        if inputs.is_empty() {
            return;
        }
        let n = unsafe {
            SendInput(
                inputs.len() as u32,
                inputs.as_ptr(),
                std::mem::size_of::<INPUT>() as i32,
            )
        };
        if (n as usize) < inputs.len() {
            self.failures += 1;
            if self.failures.is_power_of_two() {
                tracing::warn!(
                    "SendInput injected {n}/{} events: {} ({} failures)",
                    inputs.len(),
                    std::io::Error::last_os_error(),
                    self.failures
                );
            }
        }
    }

    fn apply(&mut self, ev: InputEvent) {
        let vs = virtual_screen();
        match ev {
            InputEvent::MouseMove { x, y } => {
                let (dx, dy) = to_absolute(x, y, &vs);
                self.send(&[mouse(dx, dy, ABS, 0)]);
            }
            InputEvent::MouseButton { x, y, button, down } => {
                let (dx, dy) = to_absolute(x, y, &vs);
                let (f, data) = button_flags(button, down);
                if down {
                    self.buttons.insert(button_id(button));
                } else {
                    self.buttons.remove(&button_id(button));
                }
                self.send(&[mouse(dx, dy, ABS | f, data)]);
            }
            InputEvent::MouseWheel {
                x,
                y,
                delta_y,
                delta_x,
            } => {
                let (dx, dy) = to_absolute(x, y, &vs);
                let mut v = vec![mouse(dx, dy, ABS, 0)];
                if let Some(d) = wheel_data(delta_y) {
                    v.push(mouse(dx, dy, ABS | MOUSEEVENTF_WHEEL, d));
                }
                if let Some(d) = wheel_data(delta_x) {
                    v.push(mouse(dx, dy, ABS | MOUSEEVENTF_HWHEEL, d));
                }
                self.send(&v);
            }
            InputEvent::Key { code, down } => {
                let Some(k) = key_for_code(&code) else {
                    return;
                };
                if down {
                    self.keys.insert(code, k);
                } else {
                    self.keys.remove(&code);
                }
                self.send(&[key(&k, !down)]);
            }
            InputEvent::Text { text } => {
                let mut v = Vec::new();
                for t in text_keys(&text) {
                    match t {
                        TextKey::Unicode(u) => {
                            v.push(unicode(u, false));
                            v.push(unicode(u, true));
                        }
                        TextKey::Key(k) => {
                            v.push(key(&k, false));
                            v.push(key(&k, true));
                        }
                    }
                }
                for chunk in v.chunks(64) {
                    self.send(chunk);
                }
            }
            InputEvent::ReleaseAll => self.release_all(),
            // Ctrl+Alt+Del is handled by the agent service (SendSAS).
            InputEvent::CtrlAltDel | InputEvent::Unknown => {}
        }
    }

    fn release_all(&mut self) {
        let mut v: Vec<INPUT> = self.keys.values().map(|k| key(k, true)).collect();
        self.keys.clear();
        for b in std::mem::take(&mut self.buttons) {
            let (f, data) = button_flags(button_from_id(b), false);
            v.push(mouse(0, 0, f, data)); // relative, no movement
        }
        self.send(&v);
    }
}

/// Input loop; releases everything it pressed before returning.
pub fn run(rx: Receiver<InputCmd>) {
    let mut follower = DesktopFollower::new();
    let mut inj = Injector::default();
    while let Ok(cmd) = rx.recv() {
        follower.sync();
        match cmd {
            InputCmd::Event(e) => inj.apply(e),
            InputCmd::Stop => break,
        }
    }
    follower.sync();
    inj.release_all();
}
