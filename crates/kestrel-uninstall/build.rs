//! Embeds the application manifest (requireAdministrator, PerMonitorV2,
//! Common Controls v6), a version resource and the Kestrel icon into
//! `kestrel-uninstall.exe`.
//!
//! No resource compiler and no build dependency: this writes a standard
//! 32-bit `.res` file and hands it to the MSVC linker, which accepts `.res`
//! inputs directly. Only the binary target gets it (`rustc-link-arg-bins`),
//! so test executables never require elevation. Other targets (Linux, the
//! windows-gnu cross check) build without resources.

use std::env;
use std::fs;
use std::path::PathBuf;

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_VERSION: u16 = 16;
const RT_MANIFEST: u16 = 24;
const LANG_EN_US: u16 = 0x0409;

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let manifest = dir.join("kestrel-uninstall.manifest");
    // The tray app's icon (the Kestrel shield); optional.
    let icon = dir.join("../../tray/src-tauri/icons/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed={}", icon.display());

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || target_env != "msvc" {
        return;
    }

    let mut res = Res::new();
    res.add(
        RT_MANIFEST,
        1,
        &fs::read(&manifest).expect("reading kestrel-uninstall.manifest"),
    );
    if let Ok(ico) = fs::read(&icon) {
        if !add_icon(&mut res, &ico) {
            println!("cargo:warning=icon.ico could not be parsed; building without an icon");
        }
    }
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    res.add(RT_VERSION, 1, &version_info(&version));

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("kestrel-uninstall.res");
    fs::write(&out, &res.bytes).expect("writing the .res file");
    println!("cargo:rustc-link-arg-bins={}", out.display());
    // The manifest comes from the .res; the linker must not add its own.
    println!("cargo:rustc-link-arg-bins=/MANIFEST:NO");
}

/// A 32-bit Win32 `.res` file (sequence of RESOURCEHEADER + data).
struct Res {
    bytes: Vec<u8>,
}

impl Res {
    fn new() -> Res {
        let mut r = Res { bytes: Vec::new() };
        // The leading empty resource that marks a 32-bit .res file.
        r.entry(0, 0, &[], 0, 0);
        r
    }

    fn add(&mut self, typ: u16, name: u16, data: &[u8]) {
        self.entry(typ, name, data, 0x1030, LANG_EN_US);
    }

    fn entry(&mut self, typ: u16, name: u16, data: &[u8], flags: u16, lang: u16) {
        let b = &mut self.bytes;
        b.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataSize
        b.extend_from_slice(&32u32.to_le_bytes()); // HeaderSize
        for v in [0xFFFF, typ, 0xFFFF, name] {
            b.extend_from_slice(&v.to_le_bytes()); // ordinal TYPE and NAME
        }
        b.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
        b.extend_from_slice(&flags.to_le_bytes()); // MemoryFlags
        b.extend_from_slice(&lang.to_le_bytes()); // LanguageId
        b.extend_from_slice(&0u32.to_le_bytes()); // Version
        b.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
        b.extend_from_slice(data);
        pad4(b);
    }
}

fn pad4(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// `.ico` file -> one RT_ICON per image (ids 1..n) + RT_GROUP_ICON 1.
fn add_icon(res: &mut Res, ico: &[u8]) -> bool {
    let (Some(0), Some(1), Some(count)) = (u16_at(ico, 0), u16_at(ico, 2), u16_at(ico, 4)) else {
        return false;
    };
    let mut group = Vec::new();
    group.extend_from_slice(&0u16.to_le_bytes());
    group.extend_from_slice(&1u16.to_le_bytes());
    group.extend_from_slice(&count.to_le_bytes());
    let mut images = Vec::new();
    for i in 0..count as usize {
        let e = 6 + 16 * i;
        let Some(entry) = ico.get(e..e + 16) else {
            return false;
        };
        let (Some(size), Some(off)) = (u32_at(ico, e + 8), u32_at(ico, e + 12)) else {
            return false;
        };
        let Some(img) = ico.get(off as usize..off as usize + size as usize) else {
            return false;
        };
        let id = (i + 1) as u16;
        // GRPICONDIRENTRY: the first 12 bytes of ICONDIRENTRY + the id.
        group.extend_from_slice(&entry[..12]);
        group.extend_from_slice(&id.to_le_bytes());
        images.push((id, img));
    }
    for (id, img) in images {
        res.add(RT_ICON, id, img);
    }
    res.add(RT_GROUP_ICON, 1, &group);
    true
}

/// `1.2.3[-pre]` -> [1, 2, 3, 0].
fn version_parts(v: &str) -> [u16; 4] {
    let mut out = [0u16; 4];
    for (i, p) in v
        .split(['-', '+'])
        .next()
        .unwrap_or("")
        .split('.')
        .take(4)
        .enumerate()
    {
        out[i] = p.parse().unwrap_or(0);
    }
    out
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

/// One VS_VERSIONINFO-style node: wLength, wValueLength, wType, szKey,
/// padding, value, padding, children.
fn node(key: &str, wtype: u16, value: &[u8], value_len: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; 6];
    b[2..4].copy_from_slice(&value_len.to_le_bytes());
    b[4..6].copy_from_slice(&wtype.to_le_bytes());
    b.extend_from_slice(&utf16z(key));
    pad4(&mut b);
    b.extend_from_slice(value);
    for c in children {
        pad4(&mut b);
        b.extend_from_slice(c);
    }
    let len = b.len() as u16;
    b[0..2].copy_from_slice(&len.to_le_bytes());
    b
}

fn string(key: &str, value: &str) -> Vec<u8> {
    let v = utf16z(value);
    node(key, 1, &v, (v.len() / 2) as u16, &[])
}

fn version_info(version: &str) -> Vec<u8> {
    let [a, b, c, d] = version_parts(version);
    let ms = ((a as u32) << 16) | b as u32;
    let ls = ((c as u32) << 16) | d as u32;
    let mut fixed = Vec::new();
    for v in [
        0xFEEF_04BDu32, // signature
        0x0001_0000,    // structure version
        ms,
        ls, // file version
        ms,
        ls,          // product version
        0x3F,        // flags mask
        0,           // flags
        0x0004_0004, // VOS_NT_WINDOWS32
        1,           // VFT_APP
        0,
        0,
        0,
    ] {
        fixed.extend_from_slice(&v.to_le_bytes());
    }
    let dotted = format!("{a}.{b}.{c}.{d}");
    let strings = [
        string("CompanyName", "Kestrel"),
        string("FileDescription", "Uninstall Kestrel EDR"),
        string("FileVersion", &dotted),
        string("InternalName", "kestrel-uninstall"),
        string("OriginalFilename", "kestrel-uninstall.exe"),
        string("ProductName", "Kestrel EDR"),
        string("ProductVersion", version),
    ];
    let table = node("040904B0", 1, &[], 0, &strings);
    let sfi = node("StringFileInfo", 1, &[], 0, &[table]);
    let mut translation = Vec::new();
    translation.extend_from_slice(&LANG_EN_US.to_le_bytes());
    translation.extend_from_slice(&1200u16.to_le_bytes()); // Unicode
    let var = node("Translation", 0, &translation, 4, &[]);
    let vfi = node("VarFileInfo", 1, &[], 0, &[var]);
    node(
        "VS_VERSION_INFO",
        0,
        &fixed,
        fixed.len() as u16,
        &[sfi, vfi],
    )
}
