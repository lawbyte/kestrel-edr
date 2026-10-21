// Generates the Kestrel app icon (PNG/ICO) and one tray icon per protection state.
// Run: npm run icons   (outputs into src-tauri/icons/ and public/)
//
// The mark is original: a shield with a kestrel's pointed wing sweeping across it.
// Tray icons use the same shield silhouette but a different glyph AND fill style per
// state, so the state is readable without relying on colour.
import { Resvg } from "@resvg/resvg-js";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const iconsDir = join(root, "src-tauri", "icons");
const trayDir = join(iconsDir, "tray");
const publicDir = join(root, "public");
for (const d of [iconsDir, trayDir, publicDir, join(root, "assets")]) mkdirSync(d, { recursive: true });

const SHIELD = "M32 4 L54 11.5 V29 C54 43.5 45 53.5 32 60 C19 53.5 10 43.5 10 29 V11.5 Z";

// ---- App / brand mark -------------------------------------------------------
export const brandSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="s" x1="0" y1="0" x2="0.4" y2="1">
      <stop offset="0" stop-color="#3D7299"/>
      <stop offset="1" stop-color="#1D3E57"/>
    </linearGradient>
  </defs>
  <path d="${SHIELD}" fill="url(#s)"/>
  <path d="M32 6.6 L51.6 13.3 V29 C51.6 42 43.7 51 32 57.3" fill="none" stroke="#ffffff" stroke-opacity=".14" stroke-width="1.2"/>
  <!-- kestrel wing: long pointed primaries sweeping up to the right -->
  <path d="M15.5 41 C22 31 33 22.5 49 17 C44.5 25.5 35 33.5 19.5 42.5 Z" fill="#F2F5F7"/>
  <path d="M17.5 46.5 C25 39.5 34 34.5 45.5 31 C40 37.5 31.5 42.5 21 47.5 Z" fill="#F2F5F7" fill-opacity=".82"/>
  <path d="M21.5 51 C27.5 47 33.5 44.5 40.5 43 C36 47.5 30.5 50.5 25 52.5 Z" fill="#D9A273"/>
</svg>`;

// ---- Tray icons --------------------------------------------------------------
// Designed on a 32px grid; strokes are thick so they survive downscaling to 16px.
const TRAY_SHIELD = "M16 1.5 L28.5 5.8 V15 C28.5 22.8 23.5 27.8 16 30.5 C8.5 27.8 3.5 22.8 3.5 15 V5.8 Z";
const solid = (fill) => `<path d="${TRAY_SHIELD}" fill="${fill}" stroke="#000" stroke-opacity=".28" stroke-width="1"/>`;
const tray = {
  // Solid green shield + check
  protected: `${solid("#138A55")}
    <path d="M10 16.2 L14.2 20.4 L22.5 11.6" fill="none" stroke="#fff" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/>`,
  // Solid amber shield + exclamation mark
  attention: `${solid("#F2B01E")}
    <path d="M16 8.5 V17.5" stroke="#2B1D00" stroke-width="3.6" stroke-linecap="round"/>
    <circle cx="16" cy="23" r="2.2" fill="#2B1D00"/>`,
  // Solid indigo shield + padlock (network locked down by IT)
  isolated: `${solid("#4F46B8")}
    <path d="M12 15 V12.5 a4 4 0 0 1 8 0 V15" fill="none" stroke="#fff" stroke-width="2.6"/>
    <rect x="9.5" y="14.5" width="13" height="9.5" rx="1.8" fill="#fff"/>`,
  // Half-filled shield (left half solid, right half outline) + wavy "unsteady" line
  degraded: `<path d="${TRAY_SHIELD}" fill="#fff" fill-opacity=".9" stroke="#B85C00" stroke-width="2.4" stroke-linejoin="round"/>
    <path d="M16 2.8 V29.2 C9.2 26.6 4.8 22 4.8 15 V6.7 Z" fill="#D9730D"/>
    <path d="M9 17 q3.5 -4 7 0 t7 0" fill="none" stroke="#5A2C00" stroke-width="2.8" stroke-linecap="round"/>`,
  // Solid grey shield + cloud with a slash (no server connection, still protecting)
  offline: `${solid("#6B7280")}
    <path d="M10.6 21 h11 a3.6 3.6 0 0 0 0 -7.2 a5.4 5.4 0 0 0 -10.4 1.2 a3 3 0 0 0 -0.6 6 Z" fill="#fff"/>
    <path d="M8.5 9.5 L24 25" stroke="#6B7280" stroke-width="4.2" stroke-linecap="round"/>
    <path d="M8.5 9.5 L24 25" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/>`,
  // Hollow amber outline shield + pause bars (protection turned off on this PC
  // with the uninstall token). Hollow like "unavailable": not protecting.
  paused: `<path d="${TRAY_SHIELD}" fill="#fff" fill-opacity=".92" stroke="#C98A00" stroke-width="2.6" stroke-linejoin="round"/>
    <path d="M12.6 10.5 V20.5 M19.4 10.5 V20.5" stroke="#7A4C00" stroke-width="3.6" stroke-linecap="round"/>`,
  // Hollow red outline shield + cross (service not running / pipe unavailable)
  unavailable: `<path d="${TRAY_SHIELD}" fill="#fff" fill-opacity=".92" stroke="#C42B1C" stroke-width="2.6" stroke-linejoin="round"/>
    <path d="M11.5 11 L20.5 20 M20.5 11 L11.5 20" stroke="#C42B1C" stroke-width="3.4" stroke-linecap="round"/>`,
};

const wrap32 = (inner) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">${inner}</svg>`;

function png(svg, size) {
  return new Resvg(svg, { fitTo: { mode: "width", value: size } }).render().asPng();
}

// Minimal ICO writer: PNG-compressed entries (supported since Windows Vista).
function ico(entries) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);
  const dir = Buffer.alloc(16 * entries.length);
  let offset = 6 + dir.length;
  entries.forEach(({ size, data }, i) => {
    const o = i * 16;
    dir.writeUInt8(size >= 256 ? 0 : size, o);
    dir.writeUInt8(size >= 256 ? 0 : size, o + 1);
    dir.writeUInt8(0, o + 2);
    dir.writeUInt8(0, o + 3);
    dir.writeUInt16LE(1, o + 4);
    dir.writeUInt16LE(32, o + 6);
    dir.writeUInt32LE(data.length, o + 8);
    dir.writeUInt32LE(offset, o + 12);
    offset += data.length;
  });
  return Buffer.concat([header, dir, ...entries.map((e) => e.data)]);
}

const out = (p, data) => {
  writeFileSync(p, data);
  console.log("wrote", p.replace(root + "/", ""));
};

out(join(root, "assets", "kestrel-mark.svg"), brandSvg);
out(join(publicDir, "kestrel-mark.svg"), brandSvg);
for (const [name, size] of [["32x32.png", 32], ["64x64.png", 64], ["128x128.png", 128], ["128x128@2x.png", 256], ["icon.png", 512]]) {
  out(join(iconsDir, name), png(brandSvg, size));
}
// Windows Store-style logos used by the NSIS/MSI bundle and Start menu tiles.
for (const s of [30, 44, 71, 89, 107, 142, 150, 284, 310]) out(join(iconsDir, `Square${s}x${s}Logo.png`), png(brandSvg, s));
out(join(iconsDir, "StoreLogo.png"), png(brandSvg, 50));
out(join(iconsDir, "icon.ico"), ico([16, 20, 24, 32, 40, 48, 64, 256].map((s) => ({ size: s, data: png(brandSvg, s) }))));

for (const [state, inner] of Object.entries(tray)) {
  const svg = wrap32(inner);
  out(join(trayDir, `${state}.svg`), svg);
  out(join(trayDir, `${state}.png`), png(svg, 32));
  out(join(trayDir, `${state}.ico`), ico([16, 20, 24, 32, 48].map((s) => ({ size: s, data: png(svg, s) }))));
}
// Preview sheet for eyeballing all states at 16/24/32px on light and dark taskbars.
const states = Object.keys(tray);
const sheet = `<svg xmlns="http://www.w3.org/2000/svg" width="${states.length * 120}" height="180">
  <rect width="100%" height="90" fill="#F3F3F3"/><rect y="90" width="100%" height="90" fill="#1C1C1C"/>
  ${states
    .map((s, i) =>
      [0, 90]
        .map(
          (y) => `
    <svg x="${i * 120 + 8}" y="${y + 37}" width="16" height="16" viewBox="0 0 32 32">${tray[s]}</svg>
    <svg x="${i * 120 + 32}" y="${y + 33}" width="24" height="24" viewBox="0 0 32 32">${tray[s]}</svg>
    <svg x="${i * 120 + 64}" y="${y + 29}" width="32" height="32" viewBox="0 0 32 32">${tray[s]}</svg>`,
        )
        .join(""),
    )
    .join("")}
</svg>`;
out(join(root, "screenshots", "tray-icons.png"), new Resvg(sheet, { fitTo: { mode: "zoom", value: 3 } }).render().asPng());
out(join(root, "screenshots", "app-icon.png"), png(brandSvg, 256));
