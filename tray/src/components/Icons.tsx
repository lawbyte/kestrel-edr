// Small line icons drawn on a 16px grid (Fluent-like weight), plus the state
// shield used in the status hero. The shield glyphs match the tray icons
// (scripts/gen-icons.mjs) so the window and the notification area agree.
import type { ProtectionState } from "../protocol";

export type ShieldKind = ProtectionState | "unavailable" | "loading";

const SHIELD = "M16 1.5 L28.5 5.8 V15 C28.5 22.8 23.5 27.8 16 30.5 C8.5 27.8 3.5 22.8 3.5 15 V5.8 Z";

export function StateShield({ kind, size = 72 }: { kind: ShieldKind; size?: number }) {
  return (
    <svg className={`shield shield--${kind}`} width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      {kind === "degraded" ? (
        <>
          <path d={SHIELD} className="shield__hollow" strokeWidth="1.6" strokeLinejoin="round" />
          <path d="M16 2.6 V29.3 C9.3 26.8 4.6 22 4.6 15 V6.6 Z" className="shield__fill" />
        </>
      ) : kind === "unavailable" || kind === "loading" ? (
        <path d={SHIELD} className="shield__hollow" strokeWidth="1.6" strokeLinejoin="round" />
      ) : (
        <path d={SHIELD} className="shield__fill" />
      )}
      {kind === "protected" && <path d="M10.5 16 L14.4 19.9 L22 11.8" className="shield__glyph-stroke" strokeWidth="2.6" />}
      {kind === "attention" && (
        <>
          <path d="M16 8.8 V17.2" className="shield__glyph-stroke" strokeWidth="2.8" />
          <circle cx="16" cy="22.4" r="1.7" className="shield__glyph-fill" />
        </>
      )}
      {kind === "isolated" && (
        <>
          <path d="M12.4 15 V12.6 a3.6 3.6 0 0 1 7.2 0 V15" className="shield__glyph-stroke" strokeWidth="2" fill="none" />
          <rect x="10.2" y="14.6" width="11.6" height="8.6" rx="1.6" className="shield__glyph-fill" />
        </>
      )}
      {kind === "degraded" && <path d="M9.4 17 q3.3 -3.8 6.6 0 t6.6 0" className="shield__glyph-stroke shield__glyph-stroke--ink" strokeWidth="2.2" />}
      {kind === "offline" && (
        <>
          <path d="M11 21 h10.4 a3.4 3.4 0 0 0 0 -6.8 a5.1 5.1 0 0 0 -9.8 1.1 a2.85 2.85 0 0 0 -0.6 5.7 Z" className="shield__glyph-fill" />
          <path d="M9.2 10 L23.4 24.2" className="shield__cut" strokeWidth="3.6" />
          <path d="M9.2 10 L23.4 24.2" className="shield__glyph-stroke" strokeWidth="1.8" />
        </>
      )}
      {kind === "unavailable" && <path d="M11.8 11.4 L20.2 19.8 M20.2 11.4 L11.8 19.8" className="shield__glyph-stroke shield__glyph-stroke--ink" strokeWidth="2.6" />}
    </svg>
  );
}

type P = { size?: number };
const svg = (size: number, children: React.ReactNode) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    {children}
  </svg>
);

export const IconHome = ({ size = 16 }: P) => svg(size, <path d="M2.5 7 8 2.5 13.5 7v6a.5.5 0 0 1-.5.5h-3v-4h-4v4H3a.5.5 0 0 1-.5-.5Z" />);
export const IconList = ({ size = 16 }: P) => svg(size, <path d="M5.5 4h8M5.5 8h8M5.5 12h8M2.5 4h.01M2.5 8h.01M2.5 12h.01" />);
export const IconHelp = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <circle cx="8" cy="8" r="5.75" />
      <path d="M6.4 6.3a1.7 1.7 0 0 1 3.3.5c0 1.2-1.7 1.4-1.7 2.5M8 11.3h.01" />
    </>,
  );
export const IconClose = ({ size = 16 }: P) => svg(size, <path d="M4 4l8 8M12 4l-8 8" />);
export const IconPopOut = ({ size = 16 }: P) => svg(size, <path d="M9.5 2.5h4v4M13.5 2.5 8 8M11.5 9.5v3a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h3" />);
export const IconDock = ({ size = 16 }: P) => svg(size, <path d="M2.5 13.5h11M8 2.5v8M5 7.5l3 3 3-3" />);
export const IconCheck = ({ size = 16 }: P) => svg(size, <path d="M3.5 8.5 6.5 11.5 12.5 4.5" />);
export const IconCross = ({ size = 16 }: P) => svg(size, <path d="M4.5 4.5l7 7M11.5 4.5l-7 7" />);
export const IconMail = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <rect x="2" y="3.5" width="12" height="9" rx="1.2" />
      <path d="m2.5 4.5 5.5 4 5.5-4" />
    </>,
  );
export const IconPhone = ({ size = 16 }: P) => svg(size, <path d="M5.2 2.5H3.4a1 1 0 0 0-1 1.1 11 11 0 0 0 10 10 1 1 0 0 0 1.1-1v-1.8a.8.8 0 0 0-.6-.8l-2.2-.6a.8.8 0 0 0-.8.2l-.9.9A8 8 0 0 1 5.5 6.9l.9-.9a.8.8 0 0 0 .2-.8L6 3.1a.8.8 0 0 0-.8-.6Z" />);
export const IconGlobe = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <circle cx="8" cy="8" r="5.75" />
      <path d="M2.5 8h11M8 2.25c1.6 1.6 2.4 3.5 2.4 5.75S9.6 12.15 8 13.75C6.4 12.15 5.6 10.25 5.6 8S6.4 3.85 8 2.25Z" />
    </>,
  );
export const IconOpen = ({ size = 12 }: P) => svg(size, <path d="M6 3H3.5a1 1 0 0 0-1 1v8.5a1 1 0 0 0 1 1H12a1 1 0 0 0 1-1V10M9.5 2.5h4v4M13.5 2.5 7.5 8.5" />);
export const IconChevron = ({ size = 12 }: P) => svg(size, <path d="m6 4 4 4-4 4" />);
export const IconPc = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <rect x="2" y="3" width="12" height="8" rx="1" />
      <path d="M6 13.5h4M8 11v2.5" />
    </>,
  );
export const IconSync = ({ size = 16 }: P) => svg(size, <path d="M13 6.5A5 5 0 0 0 3.6 5M3 9.5A5 5 0 0 0 12.4 11M3.5 2.5V5H6M12.5 13.5V11H10" />);
export const IconLink = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <path d="M6.5 9.5a2.5 2.5 0 0 0 3.5 0l2.3-2.3a2.5 2.5 0 0 0-3.5-3.5l-.6.6" />
      <path d="M9.5 6.5a2.5 2.5 0 0 0-3.5 0L3.7 8.8a2.5 2.5 0 0 0 3.5 3.5l.6-.6" />
    </>,
  );
export const IconScan = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <path d="M2.5 5.5v-2a1 1 0 0 1 1-1h2M10.5 2.5h2a1 1 0 0 1 1 1v2M13.5 10.5v2a1 1 0 0 1-1 1h-2M5.5 13.5h-2a1 1 0 0 1-1-1v-2" />
      <path d="M5 8h6" />
    </>,
  );
export const IconPolicy = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <path d="M4 2.5h5.5L12 5v8.5H4Z" />
      <path d="M6 8h4M6 10.5h4" />
    </>,
  );
export const IconInfo = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <circle cx="8" cy="8" r="5.75" />
      <path d="M8 7.3v3.7M8 5h.01" />
    </>,
  );
export const IconClock = ({ size = 16 }: P) =>
  svg(
    size,
    <>
      <circle cx="8" cy="8" r="5.75" />
      <path d="M8 4.8V8l2.2 1.4" />
    </>,
  );

/** Severity marker: different shapes per level, so colour isn't the only signal. */
export function SeverityMark({ severity }: { severity: "info" | "low" | "medium" | "high" | "critical" }) {
  return (
    <svg className={`sev sev--${severity}`} width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
      {severity === "critical" && <path d="M7 2h6l5 5v6l-5 5H7l-5-5V7Z" className="sev__fill" />}
      {severity === "high" && <path d="M10 2.2 18 17H2Z" className="sev__fill" strokeLinejoin="round" />}
      {severity === "medium" && <rect x="3" y="3" width="14" height="14" rx="3.5" className="sev__fill" />}
      {severity === "low" && <circle cx="10" cy="10" r="7.5" className="sev__fill" />}
      {severity === "info" && <circle cx="10" cy="10" r="7.5" className="sev__fill" />}
      {severity === "info" ? (
        <path d="M10 9v4.5M10 6.3h.01" className="sev__glyph" />
      ) : severity === "low" ? (
        <path d="M6.6 10.2 8.9 12.5 13.4 7.6" className="sev__glyph" />
      ) : severity === "high" ? (
        <path d="M10 8v4M10 14.6h.01" className="sev__glyph" />
      ) : (
        <path d="M7 10h6" className="sev__glyph" />
      )}
    </svg>
  );
}
