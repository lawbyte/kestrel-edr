// Wording and formatting for the local "turn protection off" switch.
// Pure functions (no React) so they are unit-tested in pause.test.ts.
import type { PauseDenied, PauseMode, PauseOffer, PauseResult, PauseState } from "./protocol";
import type { ApiError } from "./api/types";
import { clockTime } from "./format";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** Mode in plain words: label + what it means for the employee. */
export const MODE_COPY: Record<PauseMode, { label: string; detail: string }> = {
  detection_only: {
    label: "Detection only",
    detail: "Kestrel still watches and reports to IT but will not stop anything.",
  },
  full: {
    label: "Completely off",
    detail: "Kestrel is not watching this PC.",
  },
};

/** Warning shown when "Completely off" is selected. */
export const FULL_WARNING =
  "Kestrel will not see, stop or report anything on this PC until protection comes back on. Choose this only if IT asked you to.";

/** Who the switch is for and what happens (dialog lead text). */
export const PAUSE_INTRO =
  "This is for IT staff and technicians. You need this PC's uninstall token, which your IT team can give you. Turning protection off and back on is reported to IT, with your Windows account name.";

export const OLDER_AGENT = "This version of Kestrel cannot turn protection off from the tray.";

/** Duration option label: 15 → "15 minutes", 60 → "1 hour", 90 → "1 hour 30 minutes", 2880 → "2 days". */
export function durationLabel(minutes: number): string {
  const m = Math.max(0, Math.round(minutes));
  if (m >= 2 * 24 * 60 && m % (24 * 60) === 0) return plural(m / (24 * 60), "day");
  if (m < 60) return plural(m, "minute");
  const h = Math.floor(m / 60);
  const rest = m % 60;
  return rest === 0 ? plural(h, "hour") : `${plural(h, "hour")} ${plural(rest, "minute")}`;
}

/** Remaining time, compact: "1 h 20 min", "45 min", "2 days 3 h", "less than a minute". */
export function remaining(ms: number): string {
  if (ms < MIN) return "less than a minute";
  // Round up to whole minutes: the display never claims less time than there is.
  const mins = Math.ceil(ms / MIN);
  if (mins < 60) return `${mins} min`;
  if (mins < 24 * 60) {
    const h = Math.floor(mins / 60);
    const m = mins % 60;
    return m === 0 ? `${h} h` : `${h} h ${m} min`;
  }
  const d = Math.floor(mins / (24 * 60));
  const h = Math.floor((mins % (24 * 60)) / 60);
  return h === 0 ? plural(d, "day") : `${plural(d, "day")} ${h} h`;
}

/** Lockout countdown: "4 min" (rounded up), or "45 s" under a minute. */
export function lockoutLeft(ms: number): string {
  if (ms <= 0) return "0 s";
  if (ms < MIN) return `${Math.ceil(ms / 1000)} s`;
  return remaining(ms);
}

/** "14:30", "14:30 tomorrow" or "14:30 on 23 Oct". */
export function whenText(ts: number, now = Date.now()): string {
  const d = new Date(ts);
  const n = new Date(now);
  const startOfToday = new Date(n.getFullYear(), n.getMonth(), n.getDate()).getTime();
  const t = clockTime(ts);
  if (ts < startOfToday + DAY) return t;
  if (ts < startOfToday + 2 * DAY) return `${t} tomorrow`;
  return `${t} on ${d.toLocaleDateString(undefined, { day: "numeric", month: "short" })}`;
}

/** "Turns back on automatically at 14:30 (in 1 h 20 min)" / "Until turned back on". */
export function untilText(p: PauseState, now = Date.now()): string {
  if (p.until_ms === null) return "Until turned back on";
  return `Turns back on automatically at ${whenText(p.until_ms, now)} (in ${remaining(p.until_ms - now)})`;
}

/** "Turned off by NUSANTARA\dewi.lestari at 13:10". */
export function byText(p: PauseState, now = Date.now()): string {
  const who = p.by_user.trim();
  const at = new Date(p.since_ms).toDateString() === new Date(now).toDateString() ? clockTime(p.since_ms) : sinceDate(p.since_ms);
  return who ? `Turned off by ${who} at ${at}` : `Turned off at ${at}`;
}

function sinceDate(ts: number): string {
  return `${clockTime(ts)} on ${new Date(ts).toLocaleDateString(undefined, { day: "numeric", month: "short" })}`;
}

/** Whether the "Turn off protection" button is shown (hidden when not allowed or an older agent). */
export function canOffer(offer: PauseOffer | null | undefined): offer is PauseOffer {
  return !!offer && offer.enabled && (offer.minutes.length > 0 || offer.allow_until_resumed);
}

/** Active lockout end, if any, from the status offer and the last answer. */
export function lockedUntil(offer: PauseOffer | null | undefined, last: PauseResult | null, now = Date.now()): number | null {
  const t = Math.max(offer?.locked_until_ms ?? 0, last?.error === "locked_out" ? (last.locked_until_ms ?? 0) : 0);
  return t > now ? t : null;
}

export function lockedText(until: number, now = Date.now()): string {
  return `Too many wrong tokens. Try again in ${lockoutLeft(until - now)}.`;
}

export function deniedText(d: PauseDenied | null): string {
  switch (d) {
    case "disabled":
      return "Your organisation's policy doesn't allow turning protection off on this PC.";
    case "mode_not_allowed":
      return "Your organisation's policy doesn't allow turning Kestrel completely off. Choose Detection only.";
    case "duration_not_allowed":
      return "Your organisation's policy doesn't allow that length of time. Choose a shorter one.";
    default:
      return "Your organisation's policy doesn't allow this.";
  }
}

/**
 * Message for a failed turn-off answer (null when ok). Lockouts are shown by
 * the live countdown instead (see lockedText), so they return null here too.
 */
export function pauseErrorText(r: PauseResult): string | null {
  if (r.ok) return null;
  switch (r.error) {
    case "wrong_token":
      if (r.attempts_left === null) return "Wrong token. Check it with IT and try again.";
      return `Wrong token. ${r.attempts_left === 1 ? "1 attempt" : `${r.attempts_left} attempts`} left before a lockout.`;
    case "locked_out":
      return r.locked_until_ms === null ? "Too many wrong tokens. Try again later." : null;
    case "not_allowed":
      return deniedText(r.denied);
    case "already_off":
      return "Protection is already off.";
    case "not_off":
      return "Protection is already on.";
    case "unidentified":
      return "Kestrel couldn't confirm which Windows account you're signed in with, so protection stays on. Contact IT.";
    case "internal":
    case null:
      return r.message.trim() || "Something went wrong in Kestrel and protection is still on. Try again, or contact IT.";
  }
}

/** Message when the request didn't get a PauseResult at all. */
export function pauseTransportText(e: ApiError, turningOn = false): string {
  switch (e.kind) {
    case "agent":
      return turningOn ? "This version of Kestrel cannot turn protection back on from the tray. Contact IT." : OLDER_AGENT;
    case "unavailable":
      return "Kestrel service isn't running, so this can't be done from here. Contact IT.";
    case "timeout":
      return "Kestrel didn't answer in time. Check the Status tab before trying again.";
    case "protocol":
      return "Kestrel didn't answer correctly. Try again in a moment.";
  }
}

/** Default duration: 1 hour when offered, else the shortest, else "until turned back on". */
export function defaultMinutes(offer: PauseOffer): number | null {
  if (offer.minutes.includes(60)) return 60;
  return offer.minutes[0] ?? null;
}

function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}
