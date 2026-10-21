import { describe, expect, it } from "vitest";
import type { PauseOffer, PauseResult, PauseState } from "./protocol";
import { byText, canOffer, defaultMinutes, deniedText, durationLabel, lockedText, lockedUntil, lockoutLeft, OLDER_AGENT, pauseErrorText, pauseTransportText, remaining, untilText } from "./pause";
import { shieldKind, stateCopy } from "./copy";
import { clockTime } from "./format";

const MIN = 60_000;
const NOW = new Date(2026, 9, 21, 13, 10, 0).getTime();
const offer: PauseOffer = { enabled: true, allow_full: true, minutes: [15, 60, 240, 480], allow_until_resumed: true, locked_until_ms: null };
const result = (over: Partial<PauseResult>): PauseResult => ({ ok: false, error: null, message: "", attempts_left: null, locked_until_ms: null, denied: null, state: null, ...over });
const pause = (over: Partial<PauseState> = {}): PauseState => ({ mode: "detection_only", since_ms: NOW, until_ms: NOW + 80 * MIN, by_user: "NUSANTARA\\teknisi", ...over });

describe("durations", () => {
  it("labels the standard steps and other values", () => {
    expect([15, 60, 240, 480].map(durationLabel)).toEqual(["15 minutes", "1 hour", "4 hours", "8 hours"]);
    expect(durationLabel(1)).toBe("1 minute");
    expect(durationLabel(30)).toBe("30 minutes");
    expect(durationLabel(90)).toBe("1 hour 30 minutes");
    expect(durationLabel(1440)).toBe("24 hours");
    expect(durationLabel(2880)).toBe("2 days");
    expect(durationLabel(10080)).toBe("7 days");
  });

  it("formats remaining time compactly and rounds up", () => {
    expect(remaining(80 * MIN)).toBe("1 h 20 min");
    expect(remaining(79 * MIN + 1)).toBe("1 h 20 min");
    expect(remaining(45 * MIN)).toBe("45 min");
    expect(remaining(60 * MIN)).toBe("1 h");
    expect(remaining(30_000)).toBe("less than a minute");
    expect(remaining(27 * 60 * MIN)).toBe("1 day 3 h");
    expect(remaining(48 * 60 * MIN)).toBe("2 days");
  });

  it("formats the lockout countdown", () => {
    expect(lockoutLeft(4 * MIN)).toBe("4 min");
    expect(lockoutLeft(3 * MIN + 5_000)).toBe("4 min");
    expect(lockoutLeft(45_000)).toBe("45 s");
    expect(lockoutLeft(0)).toBe("0 s");
    expect(lockedText(NOW + 4 * MIN, NOW)).toBe("Too many wrong tokens. Try again in 4 min.");
  });

  it("defaults to 1 hour, else the shortest, else until turned back on", () => {
    expect(defaultMinutes(offer)).toBe(60);
    expect(defaultMinutes({ ...offer, minutes: [15, 30] })).toBe(15);
    expect(defaultMinutes({ ...offer, minutes: [] })).toBeNull();
  });
});

describe("pause state text", () => {
  it("says when protection comes back on", () => {
    expect(untilText(pause(), NOW)).toBe(`Turns back on automatically at ${clockTime(NOW + 80 * MIN)} (in 1 h 20 min)`);
    expect(untilText(pause({ until_ms: null }), NOW)).toBe("Until turned back on");
    expect(untilText(pause({ until_ms: NOW + 20 * 60 * MIN }), NOW)).toContain("tomorrow");
  });

  it("says who turned it off and when", () => {
    expect(byText(pause(), NOW + 5 * MIN)).toBe(`Turned off by NUSANTARA\\teknisi at ${clockTime(NOW)}`);
    expect(byText(pause({ by_user: "" }), NOW)).toBe(`Turned off at ${clockTime(NOW)}`);
  });

  it("derives the paused presentation from status.pause, not state", () => {
    const s = { state: "protected", pause: pause() } as const;
    expect(shieldKind(false, s as never)).toBe("paused");
    expect(shieldKind(false, { ...s, pause: null } as never)).toBe("protected");
    expect(shieldKind(true, s as never)).toBe("unavailable");
    const copy = stateCopy("paused", s as never);
    expect(copy.headline).toBe("Protection is off");
    expect(copy.detail).toBe("Detection only: Kestrel still watches and reports to IT but will not stop anything.");
    expect(stateCopy("paused", { ...s, pause: pause({ mode: "full" }) } as never).detail).toBe("Completely off: Kestrel is not watching this PC.");
  });
});

describe("offer and lockout", () => {
  it("offers the button only when the policy allows it", () => {
    expect(canOffer(offer)).toBe(true);
    expect(canOffer(null)).toBe(false);
    expect(canOffer({ ...offer, enabled: false })).toBe(false);
    expect(canOffer({ ...offer, minutes: [], allow_until_resumed: false })).toBe(false);
  });

  it("takes the lockout from the status offer or the last answer, while it lasts", () => {
    expect(lockedUntil(offer, null, NOW)).toBeNull();
    expect(lockedUntil({ ...offer, locked_until_ms: NOW + MIN }, null, NOW)).toBe(NOW + MIN);
    expect(lockedUntil(offer, result({ error: "locked_out", locked_until_ms: NOW + 2 * MIN }), NOW)).toBe(NOW + 2 * MIN);
    expect(lockedUntil(offer, result({ error: "locked_out", locked_until_ms: NOW - 1 }), NOW)).toBeNull();
    expect(lockedUntil(offer, result({ error: "wrong_token", locked_until_ms: NOW + MIN }), NOW)).toBeNull();
  });
});

describe("error messages", () => {
  it("wrong token counts down", () => {
    expect(pauseErrorText(result({ error: "wrong_token", attempts_left: 3 }))).toBe("Wrong token. 3 attempts left before a lockout.");
    expect(pauseErrorText(result({ error: "wrong_token", attempts_left: 1 }))).toBe("Wrong token. 1 attempt left before a lockout.");
    expect(pauseErrorText(result({ error: "wrong_token" }))).toContain("Wrong token.");
  });

  it("lockout is shown by the countdown, policy refusals say which", () => {
    expect(pauseErrorText(result({ error: "locked_out", locked_until_ms: NOW + MIN }))).toBeNull();
    expect(pauseErrorText(result({ error: "not_allowed", denied: "mode_not_allowed" }))).toBe(deniedText("mode_not_allowed"));
    expect(deniedText("disabled")).toContain("doesn't allow turning protection off");
    expect(deniedText("mode_not_allowed")).toContain("completely off");
    expect(deniedText("duration_not_allowed")).toContain("length of time");
  });

  it("other outcomes", () => {
    expect(pauseErrorText(result({ ok: true }))).toBeNull();
    expect(pauseErrorText(result({ error: "unidentified" }))).toContain("Windows account");
    expect(pauseErrorText(result({ error: "internal", message: "Could not save the state." }))).toBe("Could not save the state.");
    expect(pauseErrorText(result({ error: "internal" }))).toContain("protection is still on");
  });

  it("transport failures, including an older agent", () => {
    expect(pauseTransportText({ kind: "agent", message: "bad request: unknown variant" })).toBe(OLDER_AGENT);
    expect(OLDER_AGENT).toBe("This version of Kestrel cannot turn protection off from the tray.");
    expect(pauseTransportText({ kind: "unavailable", message: "" })).toContain("isn't running");
    expect(pauseTransportText({ kind: "timeout", message: "" })).toContain("in time");
    expect(pauseTransportText({ kind: "agent", message: "" }, true)).toContain("back on");
  });
});
