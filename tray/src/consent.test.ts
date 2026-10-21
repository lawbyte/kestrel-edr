import { describe, expect, it } from "vitest";
import { ARM_DELAY_MS, consentAsk, consentReducer, countdown, initialConsentState, isArmed, MAX_PENDING, secondsLeft, type ConsentState } from "./consent";
import type { ConsentRequest } from "./protocol";

const T = 1_000_000;
const req = (id: string, expiresIn = 60_000, extra: Partial<ConsentRequest> = {}): ConsentRequest => ({
  request_id: id,
  kind: "desktop",
  admin_name: "Rina",
  view_only: false,
  reason: "VPN",
  timeout_secs: 60,
  expires_at: T + expiresIn,
  ...extra,
});
const recv = (s: ConsentState, r: ConsentRequest, now = T) => consentReducer(s, { type: "received", req: r, now });

describe("consent queue", () => {
  it("queues in arrival order and shows only the head", () => {
    let s = recv(initialConsentState, req("a"));
    s = recv(s, req("b"), T + 10);
    expect(s.queue.map((e) => e.req.request_id)).toEqual(["a", "b"]);
    expect(s.queue[0]!.shownAt).toBe(T);
    expect(s.queue[1]!.shownAt).toBeNull();
  });

  it("ignores expired requests, de-duplicates by id and is bounded", () => {
    let s = recv(initialConsentState, req("old", -1));
    expect(s.queue).toHaveLength(0);
    s = recv(s, req("a"));
    s = recv(s, req("a", 90_000));
    expect(s.queue).toHaveLength(1);
    expect(s.queue[0]!.req.expires_at).toBe(T + 90_000);
    for (let i = 0; i < MAX_PENDING + 3; i++) s = recv(s, req(`x${i}`));
    expect(s.queue).toHaveLength(MAX_PENDING);
  });

  it("allow: answered removes the entry, reports it, and shows the next one", () => {
    let s = recv(recv(initialConsentState, req("a")), req("b"));
    s = consentReducer(s, { type: "sending", id: "a", allow: true });
    expect(s.queue[0]!.sending).toBe("allow");
    s = consentReducer(s, { type: "answered", id: "a", allow: true, ok: true, message: "IT can now connect.", now: T + 5000 });
    expect(s.queue.map((e) => e.req.request_id)).toEqual(["b"]);
    expect(s.queue[0]!.shownAt).toBe(T + 5000); // re-armed from when it became visible
    expect(s.result).toEqual({ kind: "allowed", id: "a", message: "IT can now connect." });
  });

  it("deny: reported as denied, with a fallback message", () => {
    let s = recv(initialConsentState, req("a"));
    s = consentReducer(s, { type: "answered", id: "a", allow: false, ok: true, message: "", now: T });
    expect(s.queue).toHaveLength(0);
    expect(s.result?.kind).toBe("denied");
    expect(s.result?.message).toMatch(/can't connect/);
  });

  it("timeout: drops the request without answering (deny by default)", () => {
    let s = recv(recv(initialConsentState, req("a", 10_000)), req("b", 60_000));
    s = consentReducer(s, { type: "tick", now: T + 9_999 });
    expect(s.queue).toHaveLength(2);
    s = consentReducer(s, { type: "tick", now: T + 10_000 });
    expect(s.queue.map((e) => e.req.request_id)).toEqual(["b"]);
    expect(s.queue[0]!.shownAt).toBe(T + 10_000);
    expect(s.result?.kind).toBe("expired");
    expect(s.result?.message).toMatch(/Rina from IT can't connect/);
  });

  it("an answer in flight is not expired underneath the user", () => {
    let s = recv(initialConsentState, req("a", 1000));
    s = consentReducer(s, { type: "sending", id: "a", allow: false });
    s = consentReducer(s, { type: "tick", now: T + 5000 });
    expect(s.queue).toHaveLength(1);
  });

  it("failures: agent rejection drops it; transport errors keep it for a retry", () => {
    let s = recv(recv(initialConsentState, req("a")), req("b"));
    s = consentReducer(s, { type: "sending", id: "a", allow: true });
    s = consentReducer(s, { type: "failed", id: "a", drop: false, message: "try again", now: T });
    expect(s.queue[0]).toMatchObject({ sending: null, error: "try again" });
    s = consentReducer(s, { type: "failed", id: "a", drop: true, message: "no longer valid", now: T + 1 });
    expect(s.queue.map((e) => e.req.request_id)).toEqual(["b"]);
    expect(s.result).toMatchObject({ kind: "error", message: "no longer valid" });
    expect(consentReducer(s, { type: "dismiss_result" }).result).toBeNull();
  });

  it("Allow is armed only after the prompt has been visible for a moment", () => {
    const s = recv(initialConsentState, req("a"));
    expect(isArmed(s.queue[0]!, T)).toBe(false);
    expect(isArmed(s.queue[0]!, T + ARM_DELAY_MS - 1)).toBe(false);
    expect(isArmed(s.queue[0]!, T + ARM_DELAY_MS)).toBe(true);
  });
});

describe("consent wording", () => {
  it("names the admin and what they want", () => {
    expect(consentAsk(req("a"))).toBe("Rina from IT wants to see and control your screen");
    expect(consentAsk(req("a", 1, { view_only: true }))).toBe("Rina from IT wants to see your screen (view only)");
    expect(consentAsk(req("a", 1, { kind: "files" }))).toBe("Rina from IT wants to access files on this PC");
    expect(consentAsk(req("a", 1, { admin_name: " " }))).toMatch(/^Someone from IT/);
  });
  it("counts down in m:ss and never below zero", () => {
    expect(secondsLeft(req("a", 65_000), T)).toBe(65);
    expect(secondsLeft(req("a", 500), T)).toBe(1);
    expect(secondsLeft(req("a", 0), T + 5)).toBe(0);
    expect(countdown(65)).toBe("1:05");
    expect(countdown(9)).toBe("0:09");
  });
});
