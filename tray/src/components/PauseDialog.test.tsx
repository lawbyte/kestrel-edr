import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { PauseDialog } from "./PauseDialog";
import { StatusTab } from "./StatusTab";
import type { PauseOffer, TrayStatus } from "../protocol";

const NOW = 1_760_000_000_000;
const offer: PauseOffer = { enabled: true, allow_full: true, minutes: [15, 60, 240, 480], allow_until_resumed: true, locked_until_ms: null };
const render = (o: PauseOffer = offer) =>
  renderToStaticMarkup(<PauseDialog offer={o} hostname="LT-JKT-0142" now={NOW} onSubmit={() => Promise.reject()} onDone={() => {}} onClose={() => {}} />);

describe("PauseDialog", () => {
  it("explains, asks for the token safely and is labelled", () => {
    const html = render();
    expect(html).toContain('aria-labelledby="pause-title"');
    expect(html).toContain("Turn off protection");
    expect(html).toContain("uninstall token");
    expect(html).toContain("reported to IT");
    expect(html).toMatch(/<input[^>]*type="password"/);
    expect(html).toMatch(/<input[^>]*type="password"[^>]*autoComplete="off"|<input[^>]*autocomplete="off"[^>]*type="password"|type="password"[^>]*autocomplete="off"/i);
    expect(html).toMatch(/spellCheck="false"|spellcheck="false"/);
    expect(html).toContain("<code>LT-JKT-0142</code>");
  });

  it("offers the policy's modes and durations, detection only by default", () => {
    const html = render();
    expect(html).toMatch(/checked="" value="detection_only"/);
    expect(html).toContain("Completely off");
    expect(html).toContain("After 15 minutes");
    expect(html).toContain("After 1 hour");
    expect(html).toContain("After 4 hours");
    expect(html).toContain("After 8 hours");
    expect(html).toContain("Until I turn it back on");
    expect(html).toMatch(/<option value="60" selected="">/);
  });

  it("hides what the policy doesn't allow", () => {
    const html = render({ ...offer, allow_full: false, allow_until_resumed: false, minutes: [15, 30] });
    expect(html).not.toContain("Completely off");
    expect(html).not.toContain("Until I turn it back on");
    expect(html).toContain("After 30 minutes");
    expect(html).toMatch(/<option value="15" selected="">/);
  });

  it("locked out: says so with the countdown and can't submit", () => {
    const html = render({ ...offer, locked_until_ms: NOW + 4 * 60_000 });
    expect(html).toContain('role="alert"');
    expect(html).toContain("Too many wrong tokens. Try again in 4 min.");
    expect(html).toMatch(/<button type="submit"[^>]*disabled=""/);
  });

  it("submit is disabled until a token is typed", () => {
    expect(render()).toMatch(/<button type="submit"[^>]*disabled=""/);
  });
});

const base: TrayStatus = {
  state: "protected",
  agent_version: "1.1.3",
  server_connected: true,
  last_policy_sync: NOW,
  policy_name: "Staff laptops",
  org_name: "Acme",
  it_contact: { name: "IT", email: "", phone: "", url: "" },
  privacy_notice_md: "",
  hostname: "PC-1",
  last_check: null,
  remote_session: null,
  pause: null,
  local_pause: offer,
};
const status = (s: TrayStatus, kind: "protected" | "paused") =>
  renderToStaticMarkup(
    <StatusTab kind={kind} status={s} recentBlocks={0} check={{ phase: "idle" }} onQuickCheck={() => {}} onDismissCheck={() => {}} onGo={() => {}} onTurnOff={() => {}} onResume={() => {}} now={NOW} />,
  );

describe("StatusTab and the switch", () => {
  it("shows Turn off only when allowed and protection is on", () => {
    expect(status(base, "protected")).toContain("Turn off protection");
    expect(status({ ...base, local_pause: null }, "protected")).not.toContain("Turn off protection");
    expect(status({ ...base, local_pause: { ...offer, enabled: false } }, "protected")).not.toContain("Turn off protection");
  });

  it("paused: amber card with mode, time left, who, and a resume button", () => {
    const html = status({ ...base, pause: { mode: "full", since_ms: NOW - 60_000, until_ms: null, by_user: "W\\tech" } }, "paused");
    expect(html).toContain("hero--paused");
    expect(html).toContain("shield--paused");
    expect(html).toContain("Protection is off");
    expect(html).toContain("Completely off: Kestrel is not watching this PC.");
    expect(html).toContain("Until turned back on");
    expect(html).toContain("Turned off by W\\tech");
    expect(html).toContain("Turn protection back on");
    expect(html).not.toContain("Turn off…");
  });
});
