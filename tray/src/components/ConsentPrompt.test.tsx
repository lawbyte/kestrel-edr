import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ConsentPrompt, ConsentResultLine } from "./ConsentPrompt";
import { ARM_DELAY_MS, type ConsentEntry } from "../consent";

const T = 1_000_000;
const entry = (over: Partial<ConsentEntry> = {}, req: Partial<ConsentEntry["req"]> = {}): ConsentEntry => ({
  req: { request_id: "r1", kind: "desktop", admin_name: "Rina Wijaya", view_only: false, reason: "VPN ticket #4821", timeout_secs: 60, expires_at: T + 45_000, ...req },
  shownAt: T,
  sending: null,
  error: null,
  ...over,
});
const render = (e: ConsentEntry, now = T + ARM_DELAY_MS, queued = 0) => renderToStaticMarkup(<ConsentPrompt entry={e} now={now} queued={queued} onAnswer={() => {}} />);

describe("ConsentPrompt", () => {
  it("asks clearly, with reason, countdown and both answers (accessible)", () => {
    const html = render(entry());
    expect(html).toContain('role="alertdialog"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain("Rina Wijaya from IT wants to see and control your screen");
    expect(html).toContain("Reason: VPN ticket #4821");
    expect(html).toContain('role="timer"');
    expect(html).toContain("Closes in 0:44");
    expect(html).toContain("If you don&#x27;t answer, IT can&#x27;t connect.");
    expect(html).toMatch(/data-answer="deny"[^>]*>Deny</);
    expect(html).toMatch(/data-answer="allow"[^>]*>Allow</);
    expect(html).toContain("<svg");
  });

  it("view-only and file wording", () => {
    expect(render(entry({}, { view_only: true }))).toContain("wants to see your screen (view only)");
    const files = render(entry({}, { kind: "files", reason: "" }));
    expect(files).toContain("Rina Wijaya from IT wants to access files on this PC");
    expect(files).toContain("No reason was given.");
  });

  it("Allow is disabled until armed; Deny never is", () => {
    const early = render(entry(), T + 200);
    expect(early).toMatch(/<button[^>]*data-answer="allow"[^>]*disabled=""/);
    expect(early).not.toMatch(/<button[^>]*data-answer="deny"[^>]*disabled=""/);
    expect(render(entry())).not.toMatch(/<button[^>]*data-answer="allow"[^>]*disabled=""/);
  });

  it("shows sending state, errors and the queue length", () => {
    const html = render(entry({ sending: "allow", error: null }), T + 5000, 2);
    expect(html).toContain("Sending…");
    expect(html).toMatch(/data-answer="deny"[^>]*disabled=""/);
    expect(html).toContain("2 more requests are waiting.");
    expect(render(entry({ error: "Your answer couldn't be sent. Try again." }))).toContain('role="alert"');
  });

  it("timeout: the countdown bottoms out at 0:00", () => {
    expect(render(entry(), T + 60_000)).toContain("Closes in 0:00");
  });

  it("escapes server-provided text", () => {
    const html = render(entry({}, { admin_name: "<b>x</b>", reason: "<img src=x>" }));
    expect(html).not.toContain("<b>x</b>");
    expect(html).not.toContain("<img");
  });
});

describe("ConsentResultLine", () => {
  it("announces the outcome", () => {
    const html = renderToStaticMarkup(<ConsentResultLine kind="denied" message="You said no. IT can't connect." onDismiss={() => {}} />);
    expect(html).toContain('role="status"');
    expect(html).toContain("You said no.");
  });
});
