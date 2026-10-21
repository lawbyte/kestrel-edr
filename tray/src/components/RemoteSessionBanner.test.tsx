import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { RemoteSessionBanner } from "./RemoteSessionBanner";
import { StatusTab } from "./StatusTab";
import { remoteSessionCopy } from "../copy";
import { clockTime } from "../format";
import type { ItContact, RemoteSessionNotice, TrayStatus } from "../protocol";

const contact: ItContact = { name: "IT Service Desk", email: "servicedesk@example.com", phone: "+62 21 5088 1200", url: "" };
const started = new Date(2026, 9, 21, 9, 41).getTime();
const session: RemoteSessionNotice = {
  active: true,
  kind: "desktop",
  admin_name: "Rina Wijaya",
  view_only: false,
  reason: "Checking the VPN problem",
  started_at: started,
  ended_at: null,
};
const noop = () => {};

describe("RemoteSessionBanner", () => {
  it("says who has control, since when, why, and how to reach IT", () => {
    const html = renderToStaticMarkup(<RemoteSessionBanner session={session} contact={contact} onContactIT={noop} />);
    expect(html).toContain('role="status"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain("Rina Wijaya from IT can see and control your screen");
    expect(html).toContain("Can control your screen");
    expect(html).toContain(`Since ${clockTime(started)}`);
    expect(html).toContain("Reason: Checking the VPN problem");
    expect(html).toContain("Contact IT Service Desk (+62 21 5088 1200) now.");
    expect(html).toContain("<svg"); // icon + text, not colour alone
    // Non-dismissable: the only control is "Contact IT".
    expect(html.match(/<button/g)).toHaveLength(1);
    expect(html).toContain(">Contact IT</button>");
  });

  it("uses view-only wording and copes with missing reason/contact", () => {
    const html = renderToStaticMarkup(<RemoteSessionBanner session={{ ...session, view_only: true, reason: "" }} contact={null} onContactIT={noop} />);
    expect(html).toContain("Rina Wijaya from IT is viewing your screen");
    expect(html).toContain("View only");
    expect(html).not.toContain("Reason:");
    expect(html).toContain("Didn&#x27;t expect this? Contact IT now.");
    expect(html).toContain("remote--view");
  });

  it("describes file-access sessions", () => {
    const html = renderToStaticMarkup(<RemoteSessionBanner session={{ ...session, kind: "files" }} contact={contact} onContactIT={noop} />);
    expect(html).toContain("Rina Wijaya from IT is accessing files on this PC");
    expect(html).toContain("File access");
    expect(html).toContain("remote--files");
  });

  it("escapes server-provided text", () => {
    const html = renderToStaticMarkup(<RemoteSessionBanner session={{ ...session, admin_name: "<img src=x onerror=alert(1)>" }} contact={contact} onContactIT={noop} />);
    expect(html).not.toContain("<img");
  });
});

describe("remoteSessionCopy", () => {
  it("adds the date when the session started on another day", () => {
    const c = remoteSessionCopy(session, contact, started + 30 * 60 * 60 * 1000);
    expect(c.since).toMatch(/^Since .+ on /);
    expect(remoteSessionCopy(session, contact, started + 60_000).since).toBe(`Since ${clockTime(started)}`);
  });
  it("uses email when IT has no phone number", () => {
    expect(remoteSessionCopy(session, { ...contact, phone: "" }).help).toBe("Didn't expect this? Contact IT Service Desk (servicedesk@example.com) now.");
  });
  it("falls back when the admin name is blank", () => {
    expect(remoteSessionCopy({ ...session, admin_name: "  " }).headline).toBe("Someone from IT can see and control your screen");
  });
});

describe("StatusTab", () => {
  const status: TrayStatus = {
    state: "protected",
    agent_version: "1.1.0",
    server_connected: true,
    last_policy_sync: null,
    policy_name: "Staff laptops",
    org_name: "Acme",
    it_contact: contact,
    privacy_notice_md: "",
    hostname: "PC-1",
    last_check: null,
    remote_session: session,
    pause: null,
    local_pause: null,
  };
  const props = { kind: "protected" as const, recentBlocks: 0, check: { phase: "idle" as const }, onQuickCheck: noop, onDismissCheck: noop, onGo: noop };

  it("shows an IT remote access row while a session is active", () => {
    const html = renderToStaticMarkup(<StatusTab {...props} status={status} remote={session} />);
    expect(html).toContain("IT remote access");
    expect(html).toContain("Rina Wijaya is in control");
  });

  it("has no remote row without a session", () => {
    const html = renderToStaticMarkup(<StatusTab {...props} status={{ ...status, remote_session: null }} remote={null} />);
    expect(html).not.toContain("IT remote access");
  });
});
