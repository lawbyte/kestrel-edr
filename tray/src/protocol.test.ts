import { describe, expect, it } from "vitest";
import { activeRemoteSession, encodeRequest, FEATURE_REMOTE_CONSENT, FEATURE_REMOTE_SESSION, parseResponseLine, ProtocolError, upsertActivity, type ActivityItem } from "./protocol";

const item = {
  id: "6b657374-7265-6c00-0000-000000000001",
  ts: 1_760_000_000_000,
  title: "Kestrel stopped setup_x64.exe from reading your saved browser passwords",
  body: "…",
  severity: "high",
  alert_id: "6b657374-7265-6c00-0000-000000000101",
  file: "C:\\Users\\a\\Downloads\\setup_x64.exe",
  action_taken: "Stopped and quarantined",
  review: null,
};
const status = {
  state: "protected",
  agent_version: "0.1.0",
  server_connected: true,
  last_policy_sync: 1_760_000_000_000,
  policy_name: "Staff laptops",
  org_name: "Acme",
  it_contact: { name: "IT", email: "it@acme.example", phone: "", url: "" },
  privacy_notice_md: "## Notice",
  hostname: "PC-1",
  last_check: null,
};

describe("parseResponseLine", () => {
  it("parses status (internally tagged, flattened)", () => {
    const r = parseResponseLine(JSON.stringify({ type: "status", ...status }));
    expect(r.type).toBe("status");
    if (r.type === "status") {
      expect(r.state).toBe("protected");
      expect(r.it_contact.email).toBe("it@acme.example");
      expect(r.last_check).toBeNull();
    }
  });

  it("applies serde defaults for missing optional fields", () => {
    const { last_policy_sync: _a, last_check: _b, ...minimal } = status;
    const r = parseResponseLine(JSON.stringify({ type: "status", ...minimal, it_contact: {} }));
    if (r.type !== "status") throw new Error("type");
    expect(r.last_policy_sync).toBeNull();
    expect(r.it_contact).toEqual({ name: "", email: "", phone: "", url: "" });

    const { alert_id: _c, file: _d, review: _e, ...bare } = item;
    const n = parseResponseLine(JSON.stringify({ type: "notification", ...bare }));
    if (n.type !== "notification") throw new Error("type");
    expect(n.alert_id).toBeNull();
    expect(n.review).toBeNull();
  });

  it("parses activity, ack, notification and error", () => {
    const a = parseResponseLine(JSON.stringify({ type: "activity", items: [item, { ...item, id: "x", review: "approved" }] }));
    expect(a.type === "activity" && a.items[1]!.review).toBe("approved");
    expect(parseResponseLine('{"type":"ack","ok":true,"message":"sent"}')).toEqual({ type: "ack", ok: true, message: "sent" });
    expect(parseResponseLine(JSON.stringify({ type: "notification", ...item })).type).toBe("notification");
    expect(parseResponseLine('{"type":"error","message":"boom"}')).toEqual({ type: "error", message: "boom" });
  });

  it("rejects malformed or unknown input", () => {
    expect(() => parseResponseLine("not json")).toThrow(ProtocolError);
    expect(() => parseResponseLine("[]")).toThrow(ProtocolError);
    expect(() => parseResponseLine('{"type":"surprise"}')).toThrow(/unknown response type/);
    expect(() => parseResponseLine(JSON.stringify({ type: "status", ...status, state: "pwned" }))).toThrow(/state/);
    expect(() => parseResponseLine(JSON.stringify({ type: "notification", ...item, severity: "urgent" }))).toThrow(/severity/);
    expect(() => parseResponseLine(JSON.stringify({ type: "notification", ...item, ts: "yesterday" }))).toThrow(/ts/);
    expect(() => parseResponseLine(JSON.stringify({ type: "activity", items: {} }))).toThrow(/items/);
  });

  it("ignores unknown extra fields (forward compatible, like serde)", () => {
    const r = parseResponseLine(JSON.stringify({ type: "ack", ok: false, message: "", extra: 1 }));
    expect(r).toEqual({ type: "ack", ok: false, message: "" });
  });
});

describe("encodeRequest", () => {
  it("matches the Rust TrayRequest serde shape", () => {
    expect(encodeRequest({ op: "status" })).toBe('{"op":"status"}\n');
    expect(encodeRequest({ op: "activity", limit: 50 })).toBe('{"op":"activity","limit":50}\n');
    expect(encodeRequest({ op: "quick_check" })).toBe('{"op":"quick_check"}\n');
    expect(encodeRequest({ op: "request_review", alert_id: "a", justification: "line1\nline2" })).toBe(
      '{"op":"request_review","alert_id":"a","justification":"line1\\nline2"}\n',
    );
    // A single protocol line, even with newlines in user text.
    expect(encodeRequest({ op: "request_review", alert_id: "a", justification: "x\n\ny" }).split("\n")).toHaveLength(2);
  });
});

describe("upsertActivity", () => {
  it("replaces by id and keeps newest first", () => {
    const a = { ...item, id: "a", ts: 1 } as ActivityItem;
    const b = { ...item, id: "b", ts: 2 } as ActivityItem;
    const list = upsertActivity([b, a], { ...a, review: "requested" });
    expect(list.map((i) => i.id)).toEqual(["b", "a"]);
    expect(list[1]!.review).toBe("requested");
    expect(upsertActivity(list, { ...a, id: "c", ts: 3 })[0]!.id).toBe("c");
  });
});

describe("remote session", () => {
  const notice = {
    active: true,
    kind: "desktop",
    admin_name: "Jane Doe",
    view_only: false,
    reason: "VPN ticket",
    started_at: 1_760_000_000_000,
    ended_at: null,
  };

  it("parses the remote_session push", () => {
    const r = parseResponseLine(JSON.stringify({ type: "remote_session", ...notice }));
    expect(r).toEqual({ type: "remote_session", ...notice });
    const ended = parseResponseLine(JSON.stringify({ type: "remote_session", ...notice, active: false, ended_at: 1_760_000_600_000 }));
    expect(ended.type === "remote_session" && activeRemoteSession(ended)).toBeNull();
  });

  it("applies serde defaults (kind, reason, ended_at)", () => {
    const { reason: _r, ended_at: _e, kind: _k, ...minimal } = notice;
    const r = parseResponseLine(JSON.stringify({ type: "remote_session", ...minimal }));
    if (r.type !== "remote_session") throw new Error("type");
    expect(r.kind).toBe("desktop");
    expect(r.reason).toBe("");
    expect(r.ended_at).toBeNull();
  });

  it("rejects malformed notices", () => {
    expect(() => parseResponseLine(JSON.stringify({ type: "remote_session", ...notice, active: "yes" }))).toThrow(/active/);
    expect(() => parseResponseLine(JSON.stringify({ type: "remote_session", ...notice, kind: "shell" }))).toThrow(/kind/);
    expect(() => parseResponseLine(JSON.stringify({ type: "remote_session", ...notice, admin_name: 7 }))).toThrow(/admin_name/);
    expect(() => parseResponseLine(JSON.stringify({ type: "remote_session", ...notice, started_at: null }))).toThrow(/started_at/);
    expect(() => parseResponseLine(JSON.stringify({ type: "status", ...status, remote_session: "on" }))).toThrow(/remote session/);
  });

  it("status carries remote_session; missing or null means none (older agents)", () => {
    const withSession = parseResponseLine(JSON.stringify({ type: "status", ...status, remote_session: notice }));
    expect(withSession.type === "status" && withSession.remote_session).toEqual(notice);
    const old = parseResponseLine(JSON.stringify({ type: "status", ...status }));
    expect(old.type === "status" && old.remote_session).toBeNull();
    const nul = parseResponseLine(JSON.stringify({ type: "status", ...status, remote_session: null }));
    expect(nul.type === "status" && nul.remote_session).toBeNull();
  });

  it("parses files sessions and consent requests", () => {
    const f = parseResponseLine(JSON.stringify({ type: "remote_session", ...notice, kind: "files" }));
    expect(f.type === "remote_session" && f.kind).toBe("files");
    const c = parseResponseLine(
      JSON.stringify({ type: "consent_request", request_id: "r1", kind: "desktop", admin_name: "Jane", timeout_secs: 60, expires_at: 5 }),
    );
    expect(c).toEqual({ type: "consent_request", request_id: "r1", kind: "desktop", admin_name: "Jane", view_only: false, reason: "", timeout_secs: 60, expires_at: 5 });
    expect(() => parseResponseLine(JSON.stringify({ type: "consent_request", request_id: "r1", kind: "shell", admin_name: "J", timeout_secs: 1, expires_at: 5 }))).toThrow(/kind/);
    expect(() => parseResponseLine(JSON.stringify({ type: "consent_request", request_id: "r1", kind: "files", admin_name: "J", expires_at: 5 }))).toThrow(/timeout_secs/);
    expect(encodeRequest({ op: "consent_response", request_id: "r1", allow: true })).toBe('{"op":"consent_response","request_id":"r1","allow":true}\n');
  });

  it("encodes subscribe_with like the Rust contract", () => {
    expect(encodeRequest({ op: "subscribe_with", features: [FEATURE_REMOTE_SESSION, FEATURE_REMOTE_CONSENT] })).toBe('{"op":"subscribe_with","features":["remote_session","remote_consent"]}\n');
  });
});
