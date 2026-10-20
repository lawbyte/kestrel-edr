import { describe, expect, it } from "vitest";
import { encodeRequest, parseResponseLine, ProtocolError, upsertActivity, type ActivityItem } from "./protocol";

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
