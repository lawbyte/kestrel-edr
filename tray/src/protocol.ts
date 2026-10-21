// Mirror of `kestrel_common::tray` (crates/kestrel-common/src/tray.rs) and
// `kestrel_common::policy::ItContact`. That Rust module is the contract: keep
// these types in lock-step with it. JSON shapes follow its serde attributes
// (internally tagged enums, snake_case variants).

export type TimestampMs = number;
export type Uuid = string;

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ProtectionState = "protected" | "attention" | "isolated" | "degraded" | "offline";
export type ReviewState = "requested" | "approved" | "denied";

export interface ItContact {
  name: string;
  email: string;
  phone: string;
  url: string;
}

export type RemoteKind = "desktop" | "files";
export const REMOTE_KINDS: readonly RemoteKind[] = ["desktop", "files"];

/** An admin's remote session on this PC (no consent step; the employee is always told). */
export interface RemoteSessionNotice {
  active: boolean;
  /** Desktop session or file-manager session (missing → "desktop"). */
  kind: RemoteKind;
  admin_name: string;
  /** true = the admin can only see the screen. */
  view_only: boolean;
  reason: string;
  started_at: TimestampMs;
  ended_at: TimestampMs | null;
}

/** `SubscribeWith.features` value enabling `remote_session` pushes. */
export const FEATURE_REMOTE_SESSION = "remote_session";
/** `SubscribeWith.features` value enabling `consent_request` pushes. */
export const FEATURE_REMOTE_CONSENT = "remote_consent";

/** IT asks to connect (only pushed to `remote_consent` subscribers). */
export interface ConsentRequest {
  request_id: Uuid;
  kind: RemoteKind;
  admin_name: string;
  view_only: boolean;
  reason: string;
  timeout_secs: number;
  expires_at: TimestampMs;
}

export interface TrayStatus {
  state: ProtectionState;
  agent_version: string;
  server_connected: boolean;
  last_policy_sync: TimestampMs | null;
  policy_name: string;
  org_name: string;
  it_contact: ItContact;
  privacy_notice_md: string;
  hostname: string;
  last_check: TimestampMs | null;
  /** Remote-desktop session in progress (missing from older agents → null). */
  remote_session: RemoteSessionNotice | null;
}

export interface ActivityItem {
  id: Uuid;
  ts: TimestampMs;
  title: string;
  body: string;
  severity: Severity;
  alert_id: Uuid | null;
  file: string | null;
  action_taken: string;
  review: ReviewState | null;
}

export type TrayRequest =
  | { op: "status" }
  | { op: "activity"; limit: number }
  | { op: "quick_check" }
  | { op: "request_review"; alert_id: Uuid; justification: string }
  | { op: "subscribe" }
  | { op: "subscribe_with"; features: string[] }
  | { op: "consent_response"; request_id: Uuid; allow: boolean };

export type TrayResponse =
  | ({ type: "status" } & TrayStatus)
  | { type: "activity"; items: ActivityItem[] }
  | { type: "ack"; ok: boolean; message: string }
  | ({ type: "notification" } & ActivityItem)
  | { type: "error"; message: string }
  | ({ type: "remote_session" } & RemoteSessionNotice)
  | ({ type: "consent_request" } & ConsentRequest);

export const PROTECTION_STATES: readonly ProtectionState[] = ["protected", "attention", "isolated", "degraded", "offline"];
export const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];
export const REVIEW_STATES: readonly ReviewState[] = ["requested", "approved", "denied"];

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolError";
  }
}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function str(o: Obj, k: string, def?: string): string {
  const v = o[k];
  if (typeof v === "string") return v;
  if (v === undefined && def !== undefined) return def;
  throw new ProtocolError(`field "${k}" must be a string`);
}
function num(o: Obj, k: string): number {
  const v = o[k];
  if (typeof v === "number" && Number.isFinite(v)) return v;
  throw new ProtocolError(`field "${k}" must be a number`);
}
function bool(o: Obj, k: string): boolean {
  const v = o[k];
  if (typeof v === "boolean") return v;
  throw new ProtocolError(`field "${k}" must be a boolean`);
}
/** `#[serde(default)] Option<T>`: missing or null → null. */
function opt<T>(o: Obj, k: string, read: (o: Obj, k: string) => T): T | null {
  return o[k] === undefined || o[k] === null ? null : read(o, k);
}
function oneOf<T extends string>(o: Obj, k: string, allowed: readonly T[]): T {
  const v = o[k];
  if (typeof v === "string" && (allowed as readonly string[]).includes(v)) return v as T;
  throw new ProtocolError(`field "${k}" has unknown value ${JSON.stringify(v)}`);
}

export function parseItContact(v: unknown): ItContact {
  // Every ItContact field is #[serde(default)].
  const o = isObj(v) ? v : {};
  return { name: str(o, "name", ""), email: str(o, "email", ""), phone: str(o, "phone", ""), url: str(o, "url", "") };
}

export function parseRemoteSession(o: unknown): RemoteSessionNotice {
  if (!isObj(o)) throw new ProtocolError("remote session must be an object");
  return {
    active: bool(o, "active"),
    kind: o["kind"] === undefined ? "desktop" : oneOf(o, "kind", REMOTE_KINDS),
    admin_name: str(o, "admin_name"),
    view_only: bool(o, "view_only"),
    reason: str(o, "reason", ""),
    started_at: num(o, "started_at"),
    ended_at: opt(o, "ended_at", num),
  };
}

export function parseConsentRequest(o: unknown): ConsentRequest {
  if (!isObj(o)) throw new ProtocolError("consent request must be an object");
  return {
    request_id: str(o, "request_id"),
    kind: oneOf(o, "kind", REMOTE_KINDS),
    admin_name: str(o, "admin_name"),
    view_only: o["view_only"] === undefined ? false : bool(o, "view_only"),
    reason: str(o, "reason", ""),
    timeout_secs: num(o, "timeout_secs"),
    expires_at: num(o, "expires_at"),
  };
}

export function parseStatus(o: unknown): TrayStatus {
  if (!isObj(o)) throw new ProtocolError("status must be an object");
  return {
    state: oneOf(o, "state", PROTECTION_STATES),
    agent_version: str(o, "agent_version"),
    server_connected: bool(o, "server_connected"),
    last_policy_sync: opt(o, "last_policy_sync", num),
    policy_name: str(o, "policy_name"),
    org_name: str(o, "org_name"),
    it_contact: parseItContact(o["it_contact"]),
    privacy_notice_md: str(o, "privacy_notice_md"),
    hostname: str(o, "hostname"),
    last_check: opt(o, "last_check", num),
    remote_session: opt(o, "remote_session", (oo, k) => parseRemoteSession(oo[k])),
  };
}

export function parseActivityItem(o: unknown): ActivityItem {
  if (!isObj(o)) throw new ProtocolError("activity item must be an object");
  return {
    id: str(o, "id"),
    ts: num(o, "ts"),
    title: str(o, "title"),
    body: str(o, "body"),
    severity: oneOf(o, "severity", SEVERITIES),
    alert_id: opt(o, "alert_id", str),
    file: opt(o, "file", str),
    action_taken: str(o, "action_taken"),
    review: opt(o, "review", (oo, k) => oneOf(oo, k, REVIEW_STATES)),
  };
}

/** Parse one already-decoded JSON value as a TrayResponse (validated). */
export function parseResponse(v: unknown): TrayResponse {
  if (!isObj(v)) throw new ProtocolError("response must be a JSON object");
  switch (v["type"]) {
    case "status":
      return { type: "status", ...parseStatus(v) };
    case "activity": {
      const items = v["items"];
      if (!Array.isArray(items)) throw new ProtocolError(`field "items" must be an array`);
      return { type: "activity", items: items.map(parseActivityItem) };
    }
    case "ack":
      return { type: "ack", ok: bool(v, "ok"), message: str(v, "message") };
    case "notification":
      return { type: "notification", ...parseActivityItem(v) };
    case "error":
      return { type: "error", message: str(v, "message") };
    case "remote_session":
      return { type: "remote_session", ...parseRemoteSession(v) };
    case "consent_request":
      return { type: "consent_request", ...parseConsentRequest(v) };
    default:
      throw new ProtocolError(`unknown response type ${JSON.stringify(v["type"])}`);
  }
}

/** Parse one JSON line of the pipe protocol. */
export function parseResponseLine(line: string): TrayResponse {
  let v: unknown;
  try {
    v = JSON.parse(line);
  } catch {
    throw new ProtocolError("line is not valid JSON");
  }
  return parseResponse(v);
}

/** Serialise a request as one protocol line (newline-terminated). */
export function encodeRequest(req: TrayRequest): string {
  return JSON.stringify(req) + "\n";
}

/** The session to show: only an active one counts. */
export function activeRemoteSession(n: RemoteSessionNotice | null | undefined): RemoteSessionNotice | null {
  return n && n.active ? n : null;
}

/** Insert or replace an item by id, newest first (pushes may update review state). */
export function upsertActivity(items: ActivityItem[], item: ActivityItem): ActivityItem[] {
  const rest = items.filter((i) => i.id !== item.id);
  return [item, ...rest].sort((a, b) => b.ts - a.ts);
}
