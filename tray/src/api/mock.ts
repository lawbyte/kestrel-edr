// Browser mock of the Tauri backend for `npm run dev:mock`.
//
// MOCK UNINSTALL TOKEN: kun_mock_token  (turns protection off in the mock).
// Five wrong tokens lock the switch for 1 minute, doubling up to 1 hour, like
// the agent.
//
// URL parameters (all optional):
//   ?state=protected|attention|isolated|degraded|offline|unavailable
//   ?tab=status|activity|help      initial tab
//   ?theme=light|dark              force a theme (default: follow the system)
//   ?empty=1                       no activity
//   ?push=<seconds>                push a demo notification after N seconds
//   ?notice=0                      org has no privacy notice
//   ?remote=view|control|files|cycle  IT remote session: active (view-only /
//                                  control / file access) from the start, or
//                                  starting after 3 s, ending after 30 s, repeating
//   ?consent=desktop|view|files|queue  IT asks for consent after ?consent_in=<s>
//                                  (default 1); queue = two requests at once;
//                                  ?consent_timeout=<s> (default 60)
//   ?pause=open|basic|disabled|legacy|active|active_full|locked
//                                  turn-off switch: open (default) = every mode
//                                  and "until I turn it back on" allowed; basic =
//                                  agent defaults (detection only, timed only);
//                                  disabled = not allowed by policy; legacy = an
//                                  older agent without the switch; active = off
//                                  (detection only, ~80 min left); active_full =
//                                  completely off until turned back on; locked =
//                                  lockout in force for 4 minutes
import type { ActivityItem, ConsentRequest, PauseMode, PauseOffer, PauseResult, PauseState, ProtectionState, RemoteKind, RemoteSessionNotice, TrayStatus } from "../protocol";
import type { Ack, KestrelApi, Tab, Unlisten, WindowMode } from "./types";

const MIN = 60_000;
const params = new URLSearchParams(typeof location === "undefined" ? "" : location.search);
const stateParam = params.get("state") ?? "attention";
const unavailable = stateParam === "unavailable";
const state = (["protected", "attention", "isolated", "degraded", "offline"].includes(stateParam) ? stateParam : "attention") as ProtectionState;

export const SAMPLE_NOTICE = `## Monitoring notice

Nusantara Logistik uses **Kestrel** on company laptops to detect malware that steals passwords, browser sessions and crypto wallets. This notice is given under Indonesia's Personal Data Protection Law (UU PDP) and Singapore's PDPA.

### What is collected
- Names, locations and fingerprints (hashes) of programs that run, and which program started them
- Which programs open browser password, cookie and wallet files (not what is inside them)
- Network addresses contacted by programs that are not web browsers

### Why
To stop account theft and investigate security incidents. This data is not used to measure your work or performance.

### How long we keep it, and your rights
Alerts are kept for 12 months and raw activity records for 30 days. To get a copy of data about you or ask a question, contact our Data Protection Officer at [dpo@nusantaralogistik.example](mailto:dpo@nusantaralogistik.example).

Full policy: https://intranet.nusantaralogistik.example/privacy/endpoint
`;

function sampleStatus(): TrayStatus {
  const now = Date.now();
  return {
    state,
    agent_version: "0.1.0",
    server_connected: state !== "offline",
    last_policy_sync: now - (state === "offline" ? 26 * 60 * MIN : 4 * MIN),
    policy_name: "Staff laptops",
    org_name: "Nusantara Logistik",
    it_contact: {
      name: "IT Service Desk",
      email: "servicedesk@nusantaralogistik.example",
      phone: "+62 21 5088 1200",
      url: "https://help.nusantaralogistik.example",
    },
    privacy_notice_md: params.get("notice") === "0" ? "" : SAMPLE_NOTICE,
    hostname: "LT-JKT-0142",
    last_check: now - 2 * 24 * 60 * MIN,
    remote_session:
      remoteParam === "view" || remoteParam === "control"
        ? sampleRemoteSession(remoteParam === "view")
        : remoteParam === "files"
          ? { ...sampleRemoteSession(false), kind: "files" }
          : null,
    pause:
      pauseParam === "active"
        ? { mode: "detection_only", since_ms: now - 40 * MIN, until_ms: now + 80 * MIN, by_user: MOCK_USER }
        : pauseParam === "active_full"
          ? { mode: "full", since_ms: now - 40 * MIN, until_ms: null, by_user: MOCK_USER }
          : null,
    local_pause: pauseParam === "legacy" ? null : sampleOffer(),
  };
}

export const MOCK_TOKEN = "kun_mock_token";
const MOCK_USER = String.raw`NUSANTARA\dewi.lestari`;
const pauseParam = params.get("pause") ?? "open";

function sampleOffer(): PauseOffer {
  if (pauseParam === "disabled") return { enabled: false, allow_full: false, minutes: [], allow_until_resumed: false, locked_until_ms: null };
  const open = pauseParam !== "basic";
  return {
    enabled: true,
    allow_full: open,
    minutes: [15, 60, 240, 480],
    allow_until_resumed: open,
    locked_until_ms: pauseParam === "locked" ? Date.now() + 4 * MIN : null,
  };
}

const remoteParam = params.get("remote");

export function sampleRemoteSession(viewOnly: boolean, startedAt = Date.now() - 3 * MIN): RemoteSessionNotice {
  return {
    active: true,
    kind: "desktop",
    admin_name: "Rina Wijaya",
    view_only: viewOnly,
    reason: "Checking the VPN problem you reported (ticket #4821)",
    started_at: startedAt,
    ended_at: null,
  };
}

const id = (n: number) => `6b657374-7265-6c00-0000-${String(n).padStart(12, "0")}`;

export function sampleActivity(): ActivityItem[] {
  const now = Date.now();
  return [
    {
      id: id(1),
      ts: now - 12 * MIN,
      title: "Kestrel stopped setup_x64.exe from reading your saved browser passwords",
      body: "This installer was downloaded today and tried to open the file where Chrome keeps your saved passwords. Installers don't need that file, so Kestrel stopped it before anything was read.",
      severity: "high",
      alert_id: id(101),
      file: "C:\\Users\\dewi.lestari\\Downloads\\setup_x64.exe",
      action_taken: "Stopped and quarantined",
      review: null,
    },
    {
      id: id(2),
      ts: now - 3 * 60 * MIN,
      title: "Kestrel blocked a command pasted into the Run box",
      body: 'A web page asked you to paste a command into Windows Run to "verify you are human". The command would have downloaded a hidden program. If you were following steps from a website, close that page.',
      severity: "medium",
      alert_id: id(102),
      file: null,
      action_taken: "Blocked before it ran",
      review: "requested",
    },
    {
      id: id(3),
      ts: now - 27 * 60 * MIN,
      title: "Kestrel stopped an app from sending your Telegram login to the internet",
      body: "upd4831.exe copied your Telegram Desktop session files and tried to upload them. Kestrel stopped the upload and told IT, who may contact you.",
      severity: "critical",
      alert_id: id(103),
      file: "C:\\Users\\dewi.lestari\\AppData\\Local\\Temp\\upd4831.exe",
      action_taken: "Stopped, quarantined and reported to IT",
      review: "denied",
    },
    {
      id: id(4),
      ts: now - 3 * 24 * 60 * MIN,
      title: "Kestrel paused an app that read your Discord login",
      body: "DiscordChatExporter.exe opened Discord's saved login. You asked IT to review it and they allowed it for your PC.",
      severity: "low",
      alert_id: id(104),
      file: "C:\\Users\\dewi.lestari\\Tools\\DiscordChatExporter.exe",
      action_taken: "Paused, then allowed by IT",
      review: "approved",
    },
    {
      id: id(5),
      ts: now - 5 * 24 * 60 * MIN,
      title: "Your IT team updated Kestrel's protection settings",
      body: 'New settings from the "Staff laptops" policy are now in effect. You don\'t need to do anything.',
      severity: "info",
      alert_id: null,
      file: null,
      action_taken: "Settings applied",
      review: null,
    },
  ];
}

type Listener<T> = (v: T) => void;
function emitter<T>() {
  const ls = new Set<Listener<T>>();
  return {
    on(cb: Listener<T>): Promise<Unlisten> {
      ls.add(cb);
      return Promise.resolve(() => ls.delete(cb));
    },
    emit(v: T) {
      ls.forEach((l) => l(v));
    },
  };
}

const status = sampleStatus();
let items = params.get("empty") === "1" ? [] : sampleActivity();
let mode: WindowMode = "flyout";
const notifications = emitter<ActivityItem>();
const statuses = emitter<TrayStatus>();
const remoteSessions = emitter<RemoteSessionNotice>();
const consentRequests = emitter<ConsentRequest>();
let pendingConsents: ConsentRequest[] = [];
let consentSeq = 0;

function requestConsent(kind: RemoteKind, viewOnly: boolean, timeoutSecs: number, admin = "Rina Wijaya") {
  const req: ConsentRequest = {
    request_id: `c0115e47-0000-4000-8000-${String(++consentSeq).padStart(12, "0")}`,
    kind,
    admin_name: admin,
    view_only: viewOnly && kind === "desktop",
    reason: "Checking the VPN problem you reported (ticket #4821)",
    timeout_secs: timeoutSecs,
    expires_at: Date.now() + timeoutSecs * 1000,
  };
  pendingConsents.push(req);
  consentRequests.emit(req);
}

const consentParam = params.get("consent");
if (consentParam) {
  const timeout = Number(params.get("consent_timeout") ?? "60") || 60;
  setTimeout(
    () => {
      if (consentParam === "queue") {
        requestConsent("desktop", false, timeout);
        requestConsent("files", false, timeout + 30, "Budi Santoso");
      } else requestConsent(consentParam === "files" ? "files" : "desktop", consentParam === "view", timeout);
    },
    Number(params.get("consent_in") ?? "1") * 1000,
  );
}
// Turn-off switch state (like the agent: failures, then a doubling lockout).
let pauseFailures = 0;
let pauseLockouts = 0;
const fail = (error: PauseResult["error"], extra: Partial<PauseResult> = {}): PauseResult => ({
  ok: false,
  error,
  message: "",
  attempts_left: null,
  locked_until_ms: null,
  denied: null,
  state: null,
  ...extra,
});
const legacyPause = () => Promise.reject({ kind: "agent", message: "bad request: unknown variant `pause_protection`" });

function pauseNotice(on: boolean, p: PauseState, body?: string) {
  const item: ActivityItem = {
    id: `9a05e000-0000-4000-8000-${String(Date.now() % 1e12).padStart(12, "0")}`,
    ts: Date.now(),
    title: on ? "Protection is back on" : p.mode === "full" ? "Protection was turned off completely on this PC" : "Protection was turned off on this PC (detection only)",
    body: body ?? (on ? `${MOCK_USER} turned protection back on from the tray.` : `${MOCK_USER} turned Kestrel's protection off with the uninstall token. IT has been told.`),
    severity: on ? "low" : "high",
    alert_id: null,
    file: null,
    action_taken: on ? "Protection turned back on" : "Protection turned off",
    review: null,
  };
  items = [item, ...items];
  notifications.emit(item);
}

/** End a timed pause that has run out (the agent does this on a timer). */
function expirePause() {
  const p = status.pause;
  if (p?.until_ms != null && Date.now() >= p.until_ms) {
    status.pause = null;
    pauseNotice(true, p, "The chosen time ran out, so Kestrel turned protection back on.");
  }
}

function mockPause(token: string, mode: PauseMode, minutes: number | null): PauseResult {
  const now = Date.now();
  expirePause();
  const offer = status.local_pause!;
  if (offer.locked_until_ms !== null && offer.locked_until_ms > now) return fail("locked_out", { locked_until_ms: offer.locked_until_ms });
  if (!offer.enabled) return fail("not_allowed", { denied: "disabled" });
  if (status.pause) return fail("already_off", { state: status.pause });
  if (mode === "full" && !offer.allow_full) return fail("not_allowed", { denied: "mode_not_allowed" });
  if (minutes === null ? !offer.allow_until_resumed : !offer.minutes.includes(minutes)) return fail("not_allowed", { denied: "duration_not_allowed" });
  if (token.trim() !== MOCK_TOKEN) {
    pauseFailures++;
    if (pauseFailures >= 5) {
      pauseFailures = 0;
      const until = now + Math.min(60_000 * 2 ** Math.min(pauseLockouts, 6), 3_600_000);
      pauseLockouts++;
      status.local_pause = { ...offer, locked_until_ms: until };
      return fail("locked_out", { locked_until_ms: until });
    }
    return fail("wrong_token", { attempts_left: 5 - pauseFailures });
  }
  pauseFailures = 0;
  status.local_pause = { ...offer, locked_until_ms: null };
  const state: PauseState = { mode, since_ms: now, until_ms: minutes === null ? null : now + minutes * MIN, by_user: MOCK_USER };
  status.pause = state;
  pauseNotice(false, state);
  return { ok: true, error: null, message: "Protection is off.", attempts_left: null, locked_until_ms: null, denied: null, state };
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
const down = () => Promise.reject({ kind: "unavailable", message: "Kestrel service is not running" });

const pushAfter = Number(params.get("push") ?? "0");
if (pushAfter > 0) {
  setTimeout(() => {
    const item: ActivityItem = {
      id: id(900),
      ts: Date.now(),
      title: "Kestrel stopped invoice_0921.scr from reading your crypto wallet",
      body: "This file came from an email attachment and tried to open your Exodus wallet folder. Kestrel stopped it before anything was read.",
      severity: "critical",
      alert_id: id(901),
      file: "C:\\Users\\dewi.lestari\\Downloads\\invoice_0921.scr",
      action_taken: "Stopped and quarantined",
      review: null,
    };
    items = [item, ...items];
    notifications.emit(item);
  }, pushAfter * 1000);
}

// Like the agent: each start/end pushes a remote_session state change plus a
// regular high-severity notification (which is what raises the toast).
function remoteNotice(n: RemoteSessionNotice) {
  const item: ActivityItem = {
    id: id(800 + (Date.now() % 100)),
    ts: Date.now(),
    title: n.active
      ? n.kind === "files"
        ? `${n.admin_name} from IT is accessing files on this PC`
        : n.view_only
        ? `${n.admin_name} from IT started viewing your screen`
        : `${n.admin_name} from IT connected and can control your screen`
      : `${n.admin_name} from IT disconnected from your PC`,
    body: n.active ? `Reason: ${n.reason}. Contact IT if you weren't expecting this.` : "IT can no longer see your screen.",
    severity: "high",
    alert_id: null,
    file: null,
    action_taken: n.active ? "Remote session started" : "Remote session ended",
    review: null,
  };
  status.remote_session = n.active ? n : null;
  items = [item, ...items];
  remoteSessions.emit(n);
  notifications.emit(item);
}

if (remoteParam === "cycle") {
  let viewOnly = false;
  const cycle = () => {
    const n = sampleRemoteSession(viewOnly, Date.now());
    remoteNotice(n);
    setTimeout(() => {
      remoteNotice({ ...n, active: false, ended_at: Date.now() });
      viewOnly = !viewOnly;
      setTimeout(cycle, 15_000);
    }, 30_000);
  };
  setTimeout(cycle, 3_000);
}

export const mockApi: KestrelApi = {
  host: "mock",
  async getStatus() {
    await delay(120);
    if (unavailable) return down();
    expirePause();
    return { ...status };
  },
  async getActivity(limit = 50) {
    await delay(160);
    return unavailable ? down() : items.slice(0, limit);
  },
  async quickCheck(): Promise<Ack> {
    if (unavailable) return down();
    await delay(2600);
    status.last_check = Date.now();
    statuses.emit({ ...status });
    return { ok: true, message: "Checked 147 running apps. Nothing needs your attention." };
  },
  async requestReview(alertId, justification): Promise<Ack> {
    await delay(500);
    if (!justification.trim()) return Promise.reject({ kind: "agent", message: "justification is required" });
    const item = items.find((i) => i.alert_id === alertId);
    if (!item) return Promise.reject({ kind: "agent", message: "unknown alert" });
    const updated = { ...item, review: "requested" as const };
    items = items.map((i) => (i.id === item.id ? updated : i));
    setTimeout(() => notifications.emit(updated), 50);
    return { ok: true, message: "Your request was sent to IT." };
  },
  async openLink(url) {
    window.open(url, "_blank", "noopener,noreferrer");
  },
  // Mock: nothing to start; the UI shows a note instead.
  launchUninstaller: async () => {},
  getWindowMode: async () => mode,
  setWindowMode: async (m) => {
    mode = m;
  },
  hideWindow: async () => {},
  onNotification: notifications.on,
  onStatus: statuses.on,
  onRemoteSession: remoteSessions.on,
  onConsentRequest: consentRequests.on,
  async getPendingConsents() {
    pendingConsents = pendingConsents.filter((r) => r.expires_at > Date.now());
    return pendingConsents.slice();
  },
  async respondConsent(requestId, allow): Promise<Ack> {
    await delay(400);
    const req = pendingConsents.find((r) => r.request_id === requestId && r.expires_at > Date.now());
    pendingConsents = pendingConsents.filter((r) => r.request_id !== requestId);
    if (!req) return Promise.reject({ kind: "agent", message: "no pending request with that id (it may have expired)" });
    if (!allow) return { ok: true, message: "IT has been told you said no. They can't connect." };
    remoteNotice({ active: true, kind: req.kind, admin_name: req.admin_name, view_only: req.view_only, reason: req.reason, started_at: Date.now(), ended_at: null });
    statuses.emit({ ...status });
    return { ok: true, message: "IT can now connect. You'll see a banner while they're connected." };
  },
  async pauseProtection(token, mode, minutes) {
    if (unavailable) return down();
    await delay(300);
    if (pauseParam === "legacy") return legacyPause();
    const r = mockPause(token, mode, minutes);
    statuses.emit({ ...status });
    return r;
  },
  async resumeProtection() {
    if (unavailable) return down();
    await delay(300);
    if (pauseParam === "legacy") return legacyPause();
    const p = status.pause;
    if (!p) return fail("not_off");
    status.pause = null;
    pauseNotice(true, p);
    statuses.emit({ ...status });
    return { ok: true, error: null, message: "Protection is back on.", attempts_left: null, locked_until_ms: null, denied: null, state: null };
  },
  onConnection: () => Promise.resolve(() => {}),
  onNavigate: () => Promise.resolve(() => {}),
  onQuickCheck: () => Promise.resolve(() => {}),
};

export const mockInitialTab: Tab | null = (["status", "activity", "help"] as const).find((t) => t === params.get("tab")) ?? null;
export const mockTheme = params.get("theme");
