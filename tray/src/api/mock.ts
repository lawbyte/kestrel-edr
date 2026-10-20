// Browser mock of the Tauri backend for `npm run dev:mock`.
//
// URL parameters (all optional):
//   ?state=protected|attention|isolated|degraded|offline|unavailable
//   ?tab=status|activity|help      initial tab
//   ?theme=light|dark              force a theme (default: follow the system)
//   ?empty=1                       no activity
//   ?push=<seconds>                push a demo notification after N seconds
//   ?notice=0                      org has no privacy notice
import type { ActivityItem, ProtectionState, TrayStatus } from "../protocol";
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

export const mockApi: KestrelApi = {
  host: "mock",
  async getStatus() {
    await delay(120);
    return unavailable ? down() : { ...status };
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
  getWindowMode: async () => mode,
  setWindowMode: async (m) => {
    mode = m;
  },
  hideWindow: async () => {},
  onNotification: notifications.on,
  onStatus: statuses.on,
  onConnection: () => Promise.resolve(() => {}),
  onNavigate: () => Promise.resolve(() => {}),
  onQuickCheck: () => Promise.resolve(() => {}),
};

export const mockInitialTab: Tab | null = (["status", "activity", "help"] as const).find((t) => t === params.get("tab")) ?? null;
export const mockTheme = params.get("theme");
