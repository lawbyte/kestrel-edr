import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { parseActivityItem, parseStatus, type ActivityItem, type TrayStatus } from "../protocol";
import type { Ack, KestrelApi, Tab, WindowMode } from "./types";

// Data from the backend is re-validated with the same parsers used for the
// protocol, so a malformed agent response surfaces as an error, not a crash.
export const tauriApi: KestrelApi = {
  host: "tauri",
  async getStatus() {
    return parseStatus(await invoke("get_status"));
  },
  async getActivity(limit = 50) {
    const items = await invoke<unknown[]>("get_activity", { limit });
    return items.map(parseActivityItem);
  },
  quickCheck: () => invoke<Ack>("quick_check"),
  requestReview: (alertId, justification) => invoke<Ack>("request_review", { alertId, justification }),
  openLink: (url) => invoke("open_link", { url }),
  getWindowMode: () => invoke<WindowMode>("get_window_mode"),
  setWindowMode: (mode) => invoke("set_window_mode", { mode }),
  hideWindow: () => invoke("hide_window"),
  onNotification: (cb) => listen<unknown>("kestrel://notification", (e) => cb(parseActivityItem(e.payload) as ActivityItem)),
  onStatus: (cb) => listen<unknown>("kestrel://status", (e) => cb(parseStatus(e.payload) as TrayStatus)),
  onConnection: (cb) => listen<{ connected: boolean; reason: string | null }>("kestrel://connection", (e) => cb(e.payload)),
  onNavigate: (cb) => listen<Tab>("kestrel://navigate", (e) => cb(e.payload)),
  onQuickCheck: (cb) => listen("kestrel://quick-check", () => cb()),
};
