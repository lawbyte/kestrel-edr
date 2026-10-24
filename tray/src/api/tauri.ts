import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { parseActivityItem, parseConsentRequest, parsePauseResult, parseRemoteSession, parseStatus, type ActivityItem, type TrayStatus } from "../protocol";
import { parseUiIntent, type Ack, type KestrelApi, type Tab, type WindowMode } from "./types";

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
  launchUninstaller: () => invoke("launch_uninstaller"),
  getWindowMode: () => invoke<WindowMode>("get_window_mode"),
  setWindowMode: (mode) => invoke("set_window_mode", { mode }),
  hideWindow: () => invoke("hide_window"),
  async uiReady() {
    return parseUiIntent(await invoke("ui_ready"));
  },
  onNotification: (cb) => listen<unknown>("kestrel://notification", (e) => cb(parseActivityItem(e.payload) as ActivityItem)),
  onStatus: (cb) => listen<unknown>("kestrel://status", (e) => cb(parseStatus(e.payload) as TrayStatus)),
  onRemoteSession: (cb) => listen<unknown>("kestrel://remote-session", (e) => cb(parseRemoteSession(e.payload))),
  onConsentRequest: (cb) => listen<unknown>("kestrel://consent-request", (e) => cb(parseConsentRequest(e.payload))),
  async getPendingConsents() {
    return (await invoke<unknown[]>("get_pending_consents")).map(parseConsentRequest);
  },
  respondConsent: (requestId, allow) => invoke<Ack>("respond_consent", { requestId, allow }),
  // The token goes straight to the backend; it is never logged or stored here.
  async pauseProtection(token, mode, minutes) {
    return parsePauseResult(await invoke("pause_protection", { token, mode, minutes }));
  },
  async resumeProtection() {
    return parsePauseResult(await invoke("resume_protection"));
  },
  onConnection: (cb) => listen<{ connected: boolean; reason: string | null }>("kestrel://connection", (e) => cb(e.payload)),
  onNavigate: (cb) => listen<Tab>("kestrel://navigate", (e) => cb(e.payload)),
  onQuickCheck: (cb) => listen("kestrel://quick-check", () => cb()),
};
