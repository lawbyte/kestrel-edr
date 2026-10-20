import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import type { KestrelApi, Tab } from "./api/types";
import "./styles.css";

async function boot() {
  let api: KestrelApi;
  let initialTab: Tab | null = null;
  const root = document.documentElement;
  // The mock is only compiled into `--mode mock` builds; production never shows sample data.
  if (import.meta.env.MODE === "mock") {
    const mock = await import("./api/mock");
    api = mock.mockApi;
    initialTab = mock.mockInitialTab;
    if (mock.mockTheme === "light" || mock.mockTheme === "dark") root.dataset.theme = mock.mockTheme;
  } else {
    api = (await import("./api/tauri")).tauriApi;
    // Mica is applied by the backend on Windows 11 only; otherwise keep solid surfaces.
    const { invoke } = await import("@tauri-apps/api/core");
    if (await invoke<boolean>("mica_enabled").catch(() => false)) root.dataset.mica = "on";
  }
  root.dataset.host = api.host;

  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App api={api} initialTab={initialTab} />
    </StrictMode>,
  );
}

void boot();
