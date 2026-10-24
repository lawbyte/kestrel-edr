import { describe, expect, it } from "vitest";
import { parseUiIntent } from "./types";
import { mockApi } from "./mock";

describe("parseUiIntent (window rebuilt on demand)", () => {
  it("passes through a tab or a quick check", () => {
    expect(parseUiIntent({ tab: "help", quick_check: false })).toEqual({ tab: "help", quick_check: false });
    expect(parseUiIntent({ tab: null, quick_check: true })).toEqual({ tab: null, quick_check: true });
  });

  it("treats anything unexpected as nothing to do", () => {
    expect(parseUiIntent(null)).toEqual({ tab: null, quick_check: false });
    expect(parseUiIntent("help")).toEqual({ tab: null, quick_check: false });
    expect(parseUiIntent({ tab: "settings", quick_check: "yes" })).toEqual({ tab: null, quick_check: false });
  });

  it("the browser mock has nothing pending", async () => {
    await expect(mockApi.uiReady()).resolves.toEqual({ tab: null, quick_check: false });
  });
});
