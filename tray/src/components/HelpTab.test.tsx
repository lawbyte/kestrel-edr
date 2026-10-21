import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { HelpTab } from "./HelpTab";
import { mockApi } from "../api/mock";

const noop = () => {};

describe("HelpTab uninstall entry", () => {
  it("offers the uninstall tool to IT staff when the host can start it", () => {
    const html = renderToStaticMarkup(<HelpTab status={null} onLink={noop} onUninstall={async () => null} />);
    expect(html).toContain("Remove Kestrel");
    expect(html).toContain("uninstall token and administrator approval");
    expect(html).toContain(">Uninstall Kestrel...</button>");
  });

  it("hides the entry without a launcher", () => {
    const html = renderToStaticMarkup(<HelpTab status={null} onLink={noop} />);
    expect(html).not.toContain("Uninstall Kestrel...");
  });

  it("mock launcher starts nothing", async () => {
    await expect(mockApi.launchUninstaller()).resolves.toBeUndefined();
  });
});
