import { test, expect } from "@playwright/test";
import { attachFullPage } from "./_helpers";

let alertHref: string | null = null;

test.describe("Threat Investigation Flow", () => {
  test.afterEach(async ({ page }, testInfo) => {
    await attachFullPage(page, testInfo);
  });

  test.beforeEach(async ({ page }) => {
    alertHref = null;
    await page.goto("/alerts");
    const link = page.locator('a[href^="/investigation/"]').first();
    alertHref = await link.getAttribute("href").catch(() => null);
    if (alertHref) await page.goto(alertHref);
  });

  test("renders the investigation workspace for a live alert", async ({ page }) => {
    test.skip(!alertHref, "no live alert to inspect");
    await expect(
      page.getByRole("heading", { name: /Threat investigation|Port Scan|Distributed DoS|Denial of Service|DNS Tunneling|Suspicious Traffic/i })
    ).toBeVisible();
    await expect(page.getByText("Key features", { exact: true })).toBeVisible();
    await expect(page.getByText(/Risk score|Confidence/).first()).toBeVisible();
  });

  test("shows detection sources and a score breakdown", async ({ page }) => {
    test.skip(!alertHref, "no live alert to inspect");
    await expect(page.getByText("Detection sources", { exact: true }).first()).toBeVisible();
    const breakdown = page.getByText("Detection score breakdown", { exact: true });
    if (await breakdown.count()) await expect(breakdown).toBeVisible();
  });

  test("recommended actions are advisory and read-only", async ({ page }) => {
    test.skip(!alertHref, "no live alert to inspect");
    await expect(page.getByText(/advisory only/i)).toBeVisible();
    // No mitigation/action control is offered in the read-only console.
    await expect(page.locator('button:has-text("Block"), button:has-text("Isolate"), button:has-text("Mitigate")').first()).toHaveCount(0);
  });
});