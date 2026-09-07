import { test, expect } from "@playwright/test";
import { attachFullPage } from "./_helpers";

test.describe("Security Alerts Page", () => {
  test.afterEach(async ({ page }, testInfo) => {
    await attachFullPage(page, testInfo);
  });

  test.beforeEach(async ({ page }) => {
    await page.goto("/alerts");
  });

  test("renders page header and search input", async ({ page }) => {
    await expect(
      page.getByRole("heading", { name: "Security Alerts", exact: true })
    ).toBeVisible();
    await expect(page.getByPlaceholder(/Search by IP, protocol, threat/)).toBeVisible();
  });

  test("shows status filter tabs", async ({ page }) => {
    for (const s of ["All", "New", "Investigating", "Resolved", "Ignored"]) {
      await expect(page.getByRole("button", { name: new RegExp(`^${s}\\d`), exact: false })).toBeVisible();
    }
  });

  test("severity and confidence rendering or a clear empty/offline state", async ({ page }) => {
    const row = page.locator('a[href^="/investigation/"]').first();
    const empty = page.getByText("No alerts yet", { exact: false });
    const offline = page.getByText("Backend engine not reachable", { exact: false });
    await row.or(empty).first().waitFor({ state: "visible" });

    if (await row.isVisible()) {
      await expect(row).toBeVisible();
      const sevBadge = page.locator("span").filter({ hasText: /^(Critical|High|Medium|Low)$/ }).first();
      const risk = row.getByText(/risk \d+%/);
      await risk.or(sevBadge).first().waitFor({ state: "visible" });
    } else {
      await empty.or(offline).first().waitFor({ state: "visible" });
    }
  });

  test("ignored tab is selectable without a write-back button", async ({ page }) => {
    await page.getByRole("button", { name: /^Ignored/ }).click();
    await expect(
      page.getByRole("button", { name: /^Ignored/ })
    ).toHaveClass(/bg-white/);
    // Read-only mandate: no resolve/mitigate actions are exposed on row cells.
    const row = page.locator('a[href^="/investigation/"]').first();
    if (await row.isVisible().catch(() => false)) {
      await expect(row.getByRole("button").filter({ hasText: /Resolve|Mitigate|Block|Isolate/ })).toHaveCount(0);
    }
  });
});