import { test, expect } from "@playwright/test";
import { attachFullPage } from "./_helpers";

test.describe("Security Overview", () => {
  test.afterEach(async ({ page }, testInfo) => {
    await attachFullPage(page, testInfo);
  });

  test.beforeEach(async ({ page }) => {
    await page.goto("/");
  });

  test("page renders the Security Overview heading", async ({ page }) => {
    await expect(page).toHaveTitle(/UniShield AI/i);
    await expect(
      page.getByRole("heading", { name: "Security Overview", exact: true })
    ).toBeVisible();
  });

  test("KPI cards appear or a waiting state is shown", async ({ page }) => {
    const kpi = page.getByText("Ingest rate", { exact: true }).first();
    const empty = page.getByText(/Collecting trend samples|No detections yet|Waiting for the engine to respond/).first();
    await kpi.or(empty).waitFor({ state: "visible" });

    if (await kpi.isVisible()) {
      for (const label of [
        "Ingest rate",
        "Flows processed",
        "Active flows",
        "Alerts raised",
        "ML inferences",
        "Queue / errors",
      ]) {
        await expect(page.getByText(label, { exact: true }).first()).toBeVisible();
      }
    } else {
      await expect(empty).toBeVisible();
    }
  });

  test("trend, posture and recent detections panels render", async ({ page }) => {
    await expect(page.getByText("Ingest & detection trend", { exact: true })).toBeVisible();
    await expect(page.getByText("Threat posture", { exact: true })).toBeVisible();
    await expect(page.getByText("Recent detections", { exact: true })).toBeVisible();
  });

  test("live feed navigates to the investigation page", async ({ page }) => {
    const link = page.locator('a[href^="/investigation/"]').first();
    const noData = page.getByText("No detections yet", { exact: false });
    await link.or(noData).first().waitFor({ state: "visible" });

    let clicked = false;
    if (await link.isVisible().catch(() => false)) {
      await link.click();
      clicked = true;
    } else {
      // Empty state acceptable while backend has no alerts yet.
      await expect(noData).toBeVisible();
    }

    if (clicked) {
      await expect(
        page.getByRole("heading", { name: /Threat investigation|Port Scan|Distributed DoS|Suspicious Traffic|Denial of Service/i }).first()
      ).toBeVisible();
    }
  });
});