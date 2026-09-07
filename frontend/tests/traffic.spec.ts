import { test, expect } from "@playwright/test";
import { attachFullPage } from "./_helpers";

test.describe("Live Traffic Flows Page", () => {
  test.afterEach(async ({ page }, testInfo) => {
    await attachFullPage(page, testInfo);
  });

  test.beforeEach(async ({ page }) => {
    await page.goto("/traffic");
  });

  test("renders the page heading and a protocol filter", async ({ page }) => {
    await expect(
      page.getByRole("heading", { name: "Live Traffic Flows", exact: true })
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "All protocols", exact: true })
    ).toBeVisible();
  });

  test("shows an offline or empty or populated flow table", async ({ page }) => {
    const offline = page.getByText("Backend engine not reachable", { exact: false });
    const empty = page.getByText("No active flows", { exact: false });
    const proto = page.getByRole("button", { name: "All protocols", exact: true });
    await proto.waitFor({ state: "visible" });

    // populate / empty / offline states are all acceptable while live data streams
    const state = offline.or(empty).or(page.getByText("Source → Destination", { exact: false }));
    await state.first().waitFor({ state: "visible" });
  });

  test("flows table shows flag or periodicity columns when data exists", async ({ page }) => {
    const offline = page.getByText("Backend engine not reachable", { exact: false });
    const empty = page.getByText("No active flows", { exact: false });
    const period = page.getByText("Periodicity", { exact: true });
    const flags = page.getByText("TCP flags", { exact: true });
    await offline.or(empty).or(period).first().waitFor({ state: "visible" });

    if (!(await offline.isVisible()) && !(await empty.isVisible())) {
      await expect(flags).toBeVisible();
      await expect(period).toBeVisible();
    }
  });

  test("search input accepts a filter term", async ({ page }) => {
    const input = page.getByPlaceholder(/Filter by source/);
    await input.waitFor({ state: "visible" });

    // If live flows are present, a nonsense term collapses the table to an empty state.
    const flowRow = page.getByText("Source → Destination", { exact: false });
    if (await flowRow.isVisible().catch(() => false)) {
      await input.fill("filter-test-nonexistent");
      const noMatch = page.getByText(/No flows match the filter|No active flows/).first();
      await noMatch.waitFor({ state: "visible" });
    }
  });
});