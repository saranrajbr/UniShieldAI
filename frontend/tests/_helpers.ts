import type { Page, TestInfo } from "@playwright/test";

export async function attachFullPage(page: Page, testInfo: TestInfo, title = "full-page") {
  await page.evaluate(() => {
    const main = document.querySelector("main") as HTMLElement | null;
    if (main) {
      main.style.height = "auto";
      main.style.overflow = "visible";
    }
  });
  const shot = await page.screenshot({ fullPage: true });
  await testInfo.attach(title, { body: shot, contentType: "image/png" });
}