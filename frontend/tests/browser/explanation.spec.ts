import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { AnalysisResult } from "../../src/contracts";

const TOKEN = "browser-tests-service-token-32-characters-001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", { name: "Объяснение с источниками" });
async function analyze(page: Page, partial = false): Promise<AnalysisResult> {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await page
    .getByLabel("Текст конфигурации")
    .fill(
      `hostname source-${Date.now()}\n` +
        (partial ? "unsupported private text\n" : ""),
    );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const response = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" && item.url().endsWith("/analyze"),
  );
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  const result = (await (await response).json()) as AnalysisResult;
  await expect(panel(page)).toBeVisible();
  return result;
}
async function sources(page: Page) {
  await page
    .getByRole("button", { name: "Показать источники объяснения", exact: true })
    .click();
}

test("real local source sections preserve the saved analysis and display unavailable LLM honestly", async ({
  page,
}) => {
  const result = await analyze(page, true);
  await sources(page);
  await expect(panel(page).locator(".knowledge-source")).toHaveCount(1);
  await expect(panel(page)).toContainText("LLM недоступна");
  await panel(page).locator(".knowledge-source summary").click();
  await expect(panel(page).locator(".knowledge-content")).toContainText(
    "SSH must be explicitly enabled",
  );
  await expect(panel(page)).toContainText(
    "docs/policies/management-plane.md#ssh-must-be-enabled",
  );
  expect(
    await (
      await page.request.get(`/api/v1/analyses/${result.analysis_id}`, {
        headers,
      })
    ).json(),
  ).toEqual(result);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  await expect(panel(page)).toHaveCount(0);
});

test("invalid returned bindings or chunk hash cannot be shown as sources", async ({
  page,
}) => {
  const result = await analyze(page);
  let attempt = 0;
  await page.route("**/api/v1/findings/*/explain", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    if (++attempt === 1)
      body.analysis_id = "00000000-0000-0000-0000-000000000001";
    else
      body.documents[0].content = "forged contents without updating its hash";
    await route.fulfill({ response, json: body });
  });
  for (let i = 0; i < 2; i++) {
    await sources(page);
    await expect(page.getByRole("alert")).toContainText(
      "не соответствуют выбранной находке",
    );
    await expect(panel(page).locator(".knowledge-source")).toHaveCount(0);
    await expect(
      page.getByRole("button", {
        name: "Показать источники объяснения",
        exact: true,
      }),
    ).toBeEnabled();
  }
  expect(
    await (
      await page.request.get(`/api/v1/analyses/${result.analysis_id}`, {
        headers,
      })
    ).json(),
  ).toEqual(result);
});

test("retrieved Markdown and HTML are plain text, never active links or executable markup", async ({
  page,
}) => {
  await analyze(page);
  const untrusted =
    '<img src=x onerror="window.sourceExecuted=1"> [click](https://outside.invalid)';
  const hash = await page.evaluate(
    async (content) =>
      Array.from(
        new Uint8Array(
          await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(content),
          ),
        ),
        (byte) => byte.toString(16).padStart(2, "0"),
      ).join(""),
    untrusted,
  );
  await page.route("**/api/v1/findings/*/explain", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.documents[0].content = untrusted;
    body.documents[0].content_sha256 = hash;
    await route.fulfill({ response, json: body });
  });
  await sources(page);
  await expect(panel(page).locator(".knowledge-source")).toHaveCount(1);
  await panel(page).locator(".knowledge-source summary").click();
  await expect(panel(page).locator(".knowledge-content")).toHaveText(untrusted);
  await expect(panel(page).locator("img, a")).toHaveCount(0);
  expect(await page.evaluate(() => "sourceExecuted" in window)).toBe(false);
});

test("late explanation responses are ignored after switching finding and disconnecting", async ({
  page,
}) => {
  await analyze(page);
  let release!: () => void;
  let entered!: () => void;
  const waiting = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const paused = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/findings/*/explain", async (route) => {
    const response = await route.fetch();
    entered();
    await paused;
    await route.fulfill({ response }).catch(() => undefined);
  });
  await sources(page);
  await waiting;
  await page.locator(".finding-button").nth(1).click();
  await expect(panel(page).locator(".knowledge-source")).toHaveCount(0);
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  release();
  await expect(panel(page)).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
});
