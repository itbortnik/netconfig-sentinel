import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { AnalysisResult, FeedbackSubmission } from "../../src/contracts";

const TOKEN = "browser-tests-service-token-32-characters-001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", { name: "Обратная связь по находке" });

async function connect(page: Page) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
}
async function analyze(
  page: Page,
  waitForHistory = true,
): Promise<AnalysisResult> {
  await page
    .getByLabel("Текст конфигурации")
    .fill(`hostname feedback-${test.info().project.name}-${Date.now()}\n`);
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const ready = page.getByRole("button", {
    name: "Анализировать снимок",
    exact: true,
  });
  await expect(ready).toBeVisible();
  const response = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" && item.url().endsWith("/analyze"),
  );
  // Capture the actual initial history read, not the pre-effect empty render.
  const history = waitForHistory
    ? page.waitForResponse(
        (item) =>
          item.request().method() === "GET" &&
          /\/api\/v1\/findings\/[^/]+\/feedback\?/.test(item.url()),
      )
    : null;
  await ready.click();
  const analysis = (await (await response).json()) as AnalysisResult;
  await expect(panel(page)).toBeVisible();
  if (history) {
    const initial = await history;
    expect(initial.status()).toBe(200);
    await initial.finished();
    await expect(
      panel(page).getByRole("button", {
        name: "Обновить историю оценок",
        exact: true,
      }),
    ).toBeEnabled();
  }
  return analysis;
}
const feedbackURL = (analysis: AnalysisResult, index = 0) =>
  `/api/v1/findings/${analysis.findings[index]!.finding_id}/feedback?analysis_id=${analysis.analysis_id}`;
async function submit(
  page: Page,
  comment: string,
  verdict = "confirmed_anomaly",
) {
  await page.getByLabel("Вердикт по находке").selectOption(verdict);
  await page.getByLabel("Комментарий к оценке").fill(comment);
  await page
    .getByRole("button", { name: "Сохранить оценку", exact: true })
    .click();
}
async function noOverflow(page: Page) {
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
}

test("assessments append, stay scoped across analyses, survive reconnect and do not change risk", async ({
  page,
}) => {
  test.setTimeout(60_000);
  await connect(page);
  const original = await analyze(page);
  const untrusted =
    '<img src=x onerror="window.feedbackExecuted=1">' + "x".repeat(1200);
  await submit(page, untrusted);
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(1);
  await expect(panel(page).locator(".feedback-comment")).toHaveText(untrusted);
  expect(await page.evaluate(() => "feedbackExecuted" in window)).toBe(false);
  await expect(panel(page).locator("img")).toHaveCount(0);
  const unicodeComment = "Reviewed: " + "🙂".repeat(1990);
  await submit(page, unicodeComment, "false_positive");
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(2);
  await expect(panel(page).locator(".feedback-comment").first()).toHaveText(
    unicodeComment,
  );
  const unchanged = await page.request.get(
    `/api/v1/analyses/${original.analysis_id}`,
    { headers },
  );
  expect(await unchanged.json()).toEqual(original);
  await noOverflow(page);
  if (test.info().project.name === "desktop") {
    for (const width of [1150, 1024, 800]) {
      await page.setViewportSize({ width, height: 720 });
      await noOverflow(page);
    }
  }
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(0);
  await expect(
    panel(page).getByText("На этой странице оценок нет."),
  ).toBeVisible();
  const response = await page.request.get(feedbackURL(original), { headers });
  expect((await response.json()).length).toBe(2);
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: original.analysis_id.slice(0, 8) })
    .click();
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(2);
  await expect(page.getByLabel("Комментарий к оценке")).toHaveValue("");
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
});

test("a lost save response can be retried with exactly the same ID without duplicating history", async ({
  page,
}) => {
  await connect(page);
  const analysis = await analyze(page);
  const requests: FeedbackSubmission[] = [];
  // Finish the initial read: a late initial history response can legitimately recover the write.
  await expect(
    panel(page).getByText("На этой странице оценок нет."),
  ).toBeVisible();
  await expect(
    panel(page).getByRole("button", {
      name: "Обновить историю оценок",
      exact: true,
    }),
  ).toBeEnabled();
  await page.route("**/api/v1/findings/*/feedback", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    requests.push(route.request().postDataJSON() as FeedbackSubmission);
    const response = await route.fetch();
    if (requests.length === 1) {
      expect(response.status()).toBe(201);
      await route.abort("connectionreset");
    } else {
      expect(response.status()).toBe(200);
      await route.fulfill({ response });
    }
  });
  await submit(page, "Review after a simulated response loss.");
  await expect(panel(page)).toContainText("Отправка не подтверждена");
  await page
    .getByRole("button", { name: "Сохранить оценку", exact: true })
    .click();
  await expect(panel(page)).toContainText("Оценка сохранена");
  expect(requests).toHaveLength(2);
  expect(requests[1]).toEqual(requests[0]);
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(1);
  const history = await page.request.get(feedbackURL(analysis), { headers });
  expect((await history.json()).length).toBe(1);
});

test("history recovery clears only the unchanged saved draft after an uncertain response", async ({
  page,
}) => {
  await connect(page);
  await analyze(page);
  await expect(
    panel(page).getByText("На этой странице оценок нет."),
  ).toBeVisible();
  await expect(
    panel(page).getByRole("button", {
      name: "Обновить историю оценок",
      exact: true,
    }),
  ).toBeEnabled();
  let posts = 0;
  await page.route("**/api/v1/findings/*/feedback", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    posts++;
    await route.fetch();
    await route.abort("connectionreset");
  });
  await submit(page, "Recover this confirmed assessment from history.");
  await expect(panel(page)).toContainText("Отправка не подтверждена");
  await page
    .getByRole("button", { name: "Обновить историю оценок", exact: true })
    .click();
  await expect(panel(page)).toContainText(
    "Отправленная оценка найдена в истории",
  );
  await expect(page.getByLabel("Комментарий к оценке")).toHaveValue("");
  await expect(
    page.getByRole("button", { name: "Сохранить оценку", exact: true }),
  ).toBeDisabled();
  expect(posts).toBe(1);
  await submit(page, "A second assessment saved with its response lost.");
  await expect(panel(page)).toContainText("Отправка не подтверждена");
  await page
    .getByLabel("Комментарий к оценке")
    .fill("New evidence not submitted yet.");
  await page.getByLabel("Вердикт по находке").selectOption("false_positive");
  await page
    .getByRole("button", { name: "Обновить историю оценок", exact: true })
    .click();
  await expect(panel(page)).toContainText(
    "Отправленная оценка найдена в истории",
  );
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(2);
  await expect(page.getByLabel("Комментарий к оценке")).toHaveValue(
    "New evidence not submitted yet.",
  );
  await expect(page.getByLabel("Вердикт по находке")).toHaveValue(
    "false_positive",
  );
  expect(posts).toBe(2);
});

test("switching finding drops drafts and ignores a delayed history response", async ({
  page,
}) => {
  await connect(page);
  let release: (() => void) | undefined;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  let first = true;
  let fetched!: () => void;
  let finished!: () => void;
  const firstFetched = new Promise<void>((resolve) => {
    fetched = resolve;
  });
  const firstFinished = new Promise<void>((resolve) => {
    finished = resolve;
  });
  await page.route("**/api/v1/findings/*/feedback?**", async (route) => {
    const delayed = first;
    first = false;
    const response = await route.fetch();
    if (delayed) {
      fetched();
      await hold;
    }
    await route.fulfill({ response });
    if (delayed) finished();
  });
  await analyze(page, false);
  await firstFetched;
  await page
    .getByLabel("Комментарий к оценке")
    .fill("Draft for the first finding only.");
  await page.locator(".finding-button").nth(1).click();
  await expect(page.getByLabel("Комментарий к оценке")).toHaveValue("");
  release!();
  await firstFinished;
  await expect(
    panel(page).getByText("На этой странице оценок нет."),
  ).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(
    panel(page).getByRole("button", {
      name: "Обновить историю оценок",
      exact: true,
    }),
  ).toBeEnabled();
  // The old finding's intercepted fetch has settled before removing any routes.
  await page.unrouteAll({ behavior: "wait" });
});

test("a valid record from another finding is rejected rather than shown as its history", async ({
  page,
}) => {
  await connect(page);
  const analysis = await analyze(page);
  await expect(
    panel(page).getByText("На этой странице оценок нет."),
  ).toBeVisible();
  await submit(page, "Assessment belongs only to the first finding.");
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(1);
  const history = await page.request.get(feedbackURL(analysis), { headers });
  const records = await history.json();
  await page.route("**/api/v1/findings/*/feedback?**", (route) =>
    route.fulfill({ json: records }),
  );
  await page.locator(".finding-button").nth(1).click();
  await expect(page.getByRole("alert")).toContainText(
    "не соответствует выбранной находке",
  );
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(0);
});

test("an altered save response is not accepted as confirmation and can be recovered from history", async ({
  page,
}) => {
  await connect(page);
  await analyze(page);
  await expect(
    panel(page).getByText("На этой странице оценок нет."),
  ).toBeVisible();
  await page.route("**/api/v1/findings/*/feedback", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch();
    const record = await response.json();
    await route.fulfill({
      json: { ...record, verdict: "false_positive" },
      status: 201,
    });
  });
  await submit(
    page,
    "The returned assessment must match the exact submitted intent.",
  );
  await expect(page.getByRole("alert")).toContainText(
    "не соответствует отправленной оценке",
  );
  await expect(panel(page)).toContainText("Отправка не подтверждена");
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(0);
  await page
    .getByRole("button", { name: "Обновить историю оценок", exact: true })
    .click();
  await expect(panel(page)).toContainText(
    "Отправленная оценка найдена в истории",
  );
  await expect(panel(page).locator(".feedback-history li")).toHaveCount(1);
  await expect(panel(page).locator(".feedback-history li strong")).toHaveText(
    "Аномалия подтверждена",
  );
});

test("logout during feedback save removes drafts and ignores the late response without rolling back the server", async ({
  page,
}) => {
  await connect(page);
  const analysis = await analyze(page);
  let release: (() => void) | undefined;
  let stored: (() => void) | undefined;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  const saved = new Promise<void>((resolve) => {
    stored = resolve;
  });
  await page.route("**/api/v1/findings/*/feedback", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    stored!();
    await hold;
    await route.fulfill({ response });
  });
  await submit(page, "Saved before the browser session ended.");
  await saved;
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  release!();
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await expect(panel(page)).toHaveCount(0);
  await expect(page.getByRole("alert")).toHaveCount(0);
  const history = await page.request.get(feedbackURL(analysis), { headers });
  expect((await history.json()).length).toBe(1);
});
