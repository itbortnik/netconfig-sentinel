import { expect, test } from "@playwright/test";
import type { Page, Route } from "@playwright/test";
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

const modelButton = (page: Page) =>
  page.getByRole("button", {
    name: "Запросить черновик у локальной модели",
    exact: true,
  });
const permission = (page: Page) =>
  page.getByLabel("Разрешаю передачу этого контекста локальной модели");
const modelDraft = (page: Page) =>
  panel(page).locator('[aria-label="Черновик объяснения модели"]');

async function configuredModel(page: Page) {
  await page.route("**/api/v1/explanation-capabilities", (route) =>
    route.fulfill({
      json: {
        version: "explanation-capabilities-0.1.0",
        local_model: "configured",
        model_health_checked: false,
        transport: "literal_loopback_only",
        explicit_request_permission_required: true,
      },
    }),
  );
}

// UI-only model fixture. Real local API supplies the bound saved explanation and sources;
// no real language model is configured or invoked by these browser tests.
async function syntheticModelBody(route: Route) {
  const requested = route.request().postDataJSON();
  expect(requested.provider).toBe("llm");
  expect(requested.allow_local_model_context).toBe(true);
  const response = await route.fetch({
    postData: {
      ...requested,
      provider: "local",
      allow_local_model_context: false,
    },
  });
  expect(response.ok()).toBe(true);
  const context = await response.json();
  return {
    ...context,
    version: "model-explanation-0.1.0",
    provider: "loopback_language_model",
    llm_status: "draft",
    privacy_version: "finding-context-redaction-0.1.0",
    context_sha256: "a".repeat(64),
    model_alias: "synthetic-browser-test",
    answer: {
      summary:
        '<img src=x onerror="window.modelExecuted=1"> [click](https://outside.invalid)',
      technical_explanation: "untrusted-model-text-" + "x".repeat(1200),
      possible_impact: ["Unverified hypothesis."],
      recommendation: "Review the approved policy, not this draft alone.",
      assumptions: [],
      missing_information: ["Operational context."],
      citations: [context.documents[0].citation],
      patch_draft: null,
      requires_human_review: true,
    },
  };
}

test("local model draft requires permission, stays plain text and leaves saved analysis unchanged", async ({
  page,
}) => {
  await configuredModel(page);
  let calls = 0;
  await page.route("**/api/v1/findings/*/explain", async (route) => {
    calls++;
    await route.fulfill({ json: await syntheticModelBody(route) });
  });
  const result = await analyze(page, true);
  await expect(modelButton(page)).toBeDisabled();
  await expect(permission(page)).not.toBeChecked();
  expect(calls).toBe(0);
  await permission(page).check();
  await modelButton(page).click();
  await expect(modelDraft(page)).toContainText(
    "Черновик модели — непроверенный текст",
  );
  await expect(modelDraft(page)).toContainText(
    '<img src=x onerror="window.modelExecuted=1">',
  );
  await expect(modelDraft(page).locator("img, a")).toHaveCount(0);
  expect(await page.evaluate(() => "modelExecuted" in window)).toBe(false);
  expect(calls).toBe(1);
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
  await page.locator(".finding-button").nth(1).click();
  await expect(permission(page)).not.toBeChecked();
  await expect(modelDraft(page)).toHaveCount(0);
  await expect(modelButton(page)).toBeDisabled();
});

test("unsafe model contracts and foreign binding are rejected without showing a draft", async ({
  page,
}) => {
  await configuredModel(page);
  let calls = 0;
  await page.route("**/api/v1/findings/*/explain", async (route) => {
    const body = await syntheticModelBody(route);
    switch (calls++) {
      case 0:
        body.answer.approved = true;
        break;
      case 1:
        body.answer.citations = ["unretrieved#section"];
        break;
      case 2:
        body.answer.requires_human_review = false;
        break;
      case 3:
        body.analysis_id = "00000000-0000-0000-0000-000000000001";
        break;
    }
    await route.fulfill({ json: body });
  });
  const result = await analyze(page);
  await permission(page).check();
  for (let index = 0; index < 4; index++) {
    await modelButton(page).click();
    await expect.poll(() => calls).toBe(index + 1);
    await expect(modelButton(page)).toBeEnabled();
    await expect(page.getByRole("alert")).toContainText(
      index === 3
        ? "не соответствуют выбранной находке"
        : "не соответствует поддерживаемому контракту",
    );
    await expect(modelDraft(page)).toHaveCount(0);
  }
  expect(
    await (
      await page.request.get(`/api/v1/analyses/${result.analysis_id}`, {
        headers,
      })
    ).json(),
  ).toEqual(result);
});

test("late model response is discarded on finding switch and logout", async ({
  page,
}) => {
  await configuredModel(page);
  let entered!: () => void;
  let release!: () => void;
  const waiting = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const paused = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/findings/*/explain", async (route) => {
    const body = await syntheticModelBody(route);
    entered();
    await paused;
    await route.fulfill({ json: body }).catch(() => undefined);
  });
  await analyze(page);
  await permission(page).check();
  await modelButton(page).click();
  await waiting;
  await page.locator(".finding-button").nth(1).click();
  await expect(permission(page)).not.toBeChecked();
  await expect(modelDraft(page)).toHaveCount(0);
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  release();
  await expect(panel(page)).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
});

test("default disabled adapter does not expose model request controls", async ({
  page,
}) => {
  await analyze(page);
  await expect(panel(page)).toContainText(
    "LLM недоступна без отдельной настройки сервера",
  );
  await expect(modelButton(page)).toHaveCount(0);
  await expect(permission(page)).toHaveCount(0);
});
