import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const TOKEN = "browser-tests-service-token-32-characters-001";
const READER = "browser-tests-reader-service-token-000001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const source =
  "hostname browser-owned\naaa new-model\nip ssh version 1\nline vty 0 4\n transport input ssh telnet\n!\nntp server 192.0.2.1\nlogging host 192.0.2.2\n";
const panel = (page: Page) =>
  page.getByRole("region", { name: "Модельное исправление", exact: true });
async function connect(page: Page, token = TOKEN) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
}
async function prepare(
  page: Page,
  retain = true,
  content = source,
  category = "management.ssh_version_1",
  deviceId?: string,
) {
  await connect(page);
  if (deviceId)
    await page.getByLabel("UUID устройства", { exact: true }).fill(deviceId);
  await page.getByLabel("Выбрать конфигурацию").setInputFiles({
    name: "model-owned.cfg",
    mimeType: "text/plain",
    buffer: Buffer.from(content),
  });
  if (retain)
    await page
      .getByLabel("Сохранить точный исходный текст в зашифрованной БД")
      .check();
  const uploaded = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v1/configurations") &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const snapshot = await (await uploaded).json();
  const analyzed = page.waitForResponse(
    (response) =>
      response.url().endsWith("/analyze") &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  const analysis = await (await analyzed).json();
  await page.locator(".finding-button").filter({ hasText: category }).click();
  await panel(page)
    .getByRole("button", { name: "Открыть модельные исправления", exact: true })
    .click();
  await expect(
    panel(page).getByText(
      "На этой странице нет черновиков выбранной находки.",
      { exact: true },
    ),
  ).toBeVisible();
  return { snapshot, analysis };
}
async function generate(page: Page) {
  const target = panel(page);
  await expect(
    target.getByRole("button", {
      name: "Создать модельное исправление",
      exact: true,
    }),
  ).toBeDisabled();
  await target
    .getByLabel("Разрешаю контекст этого исправления локальной модели", {
      exact: true,
    })
    .check();
  const created = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v1/model-patches") &&
      response.request().method() === "POST",
  );
  await target
    .getByRole("button", { name: "Создать модельное исправление", exact: true })
    .click();
  const response = await created;
  return response.ok()
    ? await response.json()
    : { http_status: response.status() };
}
async function verify(page: Page) {
  await panel(page)
    .getByLabel("Начальный узел области", { exact: true })
    .fill("browser-owned");
  await panel(page)
    .getByLabel("IPv4-сеть назначения", { exact: true })
    .fill("192.0.2.0/24");
  const checked = page.waitForResponse(
    (response) =>
      /\/model-patches\/[^/]+\/verify$/.test(response.url()) &&
      response.request().method() === "POST",
  );
  await panel(page)
    .getByRole("button", { name: "Сохранить проверку кандидата", exact: true })
    .click();
  return await (await checked).json();
}
async function cleanBrowser(page: Page) {
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
}

test("owned synthetic provider: real UI upload, source-bound draft, local review and append-only decisions", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const { analysis } = await prepare(page);
  const draft = await generate(page);
  expect(draft.status).toBe("draft");
  await expect(
    panel(page).getByText("Черновик: draft", { exact: true }),
  ).toBeVisible();
  await expect(
    panel(page).getByLabel(
      "Разрешаю контекст этого исправления локальной модели",
      { exact: true },
    ),
  ).not.toBeChecked();
  await expect(
    panel(page).getByLabel(
      "Разрешаю исходники выбранной сети локальному Batfish",
      { exact: true },
    ),
  ).toBeDisabled();
  await expect(
    panel(page).getByLabel(
      "Разрешаю повторную оценку кандидата локальной ML-моделью",
      { exact: true },
    ),
  ).toBeDisabled();
  const run = await verify(page);
  expect(run.execution_status).toBe("completed");
  expect(run.request.mode).toBe("local_preflight");
  expect(run.request.transformer_sha256).toBeNull();
  expect(run.network).toHaveLength(1);
  await expect(
    panel(page).getByText("Batfish не запускался.", { exact: true }),
  ).toBeVisible();
  await expect(
    panel(page).getByRole("option", {
      name: "Утвердить после независимых проверок",
    }),
  ).toHaveAttribute("disabled", "");
  await panel(page)
    .getByLabel("Комментарий к решению", { exact: true })
    .fill("Owned browser review: need independent device and network checks.");
  await panel(page)
    .getByRole("button", { name: "Записать решение инженера", exact: true })
    .click();
  await expect(
    panel(page).getByRole("list", { name: "Сохранённые решения инженера" }),
  ).toContainText("Нужны дополнительные сведения");
  await panel(page)
    .getByLabel("Решение о кандидате", { exact: true })
    .selectOption("rejected");
  await panel(page)
    .getByLabel("Комментарий к решению", { exact: true })
    .fill("Owned browser review: rejected without claiming formal approval.");
  await panel(page)
    .getByRole("button", { name: "Записать решение инженера", exact: true })
    .click();
  await expect(
    panel(page).getByRole("list", { name: "Сохранённые решения инженера" }),
  ).toContainText("Отклонено");
  await panel(page)
    .getByRole("button", { name: "Обновить историю решений", exact: true })
    .click();
  await expect(
    panel(page)
      .getByRole("list", { name: "Сохранённые решения инженера" })
      .locator("li"),
  ).toHaveCount(2);
  const unchanged = await (
    await page.request.get(`/api/v1/analyses/${analysis.analysis_id}`, {
      headers,
    })
  ).json();
  expect(unchanged).toEqual(analysis);
  const saved = await (
    await page.request.get(`/api/v1/model-patches/${draft.patch_id}`, {
      headers,
    })
  ).json();
  expect(saved).toEqual(draft);
  await cleanBrowser(page);
  expect(errors).toEqual([]);
});
test("a missing retained original is not reconstructed or promoted to a draft", async ({
  page,
}) => {
  await prepare(page, false);
  await generate(page);
  await expect(page.getByRole("alert")).toContainText("Конфликт");
  await expect(
    panel(page).getByRole("region", { name: "Сохранённый модельный черновик" }),
  ).toHaveCount(0);
  await expect(
    panel(page).getByText("Новый запуск заблокирован.", { exact: false }),
  ).toHaveCount(0);
  await cleanBrowser(page);
});
test("a synthetic JunOS null answer stays declined with no fabricated candidate or verification", async ({
  page,
}) => {
  await prepare(
    page,
    true,
    "set system host-name browser-junos\nset system services ssh protocol-version v1\n",
    "management.ssh_version_1",
  );
  const result = await generate(page);
  expect(result.status).toBe("declined");
  await expect(
    panel(page).getByText("Черновик: declined", { exact: true }),
  ).toBeVisible();
  await expect(
    panel(page).getByText(
      "Модель отказалась от создания патча; кандидат не подставлен.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    panel(page).getByRole("button", {
      name: "Сохранить проверку кандидата",
      exact: true,
    }),
  ).toHaveCount(0);
  await cleanBrowser(page);
});
test("tampered successful generation response is withheld and reconciled with GET, never retried", async ({
  page,
}) => {
  await prepare(page);
  let posts = 0;
  await page.route("**/api/v1/model-patches", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    posts++;
    const response = await route.fetch();
    const value = await response.json();
    await route.fulfill({
      response,
      json: { ...value, patch_id: "00000000-0000-0000-0000-000000000999" },
    });
  });
  await generate(page);
  await expect(
    panel(page).getByText(
      "Неопределённый или незавершённый итог. Новый запуск заблокирован.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    panel(page).getByRole("region", { name: "Сохранённый модельный черновик" }),
  ).toHaveCount(0);
  await panel(page)
    .getByRole("button", { name: "Прочитать сохранённую попытку", exact: true })
    .click();
  await expect(
    panel(page).getByText("Черновик: draft", { exact: true }),
  ).toBeVisible();
  expect(posts).toBe(1);
  await cleanBrowser(page);
});
test("a lost verification response preserves its identity and resolves from the durable HTTP record", async ({
  page,
}) => {
  await prepare(page);
  const draft = await generate(page);
  await expect(
    panel(page).getByText("Черновик: draft", { exact: true }),
  ).toBeVisible();
  let posts = 0,
    verificationId = "";
  await page.route("**/api/v1/model-patches/*/verify", async (route) => {
    posts++;
    verificationId = route.request().postDataJSON().verification_id;
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    await route.abort("failed");
  });
  await panel(page)
    .getByLabel("IPv4-сеть назначения", { exact: true })
    .fill("192.0.2.0/24");
  await panel(page)
    .getByRole("button", { name: "Сохранить проверку кандидата", exact: true })
    .click();
  await expect(
    panel(page).getByText(
      "Неопределённый или незавершённый итог. Новый запуск заблокирован.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    panel(page).getByRole("button", {
      name: "Сохранить проверку кандидата",
      exact: true,
    }),
  ).toBeDisabled();
  await panel(page)
    .getByRole("button", { name: "Прочитать сохранённую попытку", exact: true })
    .click();
  await expect(
    panel(page).getByRole("region", {
      name: "Отчёт проверки модельного кандидата",
    }),
  ).toContainText(verificationId);
  const rows = await (
    await page.request.get(
      `/api/v1/model-patches/${draft.patch_id}/verifications`,
      { headers },
    )
  ).json();
  expect(rows).toHaveLength(1);
  expect(posts).toBe(1);
});
test("changing findings resets unsent model consent and hides the old candidate", async ({
  page,
}) => {
  await prepare(page);
  await panel(page)
    .getByLabel("Разрешаю контекст этого исправления локальной модели", {
      exact: true,
    })
    .check();
  await page
    .locator(".finding-button")
    .filter({ hasText: "management.telnet_enabled" })
    .click();
  await panel(page)
    .getByRole("button", { name: "Открыть модельные исправления", exact: true })
    .click();
  await expect(
    panel(page).getByLabel(
      "Разрешаю контекст этого исправления локальной модели",
      { exact: true },
    ),
  ).not.toBeChecked();
  await generate(page);
  await expect(
    panel(page).getByText("Черновик: draft", { exact: true }),
  ).toBeVisible();
  await page
    .locator(".finding-button")
    .filter({ hasText: "management.ssh_version_1" })
    .click();
  await expect(
    panel(page).getByRole("region", { name: "Сохранённый модельный черновик" }),
  ).toHaveCount(0);
});
test("reader reconnect reads the persisted model proposal without generation or decision controls", async ({
  page,
}) => {
  const { analysis } = await prepare(page);
  const draft = await generate(page);
  await expect(
    panel(page).getByText("Черновик: draft", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  await connect(page, READER);
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: `Анализ ${analysis.analysis_id.slice(0, 8)}` })
    .click();
  await page
    .locator(".finding-button")
    .filter({ hasText: "management.ssh_version_1" })
    .click();
  await panel(page)
    .getByRole("button", { name: "Открыть модельные исправления", exact: true })
    .click();
  await panel(page)
    .getByRole("button", { name: new RegExp(draft.patch_id) })
    .click();
  await expect(
    panel(page).getByText("Черновик: draft", { exact: true }),
  ).toBeVisible();
  for (const name of [
    "Создать модельное исправление",
    "Сохранить проверку кандидата",
    "Записать решение инженера",
  ])
    await expect(
      panel(page).getByRole("button", { name, exact: true }),
    ).toHaveCount(0);
  await cleanBrowser(page);
});

test("only an explicitly selected older same-device baseline and bounded pre-generation network are sent", async ({
  page,
}) => {
  const deviceId = crypto.randomUUID();
  const baseline = await (
    await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: deviceId,
        filename: "owned-baseline.cfg",
        content: source.replace("version 1", "version 2"),
        retain_original_source: true,
      },
    })
  ).json();
  await prepare(page, true, source, "management.ssh_version_1", deviceId);
  await panel(page)
    .getByRole("button", {
      name: "Показать предыдущие снимки устройства",
      exact: true,
    })
    .click();
  await panel(page)
    .getByLabel("Эталон для генерации", { exact: true })
    .selectOption(baseline.configuration_id);
  const peerId = crypto.randomUUID();
  const peer = await (
    await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: peerId,
        filename: "owned-peer.cfg",
        content: "hostname peer-owned\n",
        retain_original_source: true,
      },
    })
  ).json();
  const secondPeer = await (
    await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: peerId,
        filename: "owned-peer-2.cfg",
        content: "hostname peer-owned\naaa new-model\n",
        retain_original_source: true,
      },
    })
  ).json();
  const draft = await generate(page);
  expect(draft.baseline.configuration_id).toBe(baseline.configuration_id);
  const future = await (
    await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: crypto.randomUUID(),
        filename: "owned-future.cfg",
        content: "hostname future-owned\n",
        retain_original_source: true,
      },
    })
  ).json();
  await panel(page)
    .getByRole("button", {
      name: "Показать снимки других устройств",
      exact: true,
    })
    .click();
  await panel(page).getByLabel(new RegExp(peer.configuration_id)).check();
  await expect(
    panel(page).getByLabel(new RegExp(secondPeer.configuration_id)),
  ).toBeDisabled();
  await expect(
    panel(page).getByLabel(new RegExp(future.configuration_id)),
  ).toHaveCount(0);
  const run = await verify(page);
  expect(run.request.network).toEqual([
    {
      configuration_id: draft.source.configuration_id,
      source_sha256: draft.source_sha256,
    },
    {
      configuration_id: peer.configuration_id,
      source_sha256: peer.canonical.source.sha256,
    },
  ]);
  await cleanBrowser(page);
});
test("a returned running record blocks decisions and resolves with read-only reconciliation", async ({
  page,
}) => {
  await prepare(page);
  await generate(page);
  await expect(
    panel(page).getByText("Черновик: draft", { exact: true }),
  ).toBeVisible();
  let posts = 0;
  await page.route("**/api/v1/model-patches/*/verify", async (route) => {
    posts++;
    const response = await route.fetch();
    const value = await response.json();
    // Only the returned projection is a synthetic pending fixture; the durable backend result is real local preflight.
    await route.fulfill({
      response,
      json: {
        ...value,
        completed_at: null,
        report: null,
        execution_status: "running",
        statistical_recheck: null,
        ml_execution: "not_requested",
        approval_blockers: ["verification_not_completed"],
      },
    });
  });
  await verify(page);
  await expect(
    panel(page).getByText(
      "Исполнение не завершено; результат не подтверждён.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    panel(page).getByRole("button", {
      name: "Записать решение инженера",
      exact: true,
    }),
  ).toHaveCount(0);
  await panel(page)
    .getByRole("button", { name: "Прочитать сохранённую попытку", exact: true })
    .click();
  await expect(
    panel(page).getByText("Отчёт сохранён; требуется решение инженера.", {
      exact: true,
    }),
  ).toBeVisible();
  expect(posts).toBe(1);
});
test("late successful generation for a previous finding is ignored without reusing consent", async ({
  page,
}) => {
  await prepare(page);
  let received = false,
    release: () => void = () => {};
  const barrier = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/model-patches", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    const response = await route.fetch();
    received = true;
    await barrier;
    await route.fulfill({ response });
  });
  await panel(page)
    .getByLabel("Разрешаю контекст этого исправления локальной модели", {
      exact: true,
    })
    .check();
  await panel(page)
    .getByRole("button", { name: "Создать модельное исправление", exact: true })
    .click();
  await expect.poll(() => received).toBe(true);
  await page
    .locator(".finding-button")
    .filter({ hasText: "management.telnet_enabled" })
    .click();
  release();
  await panel(page)
    .getByRole("button", { name: "Открыть модельные исправления", exact: true })
    .click();
  await expect(
    panel(page).getByText(
      "На этой странице нет черновиков выбранной находки.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    panel(page).getByRole("region", { name: "Сохранённый модельный черновик" }),
  ).toHaveCount(0);
  await expect(
    panel(page).getByLabel(
      "Разрешаю контекст этого исправления локальной модели",
      { exact: true },
    ),
  ).not.toBeChecked();
});
test("lost decision response reads the same append-only decision without a second POST", async ({
  page,
}) => {
  await prepare(page);
  const draft = await generate(page);
  await expect(
    panel(page).getByText("Черновик: draft", { exact: true }),
  ).toBeVisible();
  await verify(page);
  await expect(
    panel(page).getByText("Отчёт сохранён; требуется решение инженера.", {
      exact: true,
    }),
  ).toBeVisible();
  let posts = 0;
  await page.route("**/api/v1/model-patches/*/decisions", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    posts++;
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    await route.abort("failed");
  });
  await panel(page)
    .getByLabel("Комментарий к решению", { exact: true })
    .fill("Owned lost-response decision.");
  await panel(page)
    .getByRole("button", { name: "Записать решение инженера", exact: true })
    .click();
  await expect(
    panel(page).getByText(
      "Неопределённый или незавершённый итог. Новый запуск заблокирован.",
      { exact: true },
    ),
  ).toBeVisible();
  await panel(page)
    .getByRole("button", { name: "Прочитать сохранённую попытку", exact: true })
    .click();
  await expect(
    panel(page).getByRole("list", { name: "Сохранённые решения инженера" }),
  ).toContainText("Owned lost-response decision.");
  const saved = await (
    await page.request.get(
      `/api/v1/model-patches/${draft.patch_id}/decisions`,
      { headers },
    )
  ).json();
  expect(saved).toHaveLength(1);
  expect(posts).toBe(1);
});
