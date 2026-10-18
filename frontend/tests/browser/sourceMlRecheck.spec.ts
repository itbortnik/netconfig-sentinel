import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { ConfigurationSnapshot } from "../../src/contracts";
import type { PatchDraft } from "../../src/patches";
import type {
  RunSourceMlRecheck,
  SourceMlRecheck,
} from "../../src/sourceMlRecheck";

const TOKEN = "browser-tests-service-token-32-characters-001";
const READER = "browser-tests-reader-service-token-000001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", {
    name: "Парный ML-пересчёт исходников",
    exact: true,
  });
const patches = (page: Page) =>
  page.getByRole("region", { name: "Черновики изменений", exact: true });
const consent = (page: Page) =>
  panel(page).getByLabel(
    "Разрешаю отдельный парный локальный inference сохранённых исходников",
    { exact: true },
  );
const launch = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Пересчитать ML до и после",
    exact: true,
  });
async function connect(page: Page, token = TOKEN) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
}
async function upload(page: Page, content: string, device?: string) {
  if (device)
    await page.getByLabel("UUID устройства", { exact: true }).fill(device);
  await page.getByLabel("Выбрать конфигурацию").setInputFiles({
    name: "source-ml.cfg",
    mimeType: "text/plain",
    buffer: Buffer.from(content),
  });
  await page
    .getByLabel("Сохранить точный исходный текст в зашифрованной БД")
    .check();
  const pending = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/api/v1/configurations"),
  );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const received = await pending;
  expect(received.status()).toBe(201);
  await expect(
    page.getByRole("button", { name: "Выбрать для diff", exact: true }),
  ).toBeEnabled();
  return (await received.json()) as ConfigurationSnapshot;
}
async function prepare(page: Page, fail = false) {
  await connect(page);
  const hostname = `source-ml-${fail ? "fail-" : ""}${test.info().project.name}-${Date.now()}`;
  const before = await upload(page, `hostname ${hostname}\n`);
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  const after = await upload(
    page,
    `hostname ${hostname}\nntp server 192.0.2.1\n`,
    before.device_id,
  );
  await page
    .getByRole("button", { name: "Показать различия объектов", exact: true })
    .click();
  const pending = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/api/v1/patches"),
  );
  await patches(page)
    .getByRole("button", { name: "Сохранить черновик объектов", exact: true })
    .click();
  const draft = (await (await pending).json()) as PatchDraft;
  await panel(page)
    .getByRole("button", { name: "Открыть парный ML-пересчёт", exact: true })
    .click();
  await expect(panel(page)).toContainText(
    "Парная модель настроена оператором; её работоспособность этим не проверена",
  );
  return { before, after, draft };
}
async function run(page: Page) {
  await consent(page).check();
  const pending = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/api\/v2\/patches\/[^/]+\/ml-rechecks$/.test(response.url()),
  );
  await launch(page).click();
  const received = await pending;
  expect(received.status()).toBe(201);
  return (await received.json()) as SourceMlRecheck;
}
async function networkHistory(page: Page, draft: PatchDraft) {
  const v1 = await page.request.get(
    `/api/v1/patches/${draft.patch_id}/verifications`,
    { headers },
  );
  const v2 = await page.request.get(
    `/api/v2/patches/${draft.patch_id}/verifications`,
    { headers },
  );
  return { v1: await v1.json(), v2: await v2.json() };
}
test("paired numeric report is source-bound, keeps channels distinct and remains readable to a reader without changing network history", async ({
  page,
}) => {
  const { before, after, draft } = await prepare(page);
  const networks = await networkHistory(page, draft);
  await expect(launch(page)).toBeDisabled();
  const row = await run(page);
  expect(row).toMatchObject({
    status: "needs_review",
    formal_verification: "not_run",
    risk_fused: false,
    calibrated: false,
    quality_proven: false,
    approved: false,
    applied: false,
    model_sha256: "9".repeat(64),
  });
  expect(row.intent.before.configuration_id).toBe(before.configuration_id);
  expect(row.intent.after.configuration_id).toBe(after.configuration_id);
  const report = row.outcome!.report!;
  expect(row.execution_status).toBe("completed");
  expect(report).not.toBeNull();
  expect(report.before.model).toEqual(report.after.model);
  expect(report.before.runtime_torch_version).toBe(
    "owned-browser-pair-fixture",
  );
  expect(report.after.runtime_torch_version).toBe(
    report.before.runtime_torch_version,
  );
  expect(report.before.sanitization_version).toBe(
    report.after.sanitization_version,
  );
  for (const [card, member] of [
    [report.before, row.intent.before],
    [report.after, row.intent.after],
  ] as const) {
    expect(card.prediction.raw_source_sha256).toBe(member.source_sha256);
    expect(card.prediction.total_lines).toBe(member.total_lines);
    expect(card.prediction.severity_scores).toBeNull();
  }
  await expect(
    panel(page).getByRole("article", { name: "ML до изменения", exact: true }),
  ).toContainText("anomaly score: 0,800");
  await expect(
    panel(page).getByRole("article", {
      name: "ML после изменения",
      exact: true,
    }),
  ).toContainText("anomaly score: 0,200");
  await expect(panel(page)).toContainText("Категории: telnet_enabled:");
  await expect(panel(page)).toContainText("severity: отключена");
  await expect(panel(page)).toContainText(
    "Severity distribution: голова отключена",
  );
  await expect(panel(page)).toContainText("Качество доказано: нет");
  await expect(consent(page)).not.toBeChecked();
  expect(await networkHistory(page, draft)).toEqual(networks);
  for (const snapshot of [before, after])
    expect(
      await (
        await page.request.get(
          `/api/v1/configurations/${snapshot.configuration_id}`,
          { headers },
        )
      ).json(),
    ).toEqual(snapshot);
  await connect(page, READER);
  await page
    .locator(".history-item")
    .filter({ hasText: after.configuration_id.slice(0, 8) })
    .click();
  await patches(page)
    .getByRole("button", { name: "Обновить черновики", exact: true })
    .click();
  await patches(page)
    .getByRole("button", {
      name: new RegExp(`Открыть черновик ${draft.patch_id.slice(0, 8)}`),
    })
    .click();
  await panel(page)
    .getByRole("button", { name: "Открыть парный ML-пересчёт", exact: true })
    .click();
  await panel(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть парный ML-пересчёт ${row.recheck_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(panel(page)).toContainText(row.review_sha256);
  await expect(launch(page)).toHaveCount(0);
  await expect(consent(page)).toHaveCount(0);
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});
test("lost successful POST is read by the exact immutable ID with no second POST", async ({
  page,
}) => {
  const { draft } = await prepare(page);
  const requests: RunSourceMlRecheck[] = [];
  await page.route("**/api/v2/patches/*/ml-rechecks", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    requests.push(route.request().postDataJSON() as RunSourceMlRecheck);
    const received = await route.fetch();
    expect(received.status()).toBe(201);
    await route.abort("connectionreset");
  });
  await consent(page).check();
  await launch(page).click();
  await expect(panel(page)).toContainText("Итог ML-запроса не подтверждён");
  await expect(launch(page)).toBeDisabled();
  await panel(page)
    .getByRole("button", { name: "Прочитать парную ML-попытку", exact: true })
    .click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Парный ML: отчёт сохранён (completed)",
      exact: true,
    }),
  ).toBeVisible();
  expect(requests).toHaveLength(1);
  const history = await (
    await page.request.get(`/api/v2/patches/${draft.patch_id}/ml-rechecks`, {
      headers,
    })
  ).json();
  expect(history).toHaveLength(1);
  expect(history[0].recheck_id).toBe(requests[0]!.recheck_id);
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новый парный ML-пересчёт",
      exact: true,
    })
    .click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
});
test("known rejection plus actual GET404 permits explicit recovery with fresh consent and UUID", async ({
  page,
}) => {
  await prepare(page);
  const requests: RunSourceMlRecheck[] = [];
  await page.route("**/api/v2/patches/*/ml-rechecks", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    requests.push(route.request().postDataJSON() as RunSourceMlRecheck);
    if (requests.length === 1)
      await route.fulfill({
        status: 429,
        json: { detail: "Owned pre-reservation refusal" },
      });
    else await route.continue();
  });
  await consent(page).check();
  await launch(page).click();
  await expect(panel(page)).toContainText("Сервер отклонил ML-запрос");
  const reset = panel(page).getByRole("button", {
    name: "Сбросить отклонённый парный ML-запрос",
    exact: true,
  });
  await expect(reset).toHaveCount(0);
  await panel(page)
    .getByRole("button", { name: "Прочитать парную ML-попытку", exact: true })
    .click();
  await expect(reset).toBeEnabled();
  await reset.click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
  await run(page);
  expect(requests).toHaveLength(2);
  expect(requests[0]!.recheck_id).not.toBe(requests[1]!.recheck_id);
});
test("capability refresh clears consent, disabled inference blocks execution and unknown lost attempts stay frozen after GET404", async ({
  page,
}) => {
  await prepare(page);
  await consent(page).check();
  await panel(page)
    .getByRole("button", { name: "Обновить парные ML-пересчёты", exact: true })
    .click();
  await expect(consent(page)).not.toBeChecked();
  let disabled = true;
  await page.route("**/api/v2/patches/ml-capabilities", async (route) => {
    const response = await route.fetch();
    await route.fulfill({
      response,
      json: {
        ...(await response.json()),
        inference: disabled ? "disabled" : "configured",
        model_sha256: disabled ? null : "9".repeat(64),
      },
    });
  });
  await panel(page)
    .getByRole("button", { name: "Обновить парные ML-пересчёты", exact: true })
    .click();
  await expect(consent(page)).toBeDisabled();
  await expect(launch(page)).toBeDisabled();
  disabled = false;
  await panel(page)
    .getByRole("button", { name: "Обновить парные ML-пересчёты", exact: true })
    .click();
  await expect(consent(page)).toBeEnabled();
  let posts = 0;
  await page.route("**/api/v2/patches/*/ml-rechecks", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    posts++;
    await route.abort("connectionreset");
  });
  await consent(page).check();
  await launch(page).click();
  await panel(page)
    .getByRole("button", { name: "Прочитать парную ML-попытку", exact: true })
    .click();
  await expect(
    panel(page).getByRole("button", {
      name: "Сбросить отклонённый парный ML-запрос",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(launch(page)).toBeDisabled();
  expect(posts).toBe(1);
});
test("failed paired attempts remain durable without fabricated scores and can be replayed by the same ID", async ({
  page,
}) => {
  const { draft } = await prepare(page, true);
  const row = await run(page);
  expect(row.execution_status).toBe("failed");
  expect(row.outcome?.report).toBeNull();
  await expect(panel(page)).toContainText(
    "Принятых scores нет; отсутствующие результаты не заменены нулями",
  );
  await expect(
    panel(page).getByRole("article", { name: "ML до изменения", exact: true }),
  ).toHaveCount(0);
  const replay = await page.request.post(
    `/api/v2/patches/${draft.patch_id}/ml-rechecks`,
    { headers, data: row.intent.request },
  );
  expect(replay.status()).toBe(200);
  expect(await replay.json()).toEqual(row);
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новый парный ML-пересчёт",
      exact: true,
    })
    .click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
});
