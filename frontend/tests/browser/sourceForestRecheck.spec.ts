import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type {
  AnalysisResult,
  ConfigurationSnapshot,
} from "../../src/contracts";
import type { PatchDraft } from "../../src/patches";
import type {
  RunSourceForestRecheck,
  SourceForestRecheck,
} from "../../src/sourceForestRecheck";

const TOKEN = "browser-tests-service-token-32-characters-001";
const READER = "browser-tests-reader-service-token-000001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", { name: "Пересчёт исходного Forest", exact: true });
const patches = (page: Page) =>
  page.getByRole("region", { name: "Черновики изменений", exact: true });
const consent = (page: Page) =>
  panel(page).getByLabel(
    "Разрешаю отдельный локальный пересчёт исходного Forest на сохранённых исходниках",
    { exact: true },
  );
const launch = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Пересчитать исходный Forest до и после",
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
async function openDraft(
  page: Page,
  after: ConfigurationSnapshot,
  draft: PatchDraft,
) {
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
    .getByRole("button", { name: "Открыть пересчёт Forest", exact: true })
    .click();
}
async function select(page: Page, analysisId: string) {
  await panel(page)
    .getByLabel("UUID сохранённого анализа до изменения", { exact: true })
    .fill(analysisId);
  await panel(page)
    .getByRole("button", {
      name: "Загрузить исходный анализ Forest",
      exact: true,
    })
    .click();
  await expect(
    panel(page).getByLabel("Выбранный исходный Forest", { exact: true }),
  ).toBeVisible();
}
async function prepare(page: Page, fail = false) {
  const suffix = randomUUID().slice(0, 8);
  const inventory = {
    device_role: "edge",
    site_class: "branch",
    service_profile: "owned-control",
  };
  const content = (host: string, vlans: number) =>
    `hostname ${host}\naaa new-model\nip ssh version 2\n` +
    Array.from(
      { length: vlans },
      (_, n) => `vlan ${10 + n}\n name VLAN-${n}\n!\n`,
    ).join("");
  async function upload(
    text: string,
    retained = false,
    device: string = randomUUID(),
  ) {
    const response = await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: device,
        filename: "source-forest.cfg",
        content: text,
        inventory,
        retain_original_source: retained,
      },
    });
    expect(response.status()).toBe(201);
    return (await response.json()) as ConfigurationSnapshot;
  }
  // Eight authored independent training devices; numeric outputs below come from the actual registry Forest.
  const training: ConfigurationSnapshot[] = [];
  for (let n = 0; n < 8; n++)
    training.push(
      await upload(content(`owned-forest-training-${suffix}-${n}`, 1 + n)),
    );
  const trained = await page.request.post("/api/v1/models/isolation-forest", {
    headers,
    data: { configuration_ids: training.map((row) => row.configuration_id) },
  });
  expect(trained.status()).toBe(201);
  const model = await trained.json();
  const hostname = `source-forest-${fail ? "fail-" : ""}${suffix}`;
  const text = content(hostname, 12);
  const before = await upload(text, true),
    after = await upload(
      text + "ntp server 192.0.2.1\n",
      true,
      before.device_id,
    );
  const analyzed = await page.request.post(
    `/api/v1/configurations/${before.configuration_id}/analyze`,
    { headers, data: { statistical_model_id: model.model_id } },
  );
  expect(analyzed.status()).toBe(201);
  const analysis = (await analyzed.json()) as AnalysisResult;
  expect(analysis.statistical!.model.model_id).toBe(model.model_id);
  const saved = await page.request.post("/api/v1/patches", {
    headers,
    data: {
      patch_id: randomUUID(),
      before_configuration_id: before.configuration_id,
      after_configuration_id: after.configuration_id,
      before_source_sha256: before.canonical.source.sha256,
      after_source_sha256: after.canonical.source.sha256,
    },
  });
  expect(saved.status()).toBe(201);
  const draft = (await saved.json()) as PatchDraft;
  await connect(page);
  await openDraft(page, after, draft);
  await select(page, analysis.analysis_id);
  return { before, after, draft, analysis };
}
async function run(page: Page) {
  await consent(page).check();
  const pending = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/api\/v2\/patches\/[^/]+\/statistical-rechecks$/.test(response.url()),
  );
  await launch(page).click();
  const response = await pending;
  expect(response.status()).toBe(201);
  return (await response.json()) as SourceForestRecheck;
}
async function networkHistory(page: Page, draft: PatchDraft) {
  const result: unknown[] = [];
  for (const version of ["v1", "v2"])
    result.push(
      await (
        await page.request.get(
          `/api/${version}/patches/${draft.patch_id}/verifications`,
          { headers },
        )
      ).json(),
    );
  return result;
}
test("actual original numeric Forest stays bound to saved analysis and source pair; reader history does not execute it", async ({
  page,
}) => {
  const { before, after, draft, analysis } = await prepare(page);
  const networks = await networkHistory(page, draft);
  await expect(launch(page)).toBeDisabled();
  const row = await run(page),
    report = row.outcome!.report!;
  expect(row.execution_status).toBe("completed");
  expect(report.model).toEqual(analysis.statistical!.model);
  expect(report.scores.before_score_samples).toBe(
    analysis.statistical!.score_samples,
  );
  expect(report.scores.before_decision_function).toBe(
    analysis.statistical!.decision_function,
  );
  expect(report.scores.before_prediction).toBe(
    analysis.statistical!.prediction,
  );
  expect(row.intent.before.configuration_id).toBe(before.configuration_id);
  expect(row.intent.after.configuration_id).toBe(after.configuration_id);
  expect(row).toMatchObject({
    status: "needs_review",
    formal_verification: "not_run",
    risk_fused: false,
    calibrated: false,
    quality_proven: false,
    approved: false,
    applied: false,
  });
  for (const side of ["before", "after"] as const) {
    expect(report.scores[`${side}_decision_function`]).toBe(
      report.scores[`${side}_score_samples`] - report.model.decision_offset,
    );
    expect(report.scores[`${side}_prediction`]).toBe(
      report.scores[`${side}_decision_function`] < 0 ? -1 : 1,
    );
  }
  const numbers = panel(page).getByRole("table", {
    name: "Числовые результаты исходного Forest",
    exact: true,
  });
  await expect(numbers).toContainText(
    String(report.scores.before_score_samples),
  );
  await expect(numbers).toContainText(
    String(report.scores.after_decision_function),
  );
  await expect(panel(page)).toContainText(
    `offset_: ${report.model.decision_offset}`,
  );
  await expect(panel(page)).toContainText(
    "Все исходные детекторы не пересчитаны",
  );
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
  expect(
    await (
      await page.request.get(`/api/v1/analyses/${analysis.analysis_id}`, {
        headers,
      })
    ).json(),
  ).toEqual(analysis);
  await connect(page, READER);
  await openDraft(page, after, draft);
  await panel(page)
    .getByRole("button", {
      name: new RegExp(`Открыть пересчёт Forest ${row.recheck_id.slice(0, 8)}`),
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
test("changing or refreshing explicit selection clears consent and an unavailable selection cannot start", async ({
  page,
}) => {
  const { analysis } = await prepare(page);
  await consent(page).check();
  await panel(page)
    .getByRole("button", { name: "Обновить пересчёты Forest", exact: true })
    .click();
  await expect(consent(page)).not.toBeChecked();
  await expect(consent(page)).toBeDisabled();
  await select(page, analysis.analysis_id);
  await consent(page).check();
  await panel(page)
    .getByLabel("UUID сохранённого анализа до изменения", { exact: true })
    .fill(randomUUID());
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
  await panel(page)
    .getByRole("button", {
      name: "Загрузить исходный анализ Forest",
      exact: true,
    })
    .click();
  await expect(consent(page)).toBeDisabled();
  await expect(
    panel(page).getByLabel("Выбранный исходный Forest", { exact: true }),
  ).toHaveCount(0);
});
test("lost successful POST is recovered by its immutable ID with no second POST", async ({
  page,
}) => {
  const { draft } = await prepare(page),
    requests: RunSourceForestRecheck[] = [];
  await page.route(
    "**/api/v2/patches/*/statistical-rechecks",
    async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      requests.push(route.request().postDataJSON() as RunSourceForestRecheck);
      const response = await route.fetch();
      expect(response.status()).toBe(201);
      await route.abort("connectionreset");
    },
  );
  await consent(page).check();
  await launch(page).click();
  await expect(panel(page)).toContainText("Итог Forest-запроса не подтверждён");
  await expect(launch(page)).toBeDisabled();
  await panel(page)
    .getByRole("button", { name: "Прочитать Forest-попытку", exact: true })
    .click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Исходный Forest: отчёт сохранён (completed)",
      exact: true,
    }),
  ).toBeVisible();
  expect(requests).toHaveLength(1);
  const history = await (
    await page.request.get(
      `/api/v2/patches/${draft.patch_id}/statistical-rechecks`,
      { headers },
    )
  ).json();
  expect(history).toHaveLength(1);
  expect(history[0].recheck_id).toBe(requests[0]!.recheck_id);
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новый пересчёт Forest",
      exact: true,
    })
    .click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
});
test("known refusal plus GET404 permits explicit fresh request; lost plus GET404 remains frozen", async ({
  page,
}) => {
  await prepare(page);
  const requests: RunSourceForestRecheck[] = [];
  let lost = false;
  await page.route(
    "**/api/v2/patches/*/statistical-rechecks",
    async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      requests.push(route.request().postDataJSON() as RunSourceForestRecheck);
      if (lost) await route.abort("connectionreset");
      else if (requests.length === 1)
        await route.fulfill({
          status: 429,
          json: { detail: "Owned pre-reservation refusal" },
        });
      else await route.continue();
    },
  );
  await consent(page).check();
  await launch(page).click();
  await expect(panel(page)).toContainText("Сервер отклонил Forest-запрос");
  const reset = panel(page).getByRole("button", {
    name: "Сбросить отклонённый Forest-запрос",
    exact: true,
  });
  await expect(reset).toHaveCount(0);
  await panel(page)
    .getByRole("button", { name: "Прочитать Forest-попытку", exact: true })
    .click();
  await expect(reset).toBeEnabled();
  await reset.click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
  await run(page);
  expect(requests[0]!.recheck_id).not.toBe(requests[1]!.recheck_id);
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новый пересчёт Forest",
      exact: true,
    })
    .click();
  lost = true;
  await consent(page).check();
  await launch(page).click();
  await expect(panel(page)).toContainText("Итог Forest-запроса не подтверждён");
  await panel(page)
    .getByRole("button", { name: "Прочитать Forest-попытку", exact: true })
    .click();
  await expect(reset).toHaveCount(0);
  await expect(launch(page)).toBeDisabled();
  expect(requests).toHaveLength(3);
});
test("controlled numeric failure persists without fabricated scores and exact replay is read-only", async ({
  page,
}) => {
  const { draft } = await prepare(page, true),
    row = await run(page);
  expect(row.execution_status).toBe("failed");
  expect(row.outcome!.report).toBeNull();
  await expect(panel(page)).toContainText(
    "Принятых scores нет; отсутствующие результаты не заменены нулями",
  );
  await expect(
    panel(page).getByRole("table", {
      name: "Числовые результаты исходного Forest",
      exact: true,
    }),
  ).toHaveCount(0);
  const replay = await page.request.post(
    `/api/v2/patches/${draft.patch_id}/statistical-rechecks`,
    { headers, data: row.intent.request },
  );
  expect(replay.status()).toBe(200);
  expect(await replay.json()).toEqual(row);
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новый пересчёт Forest",
      exact: true,
    })
    .click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
});
