import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type {
  AnalysisResult,
  ConfigurationSnapshot,
} from "../../src/contracts";
import type { PatchDraft } from "../../src/patches";
import type {
  RunSourceDeterministicRecheck,
  SourceDeterministicComplete as SourceDeterministicRecheck,
} from "../../src/sourceDeterministicRecheck";

const TOKEN = "browser-tests-service-token-32-characters-001";
const READER = "browser-tests-reader-service-token-000001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", {
    name: "Перепроверка исходного анализа",
    exact: true,
  });
const patches = (page: Page) =>
  page.getByRole("region", { name: "Черновики изменений", exact: true });
const consent = (page: Page) =>
  panel(page).getByLabel(
    "Разрешаю отдельную локальную перепроверку исходного анализа на сохранённых исходниках",
    { exact: true },
  );
const launch = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Пересчитать исходный анализ до и после",
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
    .getByRole("button", { name: "Открыть перепроверку анализа", exact: true })
    .click();
}
async function select(page: Page, analysisId: string) {
  await panel(page)
    .getByLabel("UUID сохранённого анализа до изменения", { exact: true })
    .fill(analysisId);
  await panel(page)
    .getByRole("button", {
      name: "Загрузить исходный анализ политик и сравнений",
      exact: true,
    })
    .click();
  await expect(
    panel(page).getByLabel("Выбранный исходный анализ", { exact: true }),
  ).toBeVisible();
}
async function prepare(page: Page, fail = false) {
  const suffix = randomUUID().slice(0, 8);
  const inventory = {
    device_role: "edge",
    site_class: "branch",
    service_profile: "owned-control",
  };
  const content = (host: string, address: number, telnet = false) =>
    `hostname ${host}\naaa new-model\nip ssh version 2\nline vty 0 4\n transport input ${telnet ? "telnet ssh" : "ssh"}\n!\ninterface GigabitEthernet0/1\n ip address 192.0.2.${address} 255.255.255.0\n!\n`;
  async function upload(
    text: string,
    retained = false,
    device: string = randomUUID(),
  ) {
    const response = await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: device,
        filename: "source-deterministic.cfg",
        content: text,
        inventory,
        retain_original_source: retained,
      },
    });
    expect(response.status()).toBe(201);
    return (await response.json()) as ConfigurationSnapshot;
  }
  const peers: ConfigurationSnapshot[] = [];
  for (let n = 0; n < 3; n++)
    peers.push(await upload(content(`peer-${suffix}-${n}`, 20 + n)));
  const hostname = `source-deterministic-${fail ? "fail-" : ""}${suffix}`;
  const reference = await upload(content(hostname, 10));
  const before = await upload(
      content(hostname, 12, true),
      true,
      reference.device_id,
    ),
    after = await upload(content(hostname, 13), true, reference.device_id);
  const analyzed = await page.request.post(
    `/api/v1/configurations/${before.configuration_id}/analyze`,
    {
      headers,
      data: {
        reference_configuration_id: reference.configuration_id,
        peer_configuration_ids: peers.map((p) => p.configuration_id),
        comparison_version: "0.3.0",
      },
    },
  );
  expect(analyzed.status()).toBe(201);
  const analysis = (await analyzed.json()) as AnalysisResult;
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
  return { before, after, draft, analysis, reference };
}
async function run(page: Page) {
  await consent(page).check();
  const pending = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/api\/v2\/patches\/[^/]+\/deterministic-rechecks$/.test(response.url()),
  );
  await launch(page).click();
  const response = await pending;
  expect(response.status()).toBe(201);
  return (await response.json()) as SourceDeterministicRecheck;
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
test("actual original policy reference and peer context stays bound; reader history is read only", async ({
  page,
}) => {
  const { before, after, draft, analysis } = await prepare(page);
  const networks = await networkHistory(page, draft);
  await expect(launch(page)).toBeDisabled();
  const row = await run(page),
    report = row.outcome!.report!;
  expect(row.execution_status).toBe("completed");
  expect(row.intent.selection.original.comparison).toEqual(analysis.comparison);
  expect(report.before.policy_findings).toEqual(
    analysis.findings.filter((f) => f.detector === "policy_engine"),
  );
  expect(report.before.reference_findings).toEqual(
    analysis.findings.filter((f) => f.detector === "expected_configuration"),
  );
  expect(report.before.peer_findings).toEqual(
    analysis.findings.filter((f) => f.detector === "peer_baseline"),
  );
  expect(report.after.reference_findings).not.toBeNull();
  expect(JSON.stringify(report.after.reference_findings)).toContain(
    "192.0.2.10",
  );
  expect(JSON.stringify(report.after.reference_findings)).toContain(
    "192.0.2.13",
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
  const results = panel(page).getByRole("table", {
    name: "Результаты исходных политик и сравнений",
    exact: true,
  });
  await expect(results).toContainText(
    `Выполнено · замечаний: ${report.after.policy_findings.length}`,
  );
  await expect(panel(page)).toContainText(report.peer_profile_sha256!);
  await expect(panel(page)).toContainText(
    "Согласование исходного эталона и профиля не подтверждено",
  );
  await expect(panel(page)).not.toContainText(
    "Исходная статистическая модель не пересчитана",
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
      name: new RegExp(
        `Открыть перепроверку анализа ${row.recheck_id.slice(0, 8)}`,
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
test("changing or refreshing explicit selection clears consent and an unavailable selection cannot start", async ({
  page,
}) => {
  const { analysis } = await prepare(page);
  await consent(page).check();
  await panel(page)
    .getByRole("button", { name: "Обновить перепроверки анализа", exact: true })
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
      name: "Загрузить исходный анализ политик и сравнений",
      exact: true,
    })
    .click();
  await expect(consent(page)).toBeDisabled();
  await expect(
    panel(page).getByLabel("Выбранный исходный анализ", { exact: true }),
  ).toHaveCount(0);
});
test("lost successful POST is recovered by its immutable ID with no second POST", async ({
  page,
}) => {
  const { draft } = await prepare(page),
    requests: RunSourceDeterministicRecheck[] = [];
  await page.route(
    "**/api/v2/patches/*/deterministic-rechecks",
    async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      requests.push(
        route.request().postDataJSON() as RunSourceDeterministicRecheck,
      );
      const response = await route.fetch();
      expect(response.status()).toBe(201);
      await route.abort("connectionreset");
    },
  );
  await consent(page).check();
  await launch(page).click();
  await expect(panel(page)).toContainText(
    "Итог запроса перепроверки не подтверждён",
  );
  await expect(launch(page)).toBeDisabled();
  await panel(page)
    .getByRole("button", {
      name: "Прочитать попытку перепроверки",
      exact: true,
    })
    .click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Исходный анализ: отчёт сохранён (completed)",
      exact: true,
    }),
  ).toBeVisible();
  expect(requests).toHaveLength(1);
  const history = await (
    await page.request.get(
      `/api/v2/patches/${draft.patch_id}/deterministic-rechecks`,
      { headers },
    )
  ).json();
  expect(history).toHaveLength(1);
  expect(history[0].recheck_id).toBe(requests[0]!.recheck_id);
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новую перепроверку анализа",
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
  const requests: RunSourceDeterministicRecheck[] = [];
  let lost = false;
  await page.route(
    "**/api/v2/patches/*/deterministic-rechecks",
    async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      requests.push(
        route.request().postDataJSON() as RunSourceDeterministicRecheck,
      );
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
  await expect(panel(page)).toContainText(
    "Сервер отклонил запрос перепроверки",
  );
  const reset = panel(page).getByRole("button", {
    name: "Сбросить отклонённый запрос перепроверки",
    exact: true,
  });
  await expect(reset).toHaveCount(0);
  await panel(page)
    .getByRole("button", {
      name: "Прочитать попытку перепроверки",
      exact: true,
    })
    .click();
  await expect(reset).toBeEnabled();
  await reset.click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
  await run(page);
  expect(requests[0]!.recheck_id).not.toBe(requests[1]!.recheck_id);
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новую перепроверку анализа",
      exact: true,
    })
    .click();
  lost = true;
  await consent(page).check();
  await launch(page).click();
  await expect(panel(page)).toContainText(
    "Итог запроса перепроверки не подтверждён",
  );
  await panel(page)
    .getByRole("button", {
      name: "Прочитать попытку перепроверки",
      exact: true,
    })
    .click();
  await expect(reset).toHaveCount(0);
  await expect(launch(page)).toBeDisabled();
  expect(requests).toHaveLength(3);
});
test("controlled detector failure persists without fabricated findings and exact replay is read-only", async ({
  page,
}) => {
  const { draft } = await prepare(page, true),
    row = await run(page);
  expect(row.execution_status).toBe("failed");
  expect(row.outcome!.report).toBeNull();
  await expect(panel(page)).toContainText(
    "Принятых результатов нет; отсутствующие результаты не заменены нулями",
  );
  await expect(
    panel(page).getByRole("table", {
      name: "Результаты исходных политик и сравнений",
      exact: true,
    }),
  ).toHaveCount(0);
  const replay = await page.request.post(
    `/api/v2/patches/${draft.patch_id}/deterministic-rechecks`,
    { headers, data: row.intent.request },
  );
  expect(replay.status()).toBe(200);
  expect(await replay.json()).toEqual(row);
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новую перепроверку анализа",
      exact: true,
    })
    .click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
});
