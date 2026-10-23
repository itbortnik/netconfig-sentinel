import { createHash, randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type {
  AnalysisResult,
  ConfigurationSnapshot,
} from "../../src/contracts";
import type { PatchDraft } from "../../src/patches";
import type { SourceDeterministicRecheck } from "../../src/sourceDeterministicRecheck";
import type { SourceForestRecheck } from "../../src/sourceForestRecheck";
import type { SourceMlRecheck } from "../../src/sourceMlRecheck";
import type { SourcePatchVerification } from "../../src/sourcePatchVerification";
import type {
  CreateSourceEvidenceReport,
  SourceEvidenceReport,
} from "../../src/sourceEvidenceReports";
import { stableJson } from "../../src/contracts";

const TOKEN = "browser-tests-service-token-32-characters-001";
const READER = "browser-tests-reader-service-token-000001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", {
    name: "Совместный отчёт по сохранённым результатам",
    exact: true,
  });
const patches = (page: Page) =>
  page.getByRole("region", { name: "Черновики изменений", exact: true });
const save = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Сохранить совместный отчёт",
    exact: true,
  });
const readAttempt = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Прочитать отчёт по ID запроса",
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
}
async function openPanel(page: Page) {
  await panel(page)
    .getByRole("button", { name: "Открыть совместный отчёт", exact: true })
    .click();
  await expect(panel(page).getByRole("status")).toBeHidden();
}
async function prepare(
  page: Page,
  networkError = false,
  all = false,
  legacyNetwork: boolean | "sdk" = false,
  direction?: string,
) {
  const suffix = randomUUID().slice(0, 8),
    device = randomUUID();
  const host = `${direction ? `source-direction-${direction}-` : `source-evidence-${networkError ? "error-" : ""}`}${suffix}`;
  const inventory = {
    device_role: "edge",
    site_class: "branch",
    service_profile: "owned-control",
  };
  const text = (name: string, vlans = 1, telnet = false) =>
    `hostname ${name}\naaa new-model\nip ssh version 2\nline vty 0 4\n transport input ${telnet ? "telnet ssh" : "ssh"}\n!\n` +
    Array.from(
      { length: vlans },
      (_, i) => `vlan ${10 + i}\n name VLAN-${i}\n!\n`,
    ).join("") +
    "interface GigabitEthernet0/1\n ip address 192.0.2.10 255.255.255.0\n!\n";
  async function upload(content: string, id = randomUUID(), retained = false) {
    const response = await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: id,
        filename: "source-evidence.cfg",
        content,
        inventory,
        retain_original_source: retained,
      },
    });
    expect(response.status()).toBe(201);
    return (await response.json()) as ConfigurationSnapshot;
  }
  let modelId: string | null = null;
  if (all) {
    // Small authored original Forest control, using the real registry implementation.
    // It establishes software execution only, never independent detector quality.
    const training: ConfigurationSnapshot[] = [];
    for (let n = 0; n < 8; n++)
      training.push(
        await upload(text(`owned-evidence-training-${suffix}-${n}`, n + 1)),
      );
    const trained = await page.request.post("/api/v1/models/isolation-forest", {
      headers,
      data: { configuration_ids: training.map((row) => row.configuration_id) },
    });
    expect(trained.status()).toBe(201);
    modelId = (await trained.json()).model_id;
  }
  const before = await upload(text(host, 10, true), device, true);
  const after = await upload(
    text(host, 10) + "ntp server 192.0.2.1\n",
    device,
    true,
  );
  const analyzed = await page.request.post(
    `/api/v1/configurations/${before.configuration_id}/analyze`,
    { headers, data: modelId ? { statistical_model_id: modelId } : {} },
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
  const prefix = `/api/v2/patches/${draft.patch_id}`;
  const selectionResponse = await page.request.get(
    `${prefix}/deterministic-selection/${analysis.analysis_id}`,
    { headers },
  );
  expect(selectionResponse.status()).toBe(200);
  const selection = await selectionResponse.json();
  const detResponse = await page.request.post(
    `${prefix}/deterministic-rechecks`,
    {
      headers,
      data: {
        version: "source-deterministic-request-0.1.0",
        recheck_id: randomUUID(),
        draft_sha256: draft.draft_sha256,
        before_analysis_id: analysis.analysis_id,
        before_analysis_sha256: selection.before_analysis_sha256,
        reference_canonical_sha256: null,
        allow_local_analysis_context: true,
      },
    },
  );
  expect(detResponse.status()).toBe(201);
  const deterministic =
    (await detResponse.json()) as SourceDeterministicRecheck;
  let forest: SourceForestRecheck | null = null,
    neural: SourceMlRecheck | null = null,
    network: SourcePatchVerification | null = null;
  if (all) {
    const selectedResponse = await page.request.get(
      `${prefix}/statistical-selection/${analysis.analysis_id}`,
      { headers },
    );
    expect(selectedResponse.status()).toBe(200);
    const selected = await selectedResponse.json();
    const response = await page.request.post(`${prefix}/statistical-rechecks`, {
      headers,
      data: {
        version: "source-forest-request-0.1.0",
        recheck_id: randomUUID(),
        draft_sha256: draft.draft_sha256,
        before_analysis_id: analysis.analysis_id,
        before_analysis_sha256: selected.before_analysis_sha256,
        model_id: modelId,
        artifact_sha256: selected.original.model.artifact_sha256,
        allow_local_model_context: true,
      },
    });
    expect(response.status()).toBe(201);
    forest = (await response.json()) as SourceForestRecheck;
    const mlResponse = await page.request.post(`${prefix}/ml-rechecks`, {
      headers,
      data: {
        version: "source-ml-request-0.1.0",
        recheck_id: randomUUID(),
        draft_sha256: draft.draft_sha256,
        model_sha256: "9".repeat(64),
        allow_local_model_context: true,
      },
    });
    expect(mlResponse.status()).toBe(201);
    neural = (await mlResponse.json()) as SourceMlRecheck;
  }
  if (all || networkError || direction) {
    const response = await page.request.post(`${prefix}/verify`, {
      headers,
      data: {
        version:
          legacyNetwork === "sdk"
            ? "source-patch-request-0.2.0"
            : legacyNetwork
              ? "source-patch-request-0.1.0"
              : "source-patch-request-0.3.0",
        verification_id: randomUUID(),
        draft_sha256: draft.draft_sha256,
        companions: [],
        scope: { start_node: host, destination: "192.0.2.0/24" },
        allow_local_engine_upload: true,
      },
    });
    expect(response.status()).toBe(201);
    network = (await response.json()) as SourcePatchVerification;
  }
  await connect(page);
  await openDraft(page, after, draft);
  return {
    before,
    after,
    draft,
    analysis,
    deterministic,
    forest,
    neural,
    network,
    prefix,
  };
}
async function choose(page: Page, value: Awaited<ReturnType<typeof prepare>>) {
  await panel(page)
    .getByLabel("Исходные политики и сравнения", { exact: true })
    .selectOption(value.deterministic.recheck_id);
  if (value.forest)
    await panel(page)
      .getByLabel("Исходный Forest", { exact: true })
      .selectOption(value.forest.recheck_id);
  if (value.neural)
    await panel(page)
      .getByLabel("Нейросетевая модель", { exact: true })
      .selectOption(value.neural.recheck_id);
  if (value.network)
    await panel(page)
      .getByLabel("Сетевая проверка", { exact: true })
      .selectOption(value.network.verification_id);
}
async function compose(page: Page) {
  const pending = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/evidence-reports$/.test(response.url()),
  );
  await save(page).click();
  const response = await pending;
  expect(response.status()).toBe(201);
  const report = (await response.json()) as SourceEvidenceReport;
  await expect(
    panel(page).getByRole("heading", {
      name: "Совместный отчёт сохранён — требуется рассмотрение",
      exact: true,
    }),
  ).toBeVisible();
  return report;
}
test("closed panel does not fetch; actual saved deterministic/Forest and synthetic neural/network compose without promotion; reader is read only", async ({
  page,
}) => {
  const loaded: string[] = [];
  page.on("request", (request) => {
    if (
      /\/api\/v2\/patches\/.*\/(?:evidence-reports|deterministic-rechecks|statistical-rechecks|ml-rechecks|verifications)\?/.test(
        request.url(),
      )
    )
      loaded.push(request.url());
  });
  const value = await prepare(page, false, true);
  expect(loaded).toEqual([]);
  await openPanel(page);
  expect(loaded).toHaveLength(5);
  await expect(save(page)).toBeDisabled();
  await expect(panel(page).getByRole("checkbox")).toHaveCount(0);
  await choose(page, value);
  const report = await compose(page);
  expect(report.version).toBe("source-evidence-report-0.3.0");
  expect(report.request.version).toBe("source-evidence-request-0.3.0");
  expect(report).toMatchObject({
    status: "needs_review",
    formal_qualification: "not_proven",
    risk_fused: false,
    calibrated: false,
    quality_proven: false,
    approved: false,
    applied: false,
  });
  expect(report.network!.ml_status).toBe("not_run");
  expect(report.network).toMatchObject({
    version: "source-patch-verification-0.3.0",
    execution_version: "batfish-execution-0.3.0",
    sdk_version: "owned-browser-sdk-0.36.0",
    sdk_observation: "observed",
  });
  expect(report.forest!.scores).toEqual(value.forest!.outcome!.report!.scores);
  await expect(
    panel(page).getByRole("table", { name: "Forest в совместном отчёте" }),
  ).toContainText(String(report.forest!.scores.after_score_samples));
  await expect(
    panel(page).getByRole("table", { name: "Нейросеть в совместном отчёте" }),
  ).toContainText("0.8");
  await expect(panel(page)).toContainText(
    "Собственный ML-статус сетевой записи: not_run",
  );
  await expect(panel(page)).toContainText("SDK: owned-browser-sdk-0.36.0");
  const storedBefore = await (
    await page.request.get(
      `${value.prefix}/deterministic-rechecks/${value.deterministic.recheck_id}`,
      { headers },
    )
  ).json();
  expect(storedBefore).toEqual(value.deterministic);
  await connect(page, READER);
  await openDraft(page, value.after, value.draft);
  await openPanel(page);
  await expect(save(page)).toHaveCount(0);
  await panel(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть совместный отчёт ${report.report_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(panel(page)).toContainText(report.review_sha256);
  expect(
    (
      await page.request.post(`${value.prefix}/evidence-reports`, {
        headers: { Authorization: `Bearer ${READER}` },
        data: { ...report.request, report_id: randomUUID() },
      })
    ).status(),
  ).toBe(403);
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
test("network error is saved as actual evidence and absent model remains absent", async ({
  page,
}) => {
  const value = await prepare(page, true);
  await openPanel(page);
  await choose(page, value);
  const report = await compose(page);
  expect(report.network!.result.status).toBe("error");
  expect(report.network).toMatchObject({
    sdk_version: "owned-browser-sdk-0.36.0",
    sdk_observation: "observed",
  });
  expect(report.neural).toBeNull();
  expect(report.forest).toBeNull();
  await expect(panel(page)).toContainText("Ошибка сетевой проверки (error)");
  await expect(panel(page)).not.toContainText("Сетевой результат отсутствует");
  await expect(panel(page)).toContainText("Нейросетевой результат не выбран");
  expect(report.validation_blockers).toContain("formal_scope_not_passed");
});

test("directional report retains legacy child metadata without inventing an observation", async ({
  page,
}) => {
  const value = await prepare(page, true, false, true);
  const original = JSON.stringify(value.network);
  await openPanel(page);
  await choose(page, value);
  const report = await compose(page);
  expect(report.version).toBe("source-evidence-report-0.3.0");
  expect(report.network).toMatchObject({
    version: "source-patch-verification-0.1.0",
    sdk_version: null,
  });
  expect(report.network).not.toHaveProperty("sdk_observation");
  expect(report.network).not.toHaveProperty("execution_version");
  await expect(panel(page)).toContainText(
    "SDK: недоступно — исходная запись не сохраняла версию",
  );
  const reread = await page.request.get(
    `${value.prefix}/verifications/${value.network!.verification_id}`,
    { headers },
  );
  expect(JSON.stringify(await reread.json())).toBe(original);
});
test("directional report retains exact historical SDK child without inventing directional witnesses", async ({
  page,
}) => {
  const value = await prepare(page, true, false, "sdk");
  await openPanel(page);
  await choose(page, value);
  const report = await compose(page);
  expect(report.version).toBe("source-evidence-report-0.3.0");
  expect(report.network).toMatchObject({
    version: "source-patch-verification-0.2.0",
    execution_version: "batfish-execution-0.2.0",
    sdk_observation: "observed",
  });
  expect(report.network).not.toHaveProperty("reachability_impact");
  await expect(panel(page)).toContainText(
    "Направление изменения в исходной записи не сохранялось",
  );
  const reread = await page.request.get(
    `${value.prefix}/verifications/${value.network!.verification_id}`,
    { headers },
  );
  expect(await reread.json()).toEqual(value.network);
});

test("resealed false SDK projection cannot replace metadata from the exact immutable child", async ({
  page,
}) => {
  const value = await prepare(page, true);
  await openPanel(page);
  await choose(page, value);
  await page.route("**/api/v2/patches/*/evidence-reports", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch(),
      changed = (await response.json()) as SourceEvidenceReport;
    changed.network!.sdk_version = "fabricated-browser-sdk";
    const { review_json: _json, review_sha256: _sha, ...body } = changed;
    changed.review_json = stableJson(body);
    changed.review_sha256 = createHash("sha256")
      .update(changed.review_json)
      .digest("hex");
    await route.fulfill({ response, json: changed });
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения совместного отчёта не подтверждён",
  );
  await expect(panel(page)).not.toContainText("fabricated-browser-sdk");
  await readAttempt(page).click();
  await expect(panel(page)).toContainText("SDK: owned-browser-sdk-0.36.0");
});

test("full selected directional child is refetched and a resealed opposite direction cannot replace it", async ({
  page,
}) => {
  const value = await prepare(page, false, false, false, "loss");
  let childGets = 0;
  page.on("request", (request) => {
    if (
      request.method() === "GET" &&
      request.url().endsWith(`/verifications/${value.network!.verification_id}`)
    )
      childGets++;
  });
  await openPanel(page);
  await choose(page, value);
  await page.route("**/api/v2/patches/*/evidence-reports", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch(),
      changed = (await response.json()) as SourceEvidenceReport;
    if (changed.network?.version !== "source-patch-verification-0.3.0")
      throw new Error("Expected directional child projection");
    const impact = changed.network.reachability_impact;
    impact.direction = "gain_found";
    impact.lost_witness_count = 0;
    impact.gained_witness_count = 1;
    for (const witness of impact.witnesses) {
      [witness.before_dispositions, witness.after_dispositions] = [
        witness.after_dispositions,
        witness.before_dispositions,
      ];
      [witness.before_trace_count, witness.after_trace_count] = [
        witness.after_trace_count,
        witness.before_trace_count,
      ];
      witness.direction = "gain";
    }
    const { review_json: _json, review_sha256: _sha, ...body } = changed;
    changed.review_json = stableJson(body);
    changed.review_sha256 = createHash("sha256")
      .update(changed.review_json)
      .digest("hex");
    await route.fulfill({ response, json: changed });
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения совместного отчёта не подтверждён",
  );
  await expect.poll(() => childGets).toBeGreaterThan(0);
  await expect(readAttempt(page)).toBeEnabled();
  await expect(
    panel(page).getByRole("region", {
      name: "Направление примеров достижимости",
      exact: true,
    }),
  ).toHaveCount(0);
  await readAttempt(page).click();
  const directionView = panel(page).getByRole("region", {
    name: "Направление примеров достижимости",
    exact: true,
  });
  await expect(directionView).toContainText(
    "Наблюдены примеры потери успешной доставки",
  );
  await expect(directionView).toContainText("Примеров потери: 1; появления: 0");
  await expect(panel(page)).toContainText("not_proven");
});

test("authored mixed directional report keeps both witnesses when reachable example totals are equal", async ({
  page,
}) => {
  const value = await prepare(page, false, false, false, "both");
  await openPanel(page);
  await choose(page, value);
  const report = await compose(page);
  if (report.network?.version !== "source-patch-verification-0.3.0")
    throw new Error("Expected directional child");
  expect(report.network.result.before_reachable_count).toBe(
    report.network.result.after_reachable_count,
  );
  expect(report.network.reachability_impact).toMatchObject({
    direction: "loss_and_gain_found",
    lost_witness_count: 1,
    gained_witness_count: 1,
  });
  await expect(
    panel(page).getByRole("region", {
      name: "Направление примеров достижимости",
      exact: true,
    }),
  ).toContainText("Наблюдены примеры потери и появления успешной доставки");
  expect(report.formal_qualification).toBe("not_proven");
  expect(report.risk_fused).toBe(false);
  expect(report.approved).toBe(false);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});
test("lost POST is frozen and recovered by exact GET with no second POST", async ({
  page,
}) => {
  const value = await prepare(page),
    requests: CreateSourceEvidenceReport[] = [];
  await openPanel(page);
  await choose(page, value);
  await page.route("**/api/v2/patches/*/evidence-reports", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    requests.push(route.request().postDataJSON());
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    await route.abort("connectionreset");
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения совместного отчёта не подтверждён",
  );
  await expect(save(page)).toBeDisabled();
  await expect(
    panel(page).getByLabel("Исходные политики и сравнения", { exact: true }),
  ).toBeDisabled();
  await readAttempt(page).click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Совместный отчёт сохранён — требуется рассмотрение",
      exact: true,
    }),
  ).toBeVisible();
  expect(requests).toHaveLength(1);
  const rows = await (
    await page.request.get(`${value.prefix}/evidence-reports`, { headers })
  ).json();
  expect(rows).toHaveLength(1);
  expect(rows[0].report_id).toBe(requests[0]!.report_id);
});
test("known refusal with GET404 can reset; lost response with GET404 stays frozen", async ({
  page,
}) => {
  const value = await prepare(page),
    requests: CreateSourceEvidenceReport[] = [];
  let lost = false;
  await openPanel(page);
  await choose(page, value);
  await page.route("**/api/v2/patches/*/evidence-reports", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    requests.push(route.request().postDataJSON());
    if (lost) await route.abort("connectionreset");
    else
      await route.fulfill({
        status: 409,
        json: { detail: "Owned refusal before any storage" },
      });
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Сервер отклонил запрос совместного отчёта",
  );
  const reset = panel(page).getByRole("button", {
    name: "Сбросить отклонённый запрос отчёта",
    exact: true,
  });
  await expect(reset).toHaveCount(0);
  await readAttempt(page).click();
  await expect(reset).toBeEnabled();
  await reset.click();
  await expect(save(page)).toBeDisabled();
  await choose(page, value);
  lost = true;
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения совместного отчёта не подтверждён",
  );
  await readAttempt(page).click();
  await expect(reset).toHaveCount(0);
  await expect(save(page)).toBeDisabled();
  expect(requests).toHaveLength(2);
  expect(requests[0]!.report_id).not.toBe(requests[1]!.report_id);
});
test("resealed changed compact projection is rejected against valid unchanged saved child proofs", async ({
  page,
}) => {
  const value = await prepare(page);
  await openPanel(page);
  await choose(page, value);
  await page.route("**/api/v2/patches/*/evidence-reports", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch(),
      changed = (await response.json()) as SourceEvidenceReport;
    changed.deterministic.policy_catalog_version = "fabricated-catalog";
    const { review_json: _json, review_sha256: _sha, ...body } = changed;
    changed.review_json = stableJson(body);
    changed.review_sha256 = createHash("sha256")
      .update(changed.review_json)
      .digest("hex");
    await route.fulfill({ response, json: changed });
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения совместного отчёта не подтверждён",
  );
  await expect(
    panel(page).getByRole("heading", {
      name: "Совместный отчёт сохранён — требуется рассмотрение",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(panel(page)).not.toContainText("fabricated-catalog");
  await readAttempt(page).click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Совместный отчёт сохранён — требуется рассмотрение",
      exact: true,
    }),
  ).toBeVisible();
});
test("joint history paginates actual immutable reports and deterministic child records", async ({
  page,
}) => {
  const value = await prepare(page);
  const pin = {
    record_id: value.deterministic.recheck_id,
    review_sha256: value.deterministic.review_sha256,
  };
  for (let n = 0; n < 21; n++) {
    const response = await page.request.post(
      `${value.prefix}/evidence-reports`,
      {
        headers,
        data: {
          version: "source-evidence-request-0.1.0",
          report_id: randomUUID(),
          draft_sha256: value.draft.draft_sha256,
          deterministic: pin,
          forest: null,
          neural: null,
          network: null,
        },
      },
    );
    expect(response.status()).toBe(201);
  }
  await openPanel(page);
  await expect(
    panel(page).getByLabel("История совместных отчётов").getByRole("button"),
  ).toHaveCount(20);
  await panel(page)
    .getByRole("button", { name: "Следующие совместные отчёты", exact: true })
    .click();
  await expect(
    panel(page).getByLabel("История совместных отчётов").getByRole("button"),
  ).toHaveCount(1);
  await panel(page)
    .getByRole("button", { name: "Предыдущие совместные отчёты", exact: true })
    .click();
  await expect(
    panel(page).getByLabel("История совместных отчётов").getByRole("button"),
  ).toHaveCount(20);
  // Additional actual completed deterministic records exercise explicit child pagination.
  for (let n = 0; n < 20; n++) {
    const response = await page.request.post(
      `${value.prefix}/deterministic-rechecks`,
      {
        headers,
        data: {
          ...value.deterministic.intent.request,
          recheck_id: randomUUID(),
        },
      },
    );
    expect(response.status()).toBe(201);
  }
  await panel(page)
    .getByRole("button", {
      name: "Обновить совместные отчёты и результаты",
      exact: true,
    })
    .click();
  await panel(page)
    .getByRole("button", {
      name: "Следующие: Исходные политики и сравнения",
      exact: true,
    })
    .click();
  await expect(
    panel(page).getByLabel("Выбор: Исходные политики и сравнения", {
      exact: true,
    }),
  ).toContainText("На странице: 1; смещение: 20");
  await expect(
    panel(page).getByRole("button", {
      name: "Следующие: Исходные политики и сравнения",
      exact: true,
    }),
  ).toBeDisabled();
});

test("bounded metadata controls paginate all four histories and disable pending or failed choices", async ({
  page,
}) => {
  const value = await prepare(page, false, true);
  // These additional list-only rows are explicit UI protocol controls. The
  // underlying selected details were created by real API calls in prepare.
  const controls = [
    ["deterministic-rechecks", "Исходные политики и сравнения"],
    ["statistical-rechecks", "Исходный Forest"],
    ["ml-rechecks", "Нейросетевая модель"],
    ["verifications", "Сетевая проверка"],
  ] as const;
  for (const [segment] of controls) {
    const response = await page.request.get(`${value.prefix}/${segment}`, {
      headers,
    });
    const original = (await response.json())[0] as Record<string, unknown>;
    const rows = Array.from({ length: 20 }, (_, index) => {
      const row = {
        ...original,
        [segment === "verifications" ? "verification_id" : "recheck_id"]:
          randomUUID(),
      };
      if (index === 0) {
        row.execution_status =
          segment === "statistical-rechecks" ? "failed" : "pending_unknown";
        if (row.execution_status === "pending_unknown") row.completed_at = null;
        if (segment === "verifications") {
          row.network_status = null;
          row.cleanup_complete = null;
        }
      }
      return row;
    });
    await page.route(`**${value.prefix}/${segment}?*`, async (route) => {
      const offset = new URL(route.request().url()).searchParams.get("offset");
      await route.fulfill({ json: offset === "20" ? [original] : rows });
    });
  }
  await openPanel(page);
  for (const [, name] of controls) {
    const select = panel(page).getByLabel(name, { exact: true });
    await expect(select.locator("option:disabled")).toHaveCount(1);
    await expect(select).toHaveValue("");
    await panel(page)
      .getByRole("button", { name: `Следующие: ${name}`, exact: true })
      .click();
    await expect(
      panel(page).getByLabel(`Выбор: ${name}`, { exact: true }),
    ).toContainText("На странице: 1; смещение: 20");
    await expect(select.locator("option:disabled")).toHaveCount(0);
    await expect(select).toHaveValue("");
  }
  await expect(save(page)).toBeDisabled();
});
