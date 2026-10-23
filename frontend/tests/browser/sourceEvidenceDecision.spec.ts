import { createHash, randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { stableJson } from "../../src/contracts";
import type {
  ConfigurationSnapshot,
  AnalysisResult,
} from "../../src/contracts";
import type { PatchDraft } from "../../src/patches";
import type { SourceEvidenceReport } from "../../src/sourceEvidenceReports";
import type {
  ReviewSourceEvidenceReport,
  SourceEvidenceDecision,
} from "../../src/sourceEvidenceDecisions";

const ADMIN = "browser-tests-service-token-32-characters-001";
const ENGINEER = "browser-tests-engineer-service-token-000001";
const READER = "browser-tests-reader-service-token-000001";
const ANALYST = "browser-tests-analyst-service-token-000001";
const headers = { Authorization: `Bearer ${ADMIN}` };
const panel = (page: Page) =>
  page.getByRole("region", {
    name: "Рассмотрение совместного отчёта",
    exact: true,
  });
const reports = (page: Page) =>
  page.getByRole("region", {
    name: "Совместный отчёт по сохранённым результатам",
    exact: true,
  });
const patches = (page: Page) =>
  page.getByRole("region", { name: "Черновики изменений", exact: true });
const save = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Сохранить решение по отчёту",
    exact: true,
  });
const readAttempt = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Прочитать решение по ID запроса",
    exact: true,
  });
async function connect(page: Page, token = ENGINEER) {
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
  value: { after: ConfigurationSnapshot; draft: PatchDraft },
) {
  await page
    .locator(".history-item")
    .filter({ hasText: value.after.configuration_id.slice(0, 8) })
    .click();
  await patches(page)
    .getByRole("button", { name: "Обновить черновики", exact: true })
    .click();
  await patches(page)
    .getByRole("button", {
      name: new RegExp(`Открыть черновик ${value.draft.patch_id.slice(0, 8)}`),
    })
    .click();
  await reports(page)
    .getByRole("button", { name: "Открыть совместный отчёт", exact: true })
    .click();
}
async function openReport(page: Page, report: SourceEvidenceReport) {
  await reports(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть совместный отчёт ${report.report_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(
    reports(page).getByRole("heading", {
      name: "Совместный отчёт сохранён — требуется рассмотрение",
      exact: true,
    }),
  ).toBeVisible();
}
async function openPanel(page: Page) {
  await panel(page)
    .getByRole("button", {
      name: "Открыть рассмотрение этого отчёта",
      exact: true,
    })
    .click();
  await expect(panel(page).getByRole("status")).toBeHidden();
}
async function fill(
  page: Page,
  comment = "Нужны сведения о доступе управления и откате.",
  verdict: ReviewSourceEvidenceReport["verdict"] = "needs_more_information",
) {
  await panel(page)
    .getByLabel("Вердикт по совместному отчёту", { exact: true })
    .selectOption(verdict);
  await panel(page)
    .getByLabel("Комментарий к решению", { exact: true })
    .fill(comment);
}
async function prepare(page: Page, extras = false, legacy = false) {
  const device = randomUUID(),
    host = `source-evidence-${extras ? "error-" : ""}${randomUUID().slice(0, 8)}`;
  const text = (telnet: boolean) =>
    `hostname ${host}\naaa new-model\nip ssh version 2\nline vty 0 4\n transport input ${telnet ? "telnet ssh" : "ssh"}\n!\ninterface GigabitEthernet0/1\n ip address 192.0.2.10 255.255.255.0\n!\n`;
  async function upload(content: string) {
    const response = await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: device,
        filename: "owned-evidence-decision.cfg",
        content,
        retain_original_source: true,
      },
    });
    expect(response.status()).toBe(201);
    return (await response.json()) as ConfigurationSnapshot;
  }
  const before = await upload(text(true)),
    after = await upload(text(false));
  const analyzed = await page.request.post(
    `/api/v1/configurations/${before.configuration_id}/analyze`,
    { headers, data: {} },
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
  const draft = (await saved.json()) as PatchDraft,
    prefix = `/api/v2/patches/${draft.patch_id}`;
  const selectedResponse = await page.request.get(
    `${prefix}/deterministic-selection/${analysis.analysis_id}`,
    { headers },
  );
  expect(selectedResponse.status()).toBe(200);
  const selected = await selectedResponse.json();
  const deterministicResponse = await page.request.post(
    `${prefix}/deterministic-rechecks`,
    {
      headers,
      data: {
        version: "source-deterministic-request-0.1.0",
        recheck_id: randomUUID(),
        draft_sha256: draft.draft_sha256,
        before_analysis_id: analysis.analysis_id,
        before_analysis_sha256: selected.before_analysis_sha256,
        reference_canonical_sha256: null,
        allow_local_analysis_context: true,
      },
    },
  );
  expect(deterministicResponse.status()).toBe(201);
  const deterministic = await deterministicResponse.json();
  let neural = null,
    network = null;
  if (extras) {
    // These explicit workers return authored protocol numbers, without a model or engine.
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
    const row = await mlResponse.json();
    neural = { record_id: row.recheck_id, review_sha256: row.review_sha256 };
    const networkResponse = await page.request.post(`${prefix}/verify`, {
      headers,
      data: {
        version: legacy
          ? "source-patch-request-0.1.0"
          : "source-patch-request-0.2.0",
        verification_id: randomUUID(),
        draft_sha256: draft.draft_sha256,
        companions: [],
        scope: { start_node: host, destination: "192.0.2.0/24" },
        allow_local_engine_upload: true,
      },
    });
    expect(networkResponse.status()).toBe(201);
    const result = await networkResponse.json();
    network = {
      record_id: result.verification_id,
      review_sha256: result.review_sha256,
    };
  }
  const response = await page.request.post(`${prefix}/evidence-reports`, {
    headers,
    data: {
      version: legacy
        ? "source-evidence-request-0.1.0"
        : "source-evidence-request-0.2.0",
      report_id: randomUUID(),
      draft_sha256: draft.draft_sha256,
      deterministic: {
        record_id: deterministic.recheck_id,
        review_sha256: deterministic.review_sha256,
      },
      forest: null,
      neural,
      network,
    },
  });
  expect(response.status()).toBe(201);
  const report = (await response.json()) as SourceEvidenceReport;
  await connect(page);
  await openDraft(page, { after, draft });
  return {
    before,
    after,
    draft,
    report,
    prefix,
    decisions: `${prefix}/evidence-reports/${report.report_id}/decisions`,
  };
}
async function record(page: Page) {
  const pending = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/decisions$/.test(response.url()),
  );
  await save(page).click();
  const response = await pending;
  expect(response.status()).toBe(201);
  const decision = (await response.json()) as SourceEvidenceDecision;
  await expect(
    panel(page).getByLabel("Сохранённое решение по отчёту", { exact: true }),
  ).toBeVisible();
  return decision;
}
test("full accepted report is explicit; append-only dispositions preserve role, escaped comments and immutable parent; reader/analyst cannot post", async ({
  page,
}) => {
  const loads: string[] = [];
  page.on("request", (request) => {
    if (/\/decisions(?:\?|$|\/)/.test(request.url())) loads.push(request.url());
  });
  const value = await prepare(page, true);
  await expect(panel(page)).toHaveCount(0);
  expect(loads).toEqual([]);
  await openReport(page, value.report);
  expect(loads).toEqual([]);
  await reports(page)
    .getByText("Полная сохранённая запись совместного отчёта", { exact: true })
    .click();
  await openPanel(page);
  expect(loads).toHaveLength(1);
  await expect(save(page)).toBeDisabled();
  await expect(
    panel(page).getByRole("option", { name: "Согласовано", exact: true }),
  ).toHaveCount(0);
  const comment =
    "<img src=x onerror=alert(1)>\nЗапрос сведений 😀\tбез удостоверенной личности.";
  await fill(page, comment);
  const first = await record(page);
  expect(first.version).toBe("source-evidence-decision-0.2.0");
  expect(first.request.version).toBe("source-evidence-decision-request-0.2.0");
  expect(first.report_version).toBe("source-evidence-report-0.2.0");
  expect(value.report.network).toMatchObject({
    sdk_version: "owned-browser-sdk-0.36.0",
    sdk_observation: "observed",
  });
  expect(first.service_role).toBe("engineer");
  expect(first.request.comment).toBe(comment);
  await expect(
    panel(page).getByLabel("Сохранённый комментарий решения", { exact: true }),
  ).toHaveText(comment);
  await expect(panel(page).locator("img[src=x]")).toHaveCount(0);
  await expect(panel(page)).toContainText("Личность инженера не удостоверена");
  await panel(page)
    .getByRole("button", {
      name: "Подготовить новое решение по отчёту",
      exact: true,
    })
    .click();
  await expect(save(page)).toBeDisabled();
  await fill(page, "Отклонение без повышения формального статуса.", "rejected");
  const second = await record(page);
  expect(second.decision_id).not.toBe(first.decision_id);
  expect(
    await (
      await page.request.get(
        `${value.prefix}/evidence-reports/${value.report.report_id}`,
        { headers },
      )
    ).json(),
  ).toEqual(value.report);
  const rows = await (
    await page.request.get(value.decisions, { headers })
  ).json();
  expect(rows).toHaveLength(2);
  expect(
    rows.every((row: Record<string, unknown>) => !("comment" in row)),
  ).toBe(true);
  const replay = await page.request.post(value.decisions, {
    headers,
    data: first.request,
  });
  expect(replay.status()).toBe(200);
  expect(await replay.json()).toEqual(first);
  await connect(page, READER);
  await openDraft(page, value);
  await openReport(page, value.report);
  await openPanel(page);
  await expect(save(page)).toHaveCount(0);
  await expect(
    panel(page).getByLabel("Комментарий к решению", { exact: true }),
  ).toHaveCount(0);
  await panel(page)
    .getByRole("button", {
      name: new RegExp(`Открыть решение ${first.decision_id.slice(0, 8)}`),
    })
    .click();
  await expect(panel(page)).toContainText(first.decision_sha256);
  await expect(panel(page)).toContainText(
    "Сервисная роль при записи: engineer",
  );
  for (const token of [READER, ANALYST])
    expect(
      (
        await page.request.post(value.decisions, {
          headers: { Authorization: `Bearer ${token}` },
          data: { ...first.request, decision_id: randomUUID() },
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
test("legacy report review explicitly preserves decision protocol 0.1 and unchanged parent bytes", async ({
  page,
}) => {
  const value = await prepare(page, true, true);
  const parentRaw = await (
    await page.request.get(
      `${value.prefix}/evidence-reports/${value.report.report_id}`,
      { headers },
    )
  ).text();
  await openReport(page, value.report);
  await openPanel(page);
  await fill(page, "Исторический отчёт без наблюдения SDK.", "rejected");
  const decision = await record(page);
  expect(decision.version).toBe("source-evidence-decision-0.1.0");
  expect(decision.request.version).toBe(
    "source-evidence-decision-request-0.1.0",
  );
  expect(decision.report_version).toBe("source-evidence-report-0.1.0");
  expect(
    await (
      await page.request.get(
        `${value.prefix}/evidence-reports/${value.report.report_id}`,
        { headers },
      )
    ).text(),
  ).toBe(parentRaw);
  await expect(reports(page)).toContainText(
    "SDK: недоступно — исходная запись не сохраняла версию",
  );
});
test("comment uses Unicode codepoints and no default verdict or unsupported approval", async ({
  page,
}) => {
  const value = await prepare(page);
  await openReport(page, value.report);
  await openPanel(page);
  const comment = panel(page).getByLabel("Комментарий к решению", {
    exact: true,
  });
  await comment.fill("😀".repeat(1200));
  await expect(panel(page)).toContainText("Символов Unicode: 1200 / 1200");
  await expect(save(page)).toBeDisabled();
  await panel(page)
    .getByLabel("Вердикт по совместному отчёту", { exact: true })
    .selectOption("rejected");
  await expect(save(page)).toBeEnabled();
  await comment.fill("😀".repeat(1201));
  await expect(save(page)).toBeDisabled();
  await fill(page, " \n\t");
  await expect(save(page)).toBeDisabled();
  await fill(page, "😀".repeat(1200), "rejected");
  const result = await record(page);
  expect(Array.from(result.request.comment)).toHaveLength(1200);
  expect(result.approved).toBe(false);
});
test("lost successful POST freezes fields and parent navigation and recovers only by same-ID GET", async ({
  page,
}) => {
  const value = await prepare(page),
    requests: ReviewSourceEvidenceReport[] = [];
  await openReport(page, value.report);
  await openPanel(page);
  await fill(page);
  await page.route("**/evidence-reports/*/decisions", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    requests.push(route.request().postDataJSON());
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    await route.abort("connectionreset");
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения решения не подтверждён",
  );
  await expect(save(page)).toBeDisabled();
  await expect(
    panel(page).getByLabel("Комментарий к решению", { exact: true }),
  ).toBeDisabled();
  await expect(
    reports(page).getByRole("button", {
      name: "Обновить совместные отчёты и результаты",
      exact: true,
    }),
  ).toBeDisabled();
  await readAttempt(page).click();
  await expect(
    panel(page).getByLabel("Сохранённое решение по отчёту", { exact: true }),
  ).toBeVisible();
  expect(requests).toHaveLength(1);
  expect(
    (await (await page.request.get(value.decisions, { headers })).json())[0]
      .decision_id,
  ).toBe(requests[0]!.decision_id);
});
test("known refusal plus GET404 permits explicit reset and fresh ID", async ({
  page,
}) => {
  const value = await prepare(page),
    requests: ReviewSourceEvidenceReport[] = [];
  await openReport(page, value.report);
  await openPanel(page);
  await fill(page);
  await page.route("**/evidence-reports/*/decisions", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    requests.push(route.request().postDataJSON());
    if (requests.length === 1)
      await route.fulfill({
        status: 409,
        json: { detail: "Owned refusal before storage" },
      });
    else await route.continue();
  });
  await save(page).click();
  await expect(panel(page)).toContainText("Сервер отклонил запрос решения");
  const reset = panel(page).getByRole("button", {
    name: "Сбросить отклонённый запрос решения",
    exact: true,
  });
  await expect(reset).toHaveCount(0);
  await readAttempt(page).click();
  await expect(reset).toBeEnabled();
  await reset.click();
  await expect(save(page)).toBeDisabled();
  await fill(page);
  await record(page);
  expect(requests[0]!.decision_id).not.toBe(requests[1]!.decision_id);
});
for (const mode of ["lost", "503"] as const)
  test(`${mode} plus GET404 stays frozen without another POST`, async ({
    page,
  }) => {
    const value = await prepare(page),
      requests: ReviewSourceEvidenceReport[] = [];
    await openReport(page, value.report);
    await openPanel(page);
    await fill(page);
    await page.route("**/evidence-reports/*/decisions", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      requests.push(route.request().postDataJSON());
      if (mode === "lost") await route.abort("connectionreset");
      else
        await route.fulfill({
          status: 503,
          json: { detail: "Owned uncertain unavailable response" },
        });
    });
    await save(page).click();
    await expect(panel(page)).toContainText(
      "Итог сохранения решения не подтверждён",
    );
    await readAttempt(page).click();
    await expect(
      panel(page).getByRole("button", {
        name: "Сбросить отклонённый запрос решения",
        exact: true,
      }),
    ).toHaveCount(0);
    await expect(save(page)).toBeDisabled();
    expect(requests).toHaveLength(1);
  });
test("resealed wrong decision projection is rejected and exact stored decision can be recovered", async ({
  page,
}) => {
  const value = await prepare(page);
  await openReport(page, value.report);
  await openPanel(page);
  await fill(page);
  await page.route("**/evidence-reports/*/decisions", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch(),
      row = (await response.json()) as SourceEvidenceDecision;
    row.before.canonical_sha256 = "9".repeat(64);
    const { decision_json: _json, decision_sha256: _sha, ...body } = row;
    row.decision_json = stableJson(body);
    row.decision_sha256 = createHash("sha256")
      .update(row.decision_json)
      .digest("hex");
    await route.fulfill({ response, json: row });
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения решения не подтверждён",
  );
  await expect(
    panel(page).getByLabel("Сохранённое решение по отчёту", { exact: true }),
  ).toHaveCount(0);
  await readAttempt(page).click();
  await expect(
    panel(page).getByLabel("Сохранённое решение по отчёту", { exact: true }),
  ).toBeVisible();
});
test("actual immutable decision history paginates metadata and late detail after logout is discarded", async ({
  page,
}) => {
  const value = await prepare(page);
  const ids: string[] = [];
  for (let n = 0; n < 21; n++) {
    const id = randomUUID();
    ids.push(id);
    const response = await page.request.post(value.decisions, {
      headers,
      data: {
        version: "source-evidence-decision-request-0.2.0",
        decision_id: id,
        report_sha256: value.report.review_sha256,
        verdict: n % 2 ? "rejected" : "needs_more_information",
        comment: `Owned append-only control ${n}`,
      },
    });
    expect(response.status()).toBe(201);
  }
  await openReport(page, value.report);
  await openPanel(page);
  const list = panel(page).getByLabel("История решений по отчёту", {
    exact: true,
  });
  await expect(list.getByRole("button")).toHaveCount(20);
  await panel(page)
    .getByRole("button", { name: "Следующие решения по отчёту", exact: true })
    .click();
  await expect(list.getByRole("button")).toHaveCount(1);
  await panel(page)
    .getByRole("button", { name: "Предыдущие решения по отчёту", exact: true })
    .click();
  await expect(list.getByRole("button")).toHaveCount(20);
  let release: (() => void) | undefined, started: (() => void) | undefined;
  const arrived = new Promise<void>((resolve) => {
    started = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/evidence-reports/*/decisions/*", async (route) => {
    const response = await route.fetch();
    started!();
    await gate;
    await route.fulfill({ response });
  });
  await list.getByRole("button").first().click();
  await arrived;
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  release!();
  await expect(panel(page)).toHaveCount(0);
  await expect(page.getByLabel("API-токен", { exact: true })).toBeVisible();
});
