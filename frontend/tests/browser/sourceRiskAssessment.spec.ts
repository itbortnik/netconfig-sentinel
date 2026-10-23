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
  SourceRiskAssessment,
  CreateSourceRiskAssessment,
} from "../../src/sourceRiskAssessments";
const ADMIN = "browser-tests-service-token-32-characters-001",
  ENGINEER = "browser-tests-engineer-service-token-000001",
  READER = "browser-tests-reader-service-token-000001",
  ANALYST = "browser-tests-analyst-service-token-000001";
const headers = { Authorization: `Bearer ${ADMIN}` };
const panel = (page: Page) =>
  page.getByRole("region", {
    name: "Экспериментальный приоритет отчёта",
    exact: true,
  });
const reports = (page: Page) =>
  page.getByRole("region", {
    name: "Совместный отчёт по сохранённым результатам",
    exact: true,
  });
const decisions = (page: Page) =>
  page.getByRole("region", {
    name: "Рассмотрение совместного отчёта",
    exact: true,
  });
const patches = (page: Page) =>
  page.getByRole("region", { name: "Черновики изменений", exact: true });
const save = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Сохранить экспериментальный приоритет",
    exact: true,
  });
const recover = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Прочитать оценку по ID запроса",
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
async function prepare(
  page: Page,
  extras = false,
  legacy: boolean | "sdk" = false,
  direction?: string,
  adverse?: "critical" | "partial",
) {
  const device = randomUUID(),
    host = `${direction ? `source-direction-${direction}-` : `source-evidence-${extras ? "error-" : ""}`}${randomUUID().slice(0, 8)}`;
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
  const before = await upload(
      text(true) + (adverse === "partial" ? "owned unsupported command\n" : ""),
    ),
    after = await upload(
      text(false) +
        (adverse === "critical"
          ? "ip access-list extended OPEN\n permit ip any any\n!\n"
          : adverse === "partial"
            ? "owned unsupported command\n"
            : ""),
    );
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
        version:
          legacy === "sdk"
            ? "source-patch-request-0.2.0"
            : legacy
              ? "source-patch-request-0.1.0"
              : "source-patch-request-0.3.0",
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
      version:
        legacy === "sdk"
          ? "source-evidence-request-0.2.0"
          : legacy
            ? "source-evidence-request-0.1.0"
            : "source-evidence-request-0.3.0",
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
    assessments: `${prefix}/evidence-reports/${report.report_id}/risk-assessments`,
  };
}
async function openPanel(page: Page) {
  await panel(page)
    .getByRole("button", {
      name: "Открыть приоритеты этого отчёта",
      exact: true,
    })
    .click();
  await expect(panel(page).getByRole("status")).toBeHidden();
}
async function record(page: Page) {
  const response = page.waitForResponse(
    (r) =>
      r.request().method() === "POST" && r.url().endsWith("/risk-assessments"),
  );
  await save(page).click();
  const result = await response;
  expect(result.status()).toBe(201);
  const row = (await result.json()) as SourceRiskAssessment;
  await expect(
    panel(page).getByRole("heading", {
      name: "Экспериментальный приоритет сохранён",
      exact: true,
    }),
  ).toBeVisible();
  return row;
}
for (const direction of ["loss", "both", "gain", "unknown", "empty"]) {
  test(`explicit immutable priority ${direction}, saved exact read and same-ID cross-role replay`, async ({
    page,
  }) => {
    const v = await prepare(page, true, false, direction);
    const parentRaw = await (
      await page.request.get(
        `${v.prefix}/evidence-reports/${v.report.report_id}`,
        { headers },
      )
    ).text();
    await openReport(page, v.report);
    await openPanel(page);
    const row = await record(page),
      n = row.composition.components[4]!;
    expect(n.raw_score).toBe(["loss", "both"].includes(direction) ? 1 : null);
    if (n.raw_score !== null) expect(row.composition.score).toBe(0.95);
    expect(row.service_role).toBe("engineer");
    expect(row.approved).toBe(false);
    expect(row.applied).toBe(false);
    await expect(panel(page)).toContainText(
      "безразмерный инженерный приоритет",
    );
    await expect(
      panel(page).getByRole("table", {
        name: "Компоненты экспериментального приоритета",
      }),
    ).toBeVisible();
    const replay = await page.request.post(v.assessments, {
      headers,
      data: row.request,
    });
    expect(replay.status()).toBe(200);
    expect(await replay.json()).toEqual(row);
    const read = await page.request.get(
      `${v.assessments}/${row.assessment_id}`,
      { headers },
    );
    expect(await read.json()).toEqual(row);
    expect(
      await (
        await page.request.get(
          `${v.prefix}/evidence-reports/${v.report.report_id}`,
          { headers },
        )
      ).text(),
    ).toBe(parentRaw);
    await page.reload();
    await connect(page);
    await openDraft(page, v);
    await openReport(page, v.report);
    await openPanel(page);
    await panel(page)
      .getByRole("button", {
        name: new RegExp(`Открыть оценку ${row.assessment_id.slice(0, 8)}`),
      })
      .click();
    await expect(
      panel(page).getByRole("heading", {
        name: "Экспериментальный приоритет сохранён",
        exact: true,
      }),
    ).toBeVisible();
    expect(v.report.risk_fused).toBe(false);
  });
}
test("keeps critical semantics visible without formal promotion", async ({
  page,
}) => {
  const v = await prepare(page, true, false, "loss", "critical");
  await openReport(page, v.report);
  await openPanel(page);
  const row = await record(page);
  expect(row.composition.applicable_guardrails.map((g) => g.kind)).toContain(
    "critical_policy",
  );
  await expect(panel(page)).toContainText("Критическая политика");
  expect(row.composition.formal_qualification).toBe("not_proven");
});
// Current ordinary deterministic workflow explicitly requires complete coverage.
// This control records that boundary; it is not a partial-risk end-to-end pass.
test("partial coverage is refused by ordinary deterministic workflow before a report exists", async ({
  page,
}) => {
  const device = randomUUID(),
    host = `source-direction-loss-${randomUUID().slice(0, 8)}`;
  const upload = async (telnet: boolean) => {
    const response = await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: device,
        filename: "owned-partial-control.cfg",
        content: `hostname ${host}\naaa new-model\nip ssh version 2\nline vty 0 4\n transport input ${telnet ? "telnet ssh" : "ssh"}\n!\nowned unsupported command\n`,
        retain_original_source: true,
      },
    });
    expect(response.status()).toBe(201);
    return (await response.json()) as ConfigurationSnapshot;
  };
  const before = await upload(true),
    after = await upload(false);
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
  const draft = (await saved.json()) as PatchDraft;
  expect(draft.diff.coverage).toBe("partial");
  const prefix = `/api/v2/patches/${draft.patch_id}`;
  const selected = await (
    await page.request.get(
      `${prefix}/deterministic-selection/${analysis.analysis_id}`,
      { headers },
    )
  ).json();
  const refused = await page.request.post(`${prefix}/deterministic-rechecks`, {
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
  });
  expect(refused.status()).toBe(409);
  const reports = await page.request.get(
    `${prefix}/evidence-reports?limit=20&offset=0`,
    { headers },
  );
  expect(await reports.json()).toEqual([]);
});
test("reader and analyst can read but cannot POST", async ({ page }) => {
  const v = await prepare(page);
  await openReport(page, v.report);
  await openPanel(page);
  const row = await record(page);
  for (const token of [READER, ANALYST]) {
    await connect(page, token);
    await openDraft(page, v);
    await openReport(page, v.report);
    await openPanel(page);
    await expect(save(page)).toHaveCount(0);
    await panel(page)
      .getByRole("button", {
        name: new RegExp(`Открыть оценку ${row.assessment_id.slice(0, 8)}`),
      })
      .click();
    await expect(
      panel(page).getByRole("heading", {
        name: "Экспериментальный приоритет сохранён",
        exact: true,
      }),
    ).toBeVisible();
    const denied = await page.request.post(v.assessments, {
      headers: { Authorization: `Bearer ${token}` },
      data: { ...row.request, assessment_id: randomUUID() },
    });
    expect(denied.status()).toBe(403);
  }
});
test("lost successful POST freezes parent and decision while recovery reads same ID", async ({
  page,
}) => {
  const v = await prepare(page, true, false, "loss"),
    requests: CreateSourceRiskAssessment[] = [];
  await openReport(page, v.report);
  await openPanel(page);
  await page.route("**/evidence-reports/*/risk-assessments", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    requests.push(route.request().postDataJSON());
    const r = await route.fetch();
    expect(r.status()).toBe(201);
    await route.abort("connectionreset");
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения экспериментального приоритета не подтверждён",
  );
  await expect(save(page)).toBeDisabled();
  await expect(recover(page)).toBeEnabled();
  await expect(
    reports(page).getByRole("button", {
      name: "Обновить совместные отчёты и результаты",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(
    decisions(page).getByRole("button", {
      name: "Открыть рассмотрение этого отчёта",
      exact: true,
    }),
  ).toBeDisabled();
  await recover(page).click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Экспериментальный приоритет сохранён",
      exact: true,
    }),
  ).toBeVisible();
  expect(requests).toHaveLength(1);
});
test("parent refetch refusal after committed POST stays uncertain, GET-only recovery", async ({
  page,
}) => {
  const v = await prepare(page, true, false, "both");
  await openReport(page, v.report);
  await openPanel(page);
  const pattern = `**/api/v2/patches/*/evidence-reports/${v.report.report_id}`;
  await page.route(pattern, (route) =>
    route.fulfill({ status: 403, json: { detail: "authored parent refusal" } }),
  );
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения экспериментального приоритета не подтверждён",
  );
  await recover(page).click();
  await expect(
    panel(page).getByRole("button", {
      name: "Сбросить отклонённый запрос приоритета",
    }),
  ).toHaveCount(0);
  await expect(recover(page)).toBeEnabled();
  await page.unroute(pattern);
  await recover(page).click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Экспериментальный приоритет сохранён",
      exact: true,
    }),
  ).toBeVisible();
});
test("resealed internally valid but false neural observation cannot be displayed", async ({
  page,
}) => {
  const v = await prepare(page, true, false, "loss");
  await openReport(page, v.report);
  await openPanel(page);
  const pattern = "**/evidence-reports/*/risk-assessments";
  await page.route(pattern, async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch(),
      row = (await response.json()) as SourceRiskAssessment,
      o = row.composition.components[3]!.observation;
    if (o?.kind !== "neural") throw Error("expected neural control");
    o.classes = ["unsupported_control"];
    const { review_json: _json, review_sha256: _sha, ...body } = row;
    row.review_json = stableJson(body);
    row.review_sha256 = createHash("sha256")
      .update(row.review_json)
      .digest("hex");
    await route.fulfill({ response, json: row });
  });
  await save(page).click();
  await expect(panel(page)).toContainText(
    "Итог сохранения экспериментального приоритета не подтверждён",
  );
  await expect(
    panel(page).getByRole("heading", {
      name: "Экспериментальный приоритет сохранён",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(recover(page)).toBeEnabled();
  await page.unroute(pattern);
  await recover(page).click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Экспериментальный приоритет сохранён",
      exact: true,
    }),
  ).toBeVisible();
});
test("history uses bounded pages and verifies selected detail against compact summary", async ({
  page,
}) => {
  const v = await prepare(page);
  await openReport(page, v.report);
  await openPanel(page);
  const first = await record(page);
  for (let i = 0; i < 20; i++) {
    const response = await page.request.post(v.assessments, {
      headers,
      data: { ...first.request, assessment_id: randomUUID() },
    });
    expect(response.status()).toBe(201);
  }
  await panel(page)
    .getByRole("button", { name: "Обновить приоритеты отчёта", exact: true })
    .click();
  await expect(
    panel(page)
      .getByLabel("История экспериментальных приоритетов")
      .getByRole("button"),
  ).toHaveCount(20);
  await panel(page)
    .getByRole("button", { name: "Следующие оценки приоритета", exact: true })
    .click();
  await expect(panel(page)).toContainText(
    "Оценок на странице: 1; смещение: 20",
  );
  await panel(page)
    .getByRole("button", {
      name: new RegExp(`Открыть оценку ${first.assessment_id.slice(0, 8)}`),
    })
    .click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Экспериментальный приоритет сохранён",
      exact: true,
    }),
  ).toBeVisible();
});
