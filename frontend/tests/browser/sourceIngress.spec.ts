import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { ConfigurationSnapshot } from "../../src/contracts";
import type { PatchDraft } from "../../src/patches";
import { sourcePatchVerificationSchema } from "../../src/sourcePatchVerification";
import { sourceEvidenceReportSchema } from "../../src/sourceEvidenceReports";
import { sourceEvidenceDecisionSchema } from "../../src/sourceEvidenceDecisions";
import { sourceRiskAssessmentSchema } from "../../src/sourceRiskAssessments";

// Isolated authored worker answers test UI and persistence; no actual SDK/engine is claimed.
const ADMIN = "browser-tests-service-token-32-characters-001";
const ENGINEER = "browser-tests-engineer-service-token-000001";
const READER = "browser-tests-reader-service-token-000001";
const headers = { Authorization: `Bearer ${ADMIN}` };
const region = (page: Page, name: string) =>
  page.getByRole("region", { name, exact: true });
const network = (page: Page) =>
  region(page, "Сетевая проверка сохранённых исходников");
const reports = (page: Page) =>
  region(page, "Совместный отчёт по сохранённым результатам");
const risk = (page: Page) => region(page, "Экспериментальный приоритет отчёта");
const decisions = (page: Page) =>
  region(page, "Рассмотрение совместного отчёта");
const scope = (container: ReturnType<typeof region>) =>
  container.getByRole("region", {
    name: "Наблюдаемая область точек входа IPv4",
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
async function prepare(page: Page, flavor = "observed", junos = false) {
  const device = randomUUID(),
    host = `source-direction-loss-${flavor}-${randomUUID().slice(0, 8)}`;
  const text = (before: boolean) =>
    junos
      ? `set system host-name ${host}\nset system services ssh\n${before ? "set system services telnet\n" : ""}set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.10/24\n`
      : `hostname ${host}\naaa new-model\nip ssh version 2\nline vty 0 4\n transport input ${before ? "telnet ssh" : "ssh"}\n!\ninterface GigabitEthernet0/1\n ip address 192.0.2.10 255.255.255.0\n!\n`;
  async function upload(content: string) {
    const r = await page.request.post("/api/v1/configurations", {
      headers,
      data: {
        device_id: device,
        filename: "owned-ingress.cfg",
        content,
        retain_original_source: true,
      },
    });
    expect(r.status()).toBe(201);
    return (await r.json()) as ConfigurationSnapshot;
  }
  const before = await upload(text(true)),
    after = await upload(text(false));
  const analyzed = await page.request.post(
    `/api/v1/configurations/${before.configuration_id}/analyze`,
    { headers, data: {} },
  );
  expect(analyzed.status()).toBe(201);
  const analysis = await analyzed.json();
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
  const selection = await page.request.get(
    `${prefix}/deterministic-selection/${analysis.analysis_id}`,
    { headers },
  );
  expect(selection.status()).toBe(200);
  const selected = await selection.json();
  const checked = await page.request.post(`${prefix}/deterministic-rechecks`, {
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
  expect(checked.status()).toBe(201);
  const deterministic = await checked.json();
  return { before, after, draft, prefix, deterministic, host };
}
async function openDraft(page: Page, v: Awaited<ReturnType<typeof prepare>>) {
  await page
    .locator(".history-item")
    .filter({ hasText: v.after.configuration_id.slice(0, 8) })
    .click();
  const patches = region(page, "Черновики изменений");
  await patches
    .getByRole("button", { name: "Обновить черновики", exact: true })
    .click();
  await patches
    .getByRole("button", {
      name: new RegExp(`Открыть черновик ${v.draft.patch_id.slice(0, 8)}`),
    })
    .click();
}
async function createNetwork(
  page: Page,
  v: Awaited<ReturnType<typeof prepare>>,
) {
  await network(page)
    .getByRole("button", {
      name: "Открыть сетевые проверки исходников",
      exact: true,
    })
    .click();
  await network(page)
    .getByLabel("Начальный узел сетевой проверки", { exact: true })
    .fill(v.host);
  await network(page)
    .getByLabel("Назначение IPv4 сетевой проверки", { exact: true })
    .fill("192.0.2.0/24");
  await network(page)
    .getByRole("checkbox", {
      name: /Разрешаю передачу выбранных исходников локальному сетевому/,
    })
    .check();
  const response = page.waitForResponse(
    (r) => r.request().method() === "POST" && r.url().endsWith("/verify"),
  );
  await network(page)
    .getByRole("button", {
      name: "Проверить сохранённые исходники в сети",
      exact: true,
    })
    .click();
  const r = await response;
  expect(r.status()).toBe(201);
  const row = sourcePatchVerificationSchema.parse(await r.json());
  expect(row.version).toBe("source-patch-verification-0.4.0");
  await expect(scope(network(page))).toBeVisible();
  return row;
}
async function createReport(
  page: Page,
  v: Awaited<ReturnType<typeof prepare>>,
  id: string,
) {
  await reports(page)
    .getByRole("button", { name: "Открыть совместный отчёт", exact: true })
    .click();
  await reports(page)
    .getByLabel("Исходные политики и сравнения", { exact: true })
    .selectOption(v.deterministic.recheck_id);
  await reports(page)
    .getByLabel("Сетевая проверка", { exact: true })
    .selectOption(id);
  const response = page.waitForResponse(
    (r) =>
      r.request().method() === "POST" && r.url().endsWith("/evidence-reports"),
  );
  await reports(page)
    .getByRole("button", { name: "Сохранить совместный отчёт", exact: true })
    .click();
  const r = await response;
  expect(r.status()).toBe(201);
  const row = sourceEvidenceReportSchema.parse(await r.json());
  expect(row.version).toBe("source-evidence-report-0.4.0");
  await expect(
    reports(page).getByRole("heading", {
      name: "Совместный отчёт сохранён — требуется рассмотрение",
      exact: true,
    }),
  ).toBeVisible();
  return row;
}

test("source .4, joint .4, decision .4 and recovered risk .2 preserve full observations and legacy history", async ({
  page,
}) => {
  const v = await prepare(page);
  const legacyResponse = await page.request.post(`${v.prefix}/verify`, {
    headers,
    data: {
      version: "source-patch-request-0.3.0",
      verification_id: randomUUID(),
      draft_sha256: v.draft.draft_sha256,
      companions: [],
      scope: { start_node: v.host, destination: "192.0.2.0/24" },
      allow_local_engine_upload: true,
    },
  });
  expect(legacyResponse.status()).toBe(201);
  const legacy = await legacyResponse.json();
  await connect(page);
  await openDraft(page, v);
  const source = await createNetwork(page, v);
  await scope(network(page))
    .getByText("Сохранённые интерфейсы и назначения источника", { exact: true })
    .click();
  await expect(
    scope(network(page)).getByRole("table", {
      name: "Выбранные интерфейсы после",
      exact: true,
    }),
  ).toContainText("192.0.2.10/24");
  await network(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть сетевую проверку ${legacy.verification_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(scope(network(page))).toHaveCount(0);
  await network(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть сетевую проверку ${source.verification_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(scope(network(page))).toBeVisible();
  const report = await createReport(page, v, source.verification_id);
  await expect(scope(reports(page))).toBeVisible();
  await decisions(page)
    .getByRole("button", {
      name: "Открыть рассмотрение этого отчёта",
      exact: true,
    })
    .click();
  await decisions(page)
    .getByLabel("Вердикт по совместному отчёту", { exact: true })
    .selectOption("needs_more_information");
  await decisions(page)
    .getByLabel("Комментарий к решению", { exact: true })
    .fill("Нужны сведения о доступе управления.");
  const decisionResponse = page.waitForResponse(
    (r) => r.request().method() === "POST" && r.url().endsWith("/decisions"),
  );
  await decisions(page)
    .getByRole("button", { name: "Сохранить решение по отчёту", exact: true })
    .click();
  const d = await decisionResponse;
  expect(d.status()).toBe(201);
  expect(sourceEvidenceDecisionSchema.parse(await d.json()).version).toBe(
    "source-evidence-decision-0.4.0",
  );
  await expect(
    decisions(page).getByLabel("Сохранённый комментарий решения", {
      exact: true,
    }),
  ).toBeVisible();
  await risk(page)
    .getByRole("button", {
      name: "Открыть приоритеты этого отчёта",
      exact: true,
    })
    .click();
  let postCount = 0;
  await page.route("**/risk-assessments", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    postCount++;
    expect(route.request().postDataJSON().version).toBe(
      "source-risk-request-0.2.0",
    );
    const result = await route.fetch();
    expect(result.status()).toBe(201);
    const row = sourceRiskAssessmentSchema.parse(await result.json());
    expect(row.version).toBe("source-risk-assessment-0.2.0");
    expect(row.composition.score).toBe(0.95);
    await route.abort("connectionreset");
  });
  await risk(page)
    .getByRole("button", {
      name: "Сохранить экспериментальный приоритет",
      exact: true,
    })
    .click();
  await expect(risk(page)).toContainText(
    "Итог сохранения экспериментального приоритета не подтверждён",
  );
  await expect(
    reports(page).getByRole("button", {
      name: "Обновить совместные отчёты и результаты",
      exact: true,
    }),
  ).toBeDisabled();
  await risk(page)
    .getByRole("button", {
      name: "Прочитать оценку по ID запроса",
      exact: true,
    })
    .click();
  await expect(scope(risk(page))).toBeVisible();
  expect(postCount).toBe(1);
  const denied = await page.request.post(
    `${v.prefix}/evidence-reports/${report.report_id}/risk-assessments`,
    {
      headers: { Authorization: `Bearer ${READER}` },
      data: {
        version: "source-risk-request-0.2.0",
        assessment_id: randomUUID(),
        report_sha256: report.review_sha256,
        profile_version: "source-priority-profile-0.1.0",
      },
    },
  );
  expect(denied.status()).toBe(403);
});
for (const [flavor, junos] of [
  ["ingress-query-failed", false],
  ["junos-parent", true],
] as const)
  test(`unknown acquisition or eligibility stays unknown: ${flavor}`, async ({
    page,
  }) => {
    const v = await prepare(page, flavor, junos);
    await connect(page);
    await openDraft(page, v);
    const source = await createNetwork(page, v);
    await expect(scope(network(page))).toContainText("неизвестно");
    if (junos) {
      await scope(network(page))
        .getByText("Сохранённые интерфейсы и назначения источника", {
          exact: true,
        })
        .click();
      await expect(
        scope(network(page)).getByRole("table", {
          name: "Выбранные интерфейсы после",
          exact: true,
        }),
      ).toContainText("Неизвестно: конкретный IPv4 отсутствует");
    } else
      await expect(scope(network(page))).toContainText(
        "Получить наблюдения не удалось",
      );
    const report = await createReport(page, v, source.verification_id);
    const response = await page.request.post(
      `${v.prefix}/evidence-reports/${report.report_id}/risk-assessments`,
      {
        headers,
        data: {
          version: "source-risk-request-0.2.0",
          assessment_id: randomUUID(),
          report_sha256: report.review_sha256,
          profile_version: "source-priority-profile-0.1.0",
        },
      },
    );
    expect(response.status()).toBe(201);
    const saved = sourceRiskAssessmentSchema.parse(await response.json());
    expect(saved.composition.score).toBe(0.95);
    await risk(page)
      .getByRole("button", {
        name: "Открыть приоритеты этого отчёта",
        exact: true,
      })
      .click();
    await risk(page)
      .getByRole("button", {
        name: new RegExp(`Открыть оценку ${saved.assessment_id.slice(0, 8)}`),
      })
      .click();
    await expect(scope(risk(page))).toContainText("неизвестно");
  });
