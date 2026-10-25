import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type {
  AnalysisResult,
  ConfigurationSnapshot,
} from "../../src/contracts";
import type { PatchDraft } from "../../src/patches";

const ADMIN = "browser-tests-service-token-32-characters-001";
const ENGINEER = "browser-tests-engineer-service-token-000001";
const headers = { Authorization: `Bearer ${ADMIN}` };
const region = (page: Page, name: string) =>
  page.getByRole("region", { name, exact: true });
const source = (page: Page) => region(page, "Перепроверка исходного анализа");
const joint = (page: Page) =>
  region(page, "Совместный отчёт по сохранённым результатам");
const risk = (page: Page) => region(page, "Экспериментальный приоритет отчёта");
const decision = (page: Page) =>
  region(page, "Рассмотрение совместного отчёта");

async function connect(page: Page) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(ENGINEER);
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
  const patches = region(page, "Черновики изменений");
  await patches
    .getByRole("button", { name: "Обновить черновики", exact: true })
    .click();
  await patches
    .getByRole("button", {
      name: new RegExp(`Открыть черновик ${draft.patch_id.slice(0, 8)}`),
    })
    .click();
}

const cases = [
  ...(["cisco", "juniper"] as const).flatMap((vendor) =>
    (["before", "after", "both"] as const).map((partial) => ({
      vendor,
      partial,
      critical: false,
      zeroConfidence: false,
    })),
  ),
  ...(["cisco", "juniper"] as const).map((vendor) => ({
    vendor,
    partial: "after" as const,
    critical: true,
    zeroConfidence: false,
  })),
  {
    vendor: "juniper" as const,
    partial: "both" as const,
    critical: false,
    zeroConfidence: true,
  },
];

// Authored software scenarios on a real isolated HTTP backend, without route mocks,
// external services, model workers or a network engine. Viewports reuse templates.
for (const control of cases)
  test(`HTTP partial chain ${control.vendor}/${control.partial}/critical=${control.critical}/zero-confidence=${control.zeroConfidence}`, async ({
    page,
  }, info) => {
    const device = randomUUID();
    const host = `partial-${randomUUID().slice(0, 8)}`;
    function text(telnet: boolean, unknown: boolean, critical: boolean) {
      if (control.zeroConfidence)
        return `## Last commit: owned\n${telnet ? "set system services telnet\n" : ""}`;
      const body =
        control.vendor === "cisco"
          ? `hostname ${host}\nip ssh version 2\nline vty 0 4\n transport input ${telnet ? "telnet ssh" : "ssh"}\n!\n${critical ? "ip route 0.0.0.0 0.0.0.0 Null0\n" : ""}`
          : `set system host-name ${host}\nset system services ssh\n${telnet ? "set system services telnet\n" : ""}${critical ? "set routing-options static route 0.0.0.0/0 discard\n" : ""}`;
      return (
        body +
        (unknown
          ? `${control.vendor === "juniper" ? "set " : ""}unsupported-owned diagnostic-marker\n`
          : "")
      );
    }
    async function upload(content: string) {
      const response = await page.request.post("/api/v1/configurations", {
        headers,
        data: {
          device_id: device,
          filename: "owned-partial.cfg",
          content,
          retain_original_source: true,
        },
      });
      expect(response.status()).toBe(201);
      return (await response.json()) as ConfigurationSnapshot;
    }
    const before = await upload(text(true, control.partial !== "after", false));
    const after = await upload(
      text(false, control.partial !== "before", control.critical),
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
    const draft = (await saved.json()) as PatchDraft;
    const prefix = `/api/v2/patches/${draft.patch_id}`;
    await connect(page);
    await openDraft(page, after, draft);
    await source(page)
      .getByRole("button", {
        name: "Открыть перепроверку анализа",
        exact: true,
      })
      .click();
    await source(page)
      .getByLabel("Режим перепроверки анализа", { exact: true })
      .selectOption("partial");
    await source(page)
      .getByLabel("UUID сохранённого анализа до изменения", { exact: true })
      .fill(analysis.analysis_id);
    await source(page)
      .getByRole("button", {
        name: "Загрузить исходный анализ политик и сравнений",
        exact: true,
      })
      .click();
    await source(page)
      .getByLabel(
        "Разрешаю отдельную локальную перепроверку исходного анализа на сохранённых исходниках",
        { exact: true },
      )
      .check();
    const childResponse = page.waitForResponse(
      (r) =>
        r.url().endsWith(`${prefix}/deterministic-rechecks`) &&
        r.request().method() === "POST",
    );
    await source(page)
      .getByRole("button", {
        name: "Пересчитать исходный анализ до и после",
        exact: true,
      })
      .click();
    const childWire = await childResponse;
    expect(childWire.status()).toBe(201);
    const child = await childWire.json();
    expect(child.version).toBe("source-deterministic-recheck-0.2.0");
    expect(child.outcome.report.policy_changes).toBeNull();
    await expect(
      source(page).getByLabel("Частичная диагностика политик", { exact: true }),
    ).toBeVisible();
    await joint(page)
      .getByRole("button", { name: "Открыть совместный отчёт", exact: true })
      .click();
    await joint(page)
      .getByLabel("Режим совместного отчёта", { exact: true })
      .selectOption("partial");
    await joint(page)
      .getByRole("combobox", {
        name: "Исходные политики и сравнения",
        exact: true,
      })
      .selectOption(child.recheck_id);
    const reportResponse = page.waitForResponse(
      (r) =>
        r.url().endsWith(`${prefix}/evidence-reports`) &&
        r.request().method() === "POST",
    );
    await joint(page)
      .getByRole("button", { name: "Сохранить совместный отчёт", exact: true })
      .click();
    const reportWire = await reportResponse;
    expect(reportWire.status()).toBe(201);
    const report = await reportWire.json();
    expect(report.version).toBe("source-evidence-report-0.5.0");
    const reportBase = `${prefix}/evidence-reports/${report.report_id}`;
    await risk(page)
      .getByRole("button", {
        name: "Открыть приоритеты этого отчёта",
        exact: true,
      })
      .click();
    const riskResponse = page.waitForResponse(
      (r) =>
        r.url().endsWith(`${reportBase}/risk-assessments`) &&
        r.request().method() === "POST",
    );
    await risk(page)
      .getByRole("button", {
        name: "Сохранить экспериментальный приоритет",
        exact: true,
      })
      .click();
    const riskWire = await riskResponse;
    expect(riskWire.status()).toBe(201);
    const assessment = await riskWire.json();
    if (control.zeroConfidence) {
      const policy = assessment.composition.components.find(
        (c: { source: string }) => c.source === "policy",
      );
      expect(policy.raw_score).toBe(0);
      expect(policy.observation.finding_count).toBe(6);
      expect(child.outcome.report.after.parse.summary.confidence).toBe(0);
      const policyRow = risk(page)
        .getByRole("row")
        .filter({
          has: page.getByRole("rowheader", { name: "Политики", exact: true }),
        });
      await expect(policyRow).toContainText("Находок: 6; показатель: 0");
      await expect(policyRow).not.toContainText("наблюдений нет");
    }
    expect(assessment.composition.score).toBeNull();
    expect(assessment.composition.band).toBeNull();
    expect(assessment.composition.applied_guardrails).toEqual([]);
    expect(assessment.composition.components).toHaveLength(5);
    for (const component of assessment.composition.components) {
      expect(component.effective_weight).toBe(0);
      expect(component.contribution).toBeNull();
    }
    await expect(
      risk(page).getByRole("cell", { name: "подавлен", exact: true }),
    ).toHaveCount(5);
    if (control.critical) {
      expect(
        assessment.composition.applicable_guardrails.map(
          (g: { kind: string }) => g.kind,
        ),
      ).toContain("critical_policy");
      await expect(
        risk(page)
          .getByLabel("Применимые нижние границы приоритета")
          .getByText(/Критическая политика/),
      ).toBeVisible();
    }
    await decision(page)
      .getByRole("button", {
        name: "Открыть рассмотрение этого отчёта",
        exact: true,
      })
      .click();
    await decision(page)
      .getByLabel("Вердикт по совместному отчёту", { exact: true })
      .selectOption("needs_more_information");
    await decision(page)
      .getByLabel("Комментарий к решению", { exact: true })
      .fill(
        "Нужны сведения о неизвестных командах и независимое рассмотрение.",
      );
    const decisionResponse = page.waitForResponse(
      (r) =>
        r.url().endsWith(`${reportBase}/decisions`) &&
        r.request().method() === "POST",
    );
    await decision(page)
      .getByRole("button", { name: "Сохранить решение по отчёту", exact: true })
      .click();
    const decisionWire = await decisionResponse;
    expect(decisionWire.status()).toBe(201);
    const disposition = await decisionWire.json();
    expect(disposition.version).toBe("source-evidence-decision-0.5.0");
    expect(disposition.individual_identity_verified).toBe(false);
    expect(disposition.approved).toBe(false);
    expect(disposition.applied).toBe(false);
    expect(
      await (await page.request.get(reportBase, { headers })).json(),
    ).toEqual(report);
    await expect(
      decision(page).getByLabel("Сохранённое решение по отчёту", {
        exact: true,
      }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    await writeFile(
      info.outputPath("saved-chain.json"),
      JSON.stringify(
        {
          control,
          viewport: info.project.name,
          child,
          report,
          assessment,
          disposition,
        },
        null,
        2,
      ),
    );
    if (control.critical)
      await page.screenshot({
        path: info.outputPath("actual-http-partial-chain.png"),
        fullPage: true,
      });
    await page.reload();
    await connect(page);
    await openDraft(page, after, draft);
    await joint(page)
      .getByRole("button", { name: "Открыть совместный отчёт", exact: true })
      .click();
    await joint(page)
      .getByRole("button", {
        name: new RegExp(
          `Открыть совместный отчёт ${report.report_id.slice(0, 8)}`,
        ),
      })
      .click();
    await risk(page)
      .getByRole("button", {
        name: "Открыть приоритеты этого отчёта",
        exact: true,
      })
      .click();
    await risk(page)
      .getByRole("button", {
        name: new RegExp(
          `Открыть оценку ${assessment.assessment_id.slice(0, 8)}`,
        ),
      })
      .click();
    await expect(
      risk(page).getByText(/Общий приоритет: недоступно/),
    ).toBeVisible();
    await decision(page)
      .getByRole("button", {
        name: "Открыть рассмотрение этого отчёта",
        exact: true,
      })
      .click();
    await decision(page)
      .getByRole("button", {
        name: new RegExp(
          `Открыть решение ${disposition.decision_id.slice(0, 8)}`,
        ),
      })
      .click();
    await expect(
      decision(page).getByLabel("Сохранённое решение по отчёту", {
        exact: true,
      }),
    ).toBeVisible();
  });
