import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import controls from "../../src/testdata/sourcePartialDiagnosticControls.json" with { type: "json" };
import { rolePermissions, stableJson } from "../../src/contracts";
import {
  sourcePartialBlockers,
  sourcePartialDiagnosticSchema,
} from "../../src/sourceDeterministicRecheck";
import {
  sourceRiskAssessmentSchema,
  sourceRiskSummary,
} from "../../src/sourceRiskAssessments";

const source = (p: Page) =>
  p.getByRole("region", {
    name: "Перепроверка исходного анализа",
    exact: true,
  });
const joint = (p: Page) =>
  p.getByRole("region", {
    name: "Совместный отчёт по сохранённым результатам",
    exact: true,
  });
const risk = (p: Page) =>
  p.getByRole("region", {
    name: "Экспериментальный приоритет отчёта",
    exact: true,
  });
const digest = (s: string) => createHash("sha256").update(s).digest("hex");
async function setup(
  page: Page,
  index = 0,
  behavior:
    | "completed"
    | "pending_unknown"
    | "failed"
    | "lost"
    | "refused"
    | "corrupt" = "completed",
  reader = false,
) {
  const c = structuredClone(controls.cases[index]!),
    calls: {
      method: string;
      path: string;
      body: Record<string, unknown> | null;
    }[] = [];
  const d = sourcePartialDiagnosticSchema.parse(c.diagnostic);
  if (behavior === "pending_unknown" || behavior === "failed") {
    d.execution_status = behavior;
    d.outcome =
      behavior === "pending_unknown"
        ? null
        : {
            ...d.outcome!,
            execution_status: "failed",
            report: null,
            failure_reason:
              "original_context_or_deterministic_result_unavailable",
          };
    if (d.outcome) d.outcome.intent_sha256 = digest(stableJson(d.intent));
    d.validation_blockers = sourcePartialBlockers(
      d.intent.selection.original,
      d.outcome,
    );
    const { review_json: _j, review_sha256: _h, ...body } = d;
    d.review_json = stableJson(body);
    d.review_sha256 = digest(d.review_json);
  }
  await page.addInitScript(
    (ids) => {
      let i = 0;
      crypto.randomUUID = () =>
        ids[i++]! as ReturnType<typeof crypto.randomUUID>;
    },
    [
      d.recheck_id,
      c.report.report_id,
      c.assessment.assessment_id,
      c.decisions[0]!.decision_id,
    ],
  );
  await page.route("**/api/**", async (route) => {
    const req = route.request(),
      path = new URL(req.url()).pathname;
    calls.push({
      method: req.method(),
      path,
      body: req.postDataJSON() as Record<string, unknown> | null,
    });
    const send = (v: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(v),
      });
    if (path.endsWith("/session"))
      return send({
        version: "service-access-0.3.0",
        role: reader ? "reader" : "engineer",
        permissions: rolePermissions[reader ? "reader" : "engineer"],
        individual_identity_verified: false,
        device_scope: "all_saved_devices",
      });
    if (path.includes("deterministic-selection/")) return send(c.selection);
    if (path.endsWith("/deterministic-rechecks") && req.method() === "POST") {
      if (behavior === "lost") return route.abort("failed");
      if (behavior === "refused")
        return send(
          { detail: "complete-mode partial parse fixture refusal" },
          409,
        );
      return send(d);
    }
    if (path.includes("/deterministic-rechecks/")) return send(d);
    if (path.endsWith("/deterministic-rechecks"))
      return send([
        {
          version: "source-deterministic-summary-0.2.0",
          mode: "policy_only_partial_diagnostic",
          coverage: "partial",
          recheck_id: d.recheck_id,
          patch_id: d.patch_id,
          draft_sha256: d.draft_sha256,
          before_analysis_id: d.before_analysis_id,
          review_sha256: d.review_sha256,
          created_at: d.intent.created_at,
          completed_at: d.outcome?.completed_at ?? null,
          execution_status: d.execution_status,
          status: d.status,
        },
      ]);
    if (path.endsWith("/risk-assessments") && req.method() === "GET")
      return send([
        sourceRiskSummary(sourceRiskAssessmentSchema.parse(c.assessment)),
      ]);
    if (path.includes("/risk-assessments")) return send(c.assessment);
    if (path.endsWith("/decisions") && req.method() === "GET")
      return send(
        c.decisions.map((x) => ({
          version: "source-evidence-decision-summary-0.5.0",
          decision_id: x.decision_id,
          patch_id: x.patch_id,
          report_id: x.report_id,
          report_sha256: x.report_sha256,
          decision_sha256: x.decision_sha256,
          created_at: x.created_at,
          verdict: x.request.verdict,
          service_role: x.service_role,
          individual_identity_verified: false,
          approved: false,
          applied: false,
        })),
      );
    if (path.includes("/decisions")) return send(c.decisions[0]);
    if (path.endsWith("/evidence-reports") && req.method() === "GET")
      return send([
        {
          version: "source-evidence-summary-0.5.0",
          mode: "policy_only_partial_diagnostic",
          coverage: "partial",
          report_id: c.report.report_id,
          patch_id: c.report.patch_id,
          draft_sha256: c.report.draft_sha256,
          before_analysis_id: c.report.before_analysis_id,
          review_sha256: c.report.review_sha256,
          created_at: c.report.created_at,
          selected_kinds: ["deterministic"],
          status: "needs_review",
        },
      ]);
    if (path.includes("/evidence-reports")) {
      const r = structuredClone(c.report);
      if (behavior === "corrupt") {
        r.deterministic.report.after.policy_findings[0]!.title =
          "Fabricated fixture observation";
        const { review_json: _j, review_sha256: _h, ...body } = r;
        r.review_json = stableJson(body);
        r.review_sha256 = digest(r.review_json);
      }
      return send(r);
    }
    return send([]);
  });
  await page.goto(
    `/ui/tests/browser/fixtures/partialDiagnostic.html?case=${index}`,
  );
  await expect(source(page)).toBeVisible();
  return { c, d, calls };
}
async function openJoint(page: Page) {
  await joint(page)
    .getByRole("button", { name: "Открыть совместный отчёт", exact: true })
    .click();
}
async function historyJoint(page: Page) {
  await openJoint(page);
  await joint(page)
    .getByRole("button", { name: /^Открыть совместный отчёт / })
    .click();
}
async function launch(page: Page, id: string, partial = true) {
  await source(page)
    .getByRole("button", { name: "Открыть перепроверку анализа", exact: true })
    .click();
  if (partial)
    await source(page)
      .getByLabel("Режим перепроверки анализа", { exact: true })
      .selectOption("partial");
  await source(page)
    .getByLabel("UUID сохранённого анализа до изменения", { exact: true })
    .fill(id);
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
  await source(page)
    .getByRole("button", {
      name: "Пересчитать исходный анализ до и после",
      exact: true,
    })
    .click();
}
for (const [i, c] of controls.cases.entries())
  test(`authored fixture saved chain ${c.vendor}/${c.partial_side}/critical=${c.critical_control}`, async ({
    page,
  }, info) => {
    const f = await setup(page, i);
    await source(page)
      .getByRole("button", {
        name: "Открыть перепроверку анализа",
        exact: true,
      })
      .click();
    await source(page)
      .getByRole("button", { name: /^Открыть перепроверку анализа / })
      .click();
    await expect(
      source(page).getByLabel("Частичная диагностика политик", { exact: true }),
    ).toBeVisible();
    await historyJoint(page);
    await expect(
      joint(page).getByText(
        "Совместный отчёт частичной диагностики сохранён — требуется рассмотрение",
        { exact: true },
      ),
    ).toBeVisible();
    await risk(page)
      .getByRole("button", {
        name: "Открыть приоритеты этого отчёта",
        exact: true,
      })
      .click();
    await risk(page)
      .getByRole("button", { name: /^Открыть оценку / })
      .click();
    await expect(
      risk(page).getByText(/Общий приоритет: недоступно/),
    ).toBeVisible();
    await expect(
      risk(page).getByRole("cell", { name: "подавлен", exact: true }),
    ).toHaveCount(5);
    if (c.critical_control)
      await expect(
        risk(page)
          .getByLabel("Применимые нижние границы приоритета")
          .getByText(/Критическая политика/),
      ).toBeVisible();
    expect(
      await page.evaluate(
        () =>
          document.documentElement.scrollWidth <=
          document.documentElement.clientWidth,
      ),
    ).toBe(true);
    await joint(page)
      .getByRole("button", {
        name: "Открыть рассмотрение этого отчёта",
        exact: true,
      })
      .click();
    await joint(page)
      .getByRole("button", { name: /^Открыть решение / })
      .first()
      .click();
    await expect(
      joint(page).getByLabel("Сохранённое решение по отчёту", { exact: true }),
    ).toBeVisible();
    expect(f.calls.every((x) => x.method === "GET")).toBe(true);
    expect(await page.locator("body").innerText()).not.toContain("Fabricated");
    if (i === 0 || c.critical_control)
      await page.screenshot({
        path: info.outputPath("authored-partial-diagnostic.png"),
        fullPage: true,
      });
  });
test("explicit mode emits only .2 and .5 and excludes optional children", async ({
  page,
}) => {
  const f = await setup(page);
  await launch(page, f.c.selection.before_analysis_id);
  await expect(
    source(page).getByLabel("Частичная диагностика политик", { exact: true }),
  ).toBeVisible();
  await openJoint(page);
  await joint(page)
    .getByLabel("Режим совместного отчёта", { exact: true })
    .selectOption("partial");
  for (const name of [
    "Исходный Forest",
    "Нейросетевая модель",
    "Сетевая проверка",
  ])
    await expect(
      joint(page).getByRole("combobox", { name, exact: true }),
    ).toBeDisabled();
  await joint(page)
    .getByRole("combobox", {
      name: "Исходные политики и сравнения",
      exact: true,
    })
    .selectOption(f.d.recheck_id);
  await joint(page)
    .getByRole("button", { name: "Сохранить совместный отчёт", exact: true })
    .click();
  await expect(
    joint(page).getByText(
      "Совместный отчёт частичной диагностики сохранён — требуется рассмотрение",
      { exact: true },
    ),
  ).toBeVisible();
  expect(
    f.calls.filter((x) => x.method === "POST").map((x) => x.body?.version),
  ).toEqual([
    "source-deterministic-request-0.2.0",
    "source-evidence-request-0.5.0",
  ]);
});
for (const state of ["pending_unknown", "failed", "lost", "refused"] as const)
  test(`partial request ${state} preserves intent and never retries POST`, async ({
    page,
  }) => {
    const f = await setup(page, 0, state);
    await launch(page, f.c.selection.before_analysis_id, state !== "refused");
    if (state === "lost" || state === "refused")
      await expect(page.getByRole("alert")).toBeVisible();
    else
      await expect(
        source(page).getByLabel("Результат перепроверки анализа", {
          exact: true,
        }),
      ).toBeVisible();
    await expect(
      source(page).getByRole("button", {
        name: "Пересчитать исходный анализ до и после",
        exact: true,
      }),
    ).toBeDisabled();
    await expect(
      source(page).getByLabel("Режим перепроверки анализа", { exact: true }),
    ).toBeDisabled();
    await source(page)
      .getByRole("button", {
        name: "Прочитать попытку перепроверки",
        exact: true,
      })
      .click();
    expect(f.calls.filter((x) => x.method === "POST")).toHaveLength(1);
    expect(f.calls.find((x) => x.method === "POST")!.body?.version).toBe(
      state === "refused"
        ? "source-deterministic-request-0.1.0"
        : "source-deterministic-request-0.2.0",
    );
    expect(f.calls.at(-2)?.path ?? "").not.toContain("/analyze");
  });
test("reader can read partial history without mutation controls", async ({
  page,
}) => {
  const f = await setup(page, 0, "completed", true);
  await historyJoint(page);
  await expect(
    joint(page).getByRole("button", {
      name: "Сохранить совместный отчёт",
      exact: true,
    }),
  ).toHaveCount(0);
  await risk(page)
    .getByRole("button", {
      name: "Открыть приоритеты этого отчёта",
      exact: true,
    })
    .click();
  await expect(
    risk(page).getByRole("button", {
      name: "Сохранить экспериментальный приоритет",
      exact: true,
    }),
  ).toHaveCount(0);
  expect(f.calls.every((x) => x.method === "GET")).toBe(true);
});
test("resealed full child projection is rejected before rendering", async ({
  page,
}) => {
  await setup(page, 0, "corrupt");
  await historyJoint(page);
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(
    joint(page).getByLabel("Результат совместного отчёта", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByText("Fabricated fixture observation")).toHaveCount(0);
});
