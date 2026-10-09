import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { AnalysisResult } from "../../src/contracts";
import type {
  ConfigurationModelRun,
  RunConfigurationModel,
} from "../../src/configurationModels";

const TOKEN = "browser-tests-service-token-32-characters-001";
const PIN = "a".repeat(64);
const headers = { Authorization: `Bearer ${TOKEN}` };
async function setup(page: Page, partial = false) {
  await page.goto("/ui/");
  const snapshot = await page.request.post("/api/v1/configurations", {
    headers,
    data: {
      device_id: crypto.randomUUID(),
      filename: "configuration-model.cfg",
      content: `hostname owned-model-${Date.now()}\n${partial ? "unknown private-command\n" : ""}`,
      retain_original_source: true,
    },
  });
  expect(snapshot.status()).toBe(201);
  const source = await snapshot.json();
  const response = await page.request.post(
    `/api/v1/configurations/${source.configuration_id}/analyze`,
    { headers },
  );
  expect(response.status()).toBe(201);
  return { analysis: (await response.json()) as AnalysisResult, source };
}
async function connectAndOpen(
  page: Page,
  analysis: AnalysisResult,
  reader = false,
) {
  await page
    .getByLabel("API-токен", { exact: true })
    .fill(reader ? "browser-tests-reader-service-token-000001" : TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: analysis.analysis_id.slice(0, 8) })
    .click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
}
function syntheticResult(
  analysis: AnalysisResult,
  source: { created_at: string },
  request: RunConfigurationModel,
): ConfigurationModelRun {
  return {
    version: "configuration-model-run-0.1.0",
    inference_id: request.inference_id,
    analysis_id: analysis.analysis_id,
    source: {
      configuration_id: analysis.configuration_id,
      device_id: analysis.device_id,
      source_sha256: analysis.source_sha256,
      created_at: source.created_at,
    },
    analysis_sha256: PIN,
    model_sha256: PIN,
    total_lines: 1,
    created_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    status: "completed",
    intent_sha256: PIN,
    outcome_sha256: PIN,
    attempt_limit: 1,
    risk_fused: false,
    requires_human_review: true,
    report: {
      version: "configuration-inference-0.1.0",
      runtime_torch_version: "synthetic-browser-fixture",
      sanitization_version: "config-sanitizer-0.1.0",
      risk_fused: false,
      calibrated: false,
      quality_evaluated: false,
      production_quality_proven: false,
      model: {
        version: "config-model-card-0.1.0",
        kind: "native",
        model_sha256: PIN,
        training_format: "multitask-training-0.1.0",
        report_sha256: PIN,
        encoder_sha256: PIN,
        tokenizer_sha256: PIN,
        source_manifest_sha256: null,
        train_fingerprint: PIN,
        selection_fingerprint: PIN,
        classes: ["telnet_enabled"],
        enabled_heads: {
          anomaly: true,
          category: true,
          localization: true,
          severity: false,
          contrastive: false,
        },
        parameter_count: 200,
        trainable_parameters: 100,
        train_examples: 4,
        selection_examples: 2,
        target_semantics: "injected_mutation",
        external_pretraining_exposure: "not_applicable",
        status: "experimental",
        calibrated: false,
        production_quality_proven: false,
        activated: false,
      },
      prediction: {
        raw_source_sha256: analysis.source_sha256,
        sanitized_source_sha256: PIN,
        model_sha256: PIN,
        total_lines: 1,
        anomaly_score: 0.3,
        category_scores: { telnet_enabled: 0.4 },
        severity_scores: null,
        line_scores: [0.2],
        block_attention: [1],
        embedding_sha256: null,
        embedding_dimensions: 0,
        replacement_counts: {},
        calibrated: false,
      },
    },
  };
}
for (const mode of ["normal", "lost", "tampered"] as const) {
  test(`synthetic configuration model ${mode}: consent, immutable history and no POST retry`, async ({
    page,
  }) => {
    const { analysis, source } = await setup(page);
    let posts = 0,
      gets = 0,
      saved: ConfigurationModelRun | null = null;
    await page.route("**/api/v1/configuration-model-runs**", async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith("/capabilities"))
        return route.fulfill({
          json: {
            version: "configuration-model-capabilities-0.1.0",
            inference: "configured",
            model_sha256: PIN,
            health_checked: false,
          },
        });
      if (route.request().method() === "POST") {
        posts++;
        const options = route.request().postDataJSON() as RunConfigurationModel;
        expect(options.analysis_id).toBe(analysis.analysis_id);
        expect(options.source_sha256).toBe(analysis.source_sha256);
        expect(options.allow_local_model_context).toBe(true);
        saved = syntheticResult(analysis, source, options);
        if (mode === "lost")
          return route.fulfill({
            status: 503,
            json: { detail: "Owned lost response fixture" },
          });
        if (mode === "tampered")
          return route.fulfill({
            json: { ...saved, analysis_id: crypto.randomUUID() },
          });
        return route.fulfill({ status: 201, json: saved });
      }
      if (url.searchParams.has("analysis_id"))
        return route.fulfill({ json: saved ? [saved] : [] });
      gets++;
      return route.fulfill({ json: saved });
    });
    await connectAndOpen(page, analysis);
    const panel = page.getByRole("region", { name: "Конфигурационная модель" });
    const consent = panel.getByRole("checkbox");
    const start = panel.getByRole("button", {
      name: "Запустить конфигурационную модель",
      exact: true,
    });
    await expect(consent).not.toBeChecked();
    await expect(start).toBeDisabled();
    expect(posts).toBe(0);
    await consent.check();
    await start.click();
    if (mode !== "normal") {
      await expect(
        panel.getByText(/Итог запроса не подтверждён/),
      ).toBeVisible();
      await expect(
        panel.getByText("Сохранённый результат: completed"),
      ).toHaveCount(0);
      await panel
        .getByRole("button", {
          name: "Проверить сохранённую попытку",
          exact: true,
        })
        .click();
    }
    await expect(
      panel.getByText("Сохранённый результат: completed"),
    ).toBeVisible();
    await expect(
      panel.getByText(/Некалиброванный anomaly score:/),
    ).toBeVisible();
    expect(posts).toBe(1);
    expect(gets).toBe(mode === "normal" ? 0 : 1);
    expect(
      (
        await page.request.get(`/api/v1/analyses/${analysis.analysis_id}`, {
          headers,
        })
      ).ok(),
    ).toBe(true);
    const unchanged = await page.request.get(
      `/api/v1/analyses/${analysis.analysis_id}`,
      { headers },
    );
    expect(await unchanged.json()).toEqual(analysis);
    await page.reload();
    await connectAndOpen(page, analysis);
    await panel.getByText(/История конфигурационной модели \(1/).click();
    await panel
      .getByRole("button", { name: new RegExp(saved!.inference_id) })
      .click();
    await expect(
      panel.getByText("Сохранённый результат: completed"),
    ).toBeVisible();
    await expect(panel.getByRole("checkbox")).not.toBeChecked();
    expect(posts).toBe(1);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  });
}
test("reader can read history but never receives model launch controls", async ({
  page,
}) => {
  const { analysis } = await setup(page);
  await page.route("**/api/v1/configuration-model-runs/capabilities", (route) =>
    route.fulfill({
      json: {
        version: "configuration-model-capabilities-0.1.0",
        inference: "configured",
        model_sha256: PIN,
        health_checked: false,
      },
    }),
  );
  await connectAndOpen(page, analysis, true);
  const panel = page.getByRole("region", { name: "Конфигурационная модель" });
  await expect(panel.getByText(/Модель настроена/)).toBeVisible();
  await expect(panel.getByRole("checkbox")).toHaveCount(0);
  await expect(
    panel.getByRole("button", { name: "Запустить конфигурационную модель" }),
  ).toHaveCount(0);
});
test("partial parsing and disabled configuration do not offer inference", async ({
  page,
}) => {
  const { analysis } = await setup(page, true);
  await connectAndOpen(page, analysis);
  const panel = page.getByRole("region", { name: "Конфигурационная модель" });
  await expect(
    panel.getByText("Конфигурационная модель отключена."),
  ).toBeVisible();
  await expect(
    panel.getByText("Запуск недоступен при неполном разборе."),
  ).toBeVisible();
  await expect(panel.getByRole("checkbox")).toHaveCount(0);
});
