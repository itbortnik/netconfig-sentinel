import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const TOKEN = "browser-tests-service-token-32-characters-001";
type Form = "ios" | "set" | "blocks";
function source(form: Form, host: string, partial = false, small = false) {
  const address = host.startsWith("peer-") ? "192.0.2.10" : "192.0.2.99";
  const copies = small ? 100 : 1; // Denominator fixture, not additional devices.
  if (form === "ios")
    return (
      `hostname ${host}\nip ssh version 2\n` +
      `ntp server ${address}\n`.repeat(copies) +
      (partial ? "unknown OWNED_PRIVATE_MARKER\n" : "") +
      "end\n"
    );
  if (form === "set")
    return (
      `set system host-name ${host}\nset system services ssh\n` +
      `set system ntp server ${address}\n`.repeat(copies) +
      (partial ? "set unknown OWNED_PRIVATE_MARKER\n" : "")
    );
  return (
    `system {\n host-name ${host};\n services {\n  ssh;\n }\n ntp {\n` +
    `  server ${address};\n`.repeat(copies) +
    " }\n" +
    (partial ? " unknown OWNED_PRIVATE_MARKER;\n" : "") +
    "}\n"
  );
}
async function connect(page: Page) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
}
async function upload(page: Page, content: string) {
  await page.getByLabel("Выбрать конфигурацию").setInputFiles({
    name: "owned-measured.cfg",
    mimeType: "text/plain",
    buffer: Buffer.from(content),
  });
  const saved = page.waitForResponse(
    (r) =>
      r.request().method() === "POST" &&
      r.url().endsWith("/api/v1/configurations"),
  );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const response = await saved;
  expect(response.status()).toBe(201);
  await expect(
    page.getByRole("button", { name: "Анализировать снимок", exact: true }),
  ).toBeVisible();
  return response.json();
}
async function selectPeers(page: Page, form: Form, suffix: string) {
  await page
    .getByText("Метки группы сравнения (необязательно)", { exact: true })
    .click();
  await page.getByLabel("Роль устройства", { exact: true }).fill("edge");
  await page.getByLabel("Класс площадки", { exact: true }).fill("branch");
  await page
    .getByLabel("Профиль сервиса", { exact: true })
    .fill("owned-measured");
  for (let n = 0; n < 3; n++) {
    await page.getByRole("button", { name: "Новое", exact: true }).click();
    await upload(page, source(form, `peer-${suffix}-${n}`));
    await page
      .getByRole("button", { name: "Добавить в группу сравнения", exact: true })
      .click();
  }
  await page.getByRole("button", { name: "Новое", exact: true }).click();
}

for (const form of ["ios", "set", "blocks"] as const) {
  for (const scenario of ["completed", "partial", "below-tolerance"] as const) {
    test(`measured peers ${form} ${scenario}: actual uploads, sources and preserved history`, async ({
      page,
    }) => {
      await connect(page);
      const suffix = `${test.info().project.name}-${Date.now()}`;
      await selectPeers(page, form, suffix);
      const target = await upload(
        page,
        source(
          form,
          `target-${suffix}`,
          scenario !== "completed",
          scenario === "below-tolerance",
        ),
      );
      await expect(
        page.getByLabel("Область сравнения", { exact: true }),
      ).toHaveValue("0.1.0");
      await page
        .getByLabel("Область сравнения", { exact: true })
        .selectOption("0.3.0");
      const saved = page.waitForResponse(
        (r) => r.request().method() === "POST" && r.url().endsWith("/analyze"),
      );
      await page
        .getByRole("button", { name: "Анализировать снимок", exact: true })
        .click();
      const response = await saved;
      expect(response.status()).toBe(201);
      expect(response.request().postDataJSON().comparison_version).toBe(
        "0.3.0",
      );
      const result = await response.json();
      expect(result.version).toBe("analysis-api-0.5.0");
      const report = result.comparison.peer_evaluation;
      expect(report.coverage).toEqual(target.parser_coverage);
      expect(result.statistical).toBeNull();
      await expect(
        page.getByRole("heading", { name: "Находки и доказательства" }),
      ).toBeVisible();
      await page
        .getByText("Входы сравнения и профиль группы", { exact: true })
        .click();
      const summary = page.locator(".analysis-summary");
      await expect(summary).toContainText("Измеренное сравнение 0.3.0");
      await expect(summary).toContainText(
        `Неразобранных: ${report.coverage.unparsed_units} из ${report.coverage.command_units} учитываемых строк`,
      );
      await expect(summary).toContainText(
        "Это не доверие парсера, не вероятность ошибки",
      );
      await expect(summary).not.toContainText("Дефицит доверия парсера:");
      if (scenario === "completed") {
        expect(report.status).toBe("completed");
        expect(report.compared_features).toHaveLength(19);
        expect(report.skipped_features).toEqual([]);
        expect(result.risk).not.toBeNull();
        await expect(summary).toContainText("Сравнено: 19");
      } else {
        expect(report.status).toBe("partial");
        expect(report.compared_features).toEqual([]);
        expect(report.skipped_features).toHaveLength(19);
        expect(result.risk).toBeNull();
        await expect(summary).toContainText("Сравнение свойств пропущено");
        await expect(summary).toContainText("Пропущено из-за разбора: 19");
        expect(1 - target.canonical.parser_confidence).not.toBe(
          report.coverage.unparsed_fraction,
        );
      }
      if (scenario === "below-tolerance") {
        expect(report.coverage.unparsed_fraction).toBeGreaterThan(0);
        expect(report.coverage.unparsed_fraction).toBeLessThanOrEqual(0.05);
        expect(report.findings).toEqual([]);
      } else {
        const finding = report.findings[0];
        expect(finding.model_version).toBe("peer-baseline-0.3.0");
        expect(finding.category).toBe(
          scenario === "partial"
            ? "baseline.parser.unparsed_fraction_high"
            : "baseline.management.ntp_servers_deviation",
        );
        await page.getByLabel("Поиск по находкам").fill(finding.category);
        await page.locator(".finding-button").first().click();
        const explained = page.waitForResponse(
          (r) =>
            r.request().method() === "POST" && r.url().endsWith("/explain"),
        );
        await page
          .getByRole("button", {
            name: "Показать источники объяснения",
            exact: true,
          })
          .click();
        const contextResponse = await explained;
        expect(contextResponse.status()).toBe(200);
        const context = await contextResponse.json();
        expect(context.knowledge_version).toBe("project-knowledge-0.4.0");
        expect(context.documents[0].section).toBe("measured-parser-coverage");
        expect(context.provider).toBe("deterministic_local");
        expect(context.explanation.formal_verification).toBe("not_run");
        await expect(
          page.getByRole("region", { name: "Объяснение с источниками" }),
        ).toContainText("project-knowledge-0.4.0");
        const reread = await page.request.get(
          `/api/v1/analyses/${result.analysis_id}`,
          { headers: { Authorization: `Bearer ${TOKEN}` } },
        );
        expect(await reread.json()).toEqual(result);
      }
      const layout = await page.evaluate(() => ({
        viewport: innerWidth,
        scroll: document.documentElement.scrollWidth,
      }));
      expect(layout.scroll).toBeLessThanOrEqual(layout.viewport);
      expect(
        await page.evaluate(() => ({
          local: { ...localStorage },
          session: { ...sessionStorage },
        })),
      ).toEqual({ local: {}, session: {} });
      await page.reload();
      await connect(page);
      await expect(
        page.getByLabel("Область сравнения", { exact: true }),
      ).toHaveValue("0.1.0");
      await page.getByRole("button", { name: "Анализы", exact: true }).click();
      await page.locator(".history-item").first().click();
      await page
        .getByText("Входы сравнения и профиль группы", { exact: true })
        .click();
      await expect(page.locator(".analysis-summary")).toContainText(
        "Измеренное сравнение 0.3.0",
      );
      await expect(page.locator(".analysis-summary")).toContainText(
        `Неразобранных: ${report.coverage.unparsed_units} из ${report.coverage.command_units} учитываемых строк`,
      );
    });
  }
}

test("legacy missing measurement refuses 0.3 before any analyze POST", async ({
  page,
}) => {
  await connect(page);
  await selectPeers(page, "ios", `${test.info().project.name}-${Date.now()}`);
  await page.route("**/api/v1/configurations", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch();
    const snapshot = await response.json();
    // Synthetic legacy wire shape; the real backend report remains unchanged.
    delete snapshot.parser_coverage;
    await route.fulfill({ response, json: snapshot });
  });
  await upload(page, source("ios", "target-legacy-measurement"));
  let analyzes = 0;
  page.on("request", (r) => {
    if (r.method() === "POST" && r.url().endsWith("/analyze")) analyzes++;
  });
  await page
    .getByLabel("Область сравнения", { exact: true })
    .selectOption("0.3.0");
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText(
    "Исторические снимки не пересчитываются автоматически",
  );
  expect(analyzes).toBe(0);
});
