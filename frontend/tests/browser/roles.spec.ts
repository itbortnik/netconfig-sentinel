import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { AnalysisResult } from "../../src/contracts";

const tokens = {
  admin: "browser-tests-service-token-32-characters-001",
  reader: "browser-tests-reader-service-token-000001",
  analyst: "browser-tests-analyst-service-token-000001",
  engineer: "browser-tests-engineer-service-token-000001",
};
const headers = (role: keyof typeof tokens) => ({
  Authorization: "Bearer " + tokens[role],
});
async function connect(page: Page, role: keyof typeof tokens) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(tokens[role]);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
}
async function savedAnalysis(page: Page): Promise<AnalysisResult> {
  const device = await page.evaluate(() => crypto.randomUUID());
  const response = await page.request.post("/api/v1/configurations", {
    headers: headers("admin"),
    data: {
      device_id: device,
      filename: "roles.cfg",
      content: `hostname roles-${Date.now()}\n`,
    },
  });
  expect(response.status()).toBe(201);
  const snapshot = await response.json();
  const analyzed = await page.request.post(
    `/api/v1/configurations/${snapshot.configuration_id}/analyze`,
    { headers: headers("admin") },
  );
  expect(analyzed.status()).toBe(201);
  return analyzed.json();
}
async function openAnalysis(page: Page, result: AnalysisResult) {
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: result.analysis_id.slice(0, 8) })
    .click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
}
test("reader sees real history and local sources but no write or model controls", async ({
  page,
}) => {
  await page.goto("/ui/");
  const result = await savedAnalysis(page);
  await page.route("**/api/v1/explanation-capabilities", (route) =>
    route.fulfill({
      json: {
        version: "explanation-capabilities-0.1.0",
        local_model: "configured",
        model_health_checked: false,
        transport: "literal_loopback_only",
        explicit_request_permission_required: true,
      },
    }),
  );
  await connect(page, "reader");
  await expect(page.getByLabel("Роль сессии")).toContainText("только просмотр");
  await expect(page.getByLabel("Текст конфигурации")).toHaveCount(0);
  await openAnalysis(page, result);
  await expect(
    page.getByRole("button", { name: "Анализировать снимок", exact: true }),
  ).toBeDisabled();
  await expect(page.getByLabel("Комментарий к оценке")).toBeDisabled();
  await expect(
    page.getByRole("button", {
      name: "Сохранить черновик объектов",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", {
      name: "Запросить черновик у локальной модели",
      exact: true,
    }),
  ).toHaveCount(0);
  await page
    .getByRole("button", { name: "Показать источники объяснения", exact: true })
    .click();
  await expect(page.locator(".knowledge-source")).toHaveCount(1);
  const denied = await page.request.post("/api/v1/configurations", {
    headers: headers("reader"),
    data: { role: "admin" },
  });
  expect(denied.status()).toBe(403);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
});
test("analyst uploads and analyzes while engineer operations stay disabled", async ({
  page,
}) => {
  await connect(page, "analyst");
  await expect(page.getByLabel("Роль сессии")).toContainText("анализ");
  await page
    .getByLabel("Текст конфигурации")
    .fill(`hostname analyst-${Date.now()}\n`);
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
  await expect(page.getByLabel("Комментарий к оценке")).toBeDisabled();
  const denied = await page.request.post("/api/v1/models/isolation-forest", {
    headers: headers("analyst"),
    data: {},
  });
  expect(denied.status()).toBe(403);
});
test("engineer assessment is saved, then reader reconnect clears write permissions", async ({
  page,
}) => {
  await page.goto("/ui/");
  const result = await savedAnalysis(page);
  await connect(page, "engineer");
  await openAnalysis(page, result);
  await page
    .getByLabel("Комментарий к оценке")
    .fill("Synthetic role-scoped assessment.");
  await page
    .getByRole("button", { name: "Сохранить оценку", exact: true })
    .click();
  await expect(page.locator(".feedback-history li")).toHaveCount(1);
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  await connect(page, "reader");
  await openAnalysis(page, result);
  await expect(page.locator(".feedback-history li")).toHaveCount(1);
  await expect(page.getByLabel("Комментарий к оценке")).toBeDisabled();
  expect(
    await (
      await page.request.get(`/api/v1/analyses/${result.analysis_id}`, {
        headers: headers("reader"),
      })
    ).json(),
  ).toEqual(result);
});
test("invalid session permissions cannot fall back to administrator login", async ({
  page,
}) => {
  await page.route("**/api/v1/session", (route) =>
    route.fulfill({
      json: {
        version: "service-access-0.1.0",
        role: "reader",
        permissions: ["read", "train_model"],
        individual_identity_verified: false,
        device_scope: "all_saved_devices",
      },
    }),
  );
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(tokens.reader);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText(
    "не соответствует поддерживаемому контракту",
  );
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByLabel("Текст конфигурации")).toHaveCount(0);
});
