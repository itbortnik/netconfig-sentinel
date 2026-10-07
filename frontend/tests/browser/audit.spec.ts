import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const tokens = {
  admin: "browser-tests-service-token-32-characters-001",
  reader: "browser-tests-reader-service-token-000001",
  engineer: "browser-tests-engineer-service-token-000001",
};
const headers = (role: keyof typeof tokens = "admin") => ({
  Authorization: `Bearer ${tokens[role]}`,
});
async function connect(page: Page, role: keyof typeof tokens = "admin") {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(tokens[role]);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
}

test("administrator reads real encrypted operation bindings with stable pagination and no browser storage", async ({
  page,
}) => {
  await connect(page);
  for (let i = 0; i < 25; i++)
    expect(
      (
        await page.request.get("/api/v1/session", { headers: headers() })
      ).status(),
    ).toBe(200);
  const panel = page.getByRole("region", {
    name: "Журнал операций",
    exact: true,
  });
  const firstResponse = page.waitForResponse(
    (response) =>
      response.url().includes("/api/v1/operation-audit?") &&
      response.request().method() === "GET",
  );
  await panel
    .getByRole("button", { name: "Открыть журнал", exact: true })
    .click();
  const first = await (await firstResponse).json();
  await expect(panel.locator(".audit-record")).toHaveCount(20);
  await panel.locator(".audit-record").first().click();
  await expect(
    panel.getByRole("region", { name: "Детали операции" }),
  ).toContainText("Успешный ответ API");
  await expect(
    panel.getByRole("region", { name: "Детали операции" }),
  ).toContainText("service-access-0.2.0");
  const secondResponse = page.waitForResponse(
    (response) =>
      response.url().includes("before=") &&
      response.url().includes("/operation-audit?"),
  );
  await expect(
    panel.getByRole("button", { name: "Более ранние", exact: true }),
  ).toBeEnabled();
  await panel
    .getByRole("button", { name: "Более ранние", exact: true })
    .click();
  const second = await (await secondResponse).json();
  const ids = new Set(
    first.records.map(
      (item: { receipt: { operation_id: string } }) =>
        item.receipt.operation_id,
    ),
  );
  expect(
    second.records.every(
      (item: { receipt: { operation_id: string } }) =>
        !ids.has(item.receipt.operation_id),
    ),
  ).toBe(true);
  await expect(
    panel.getByRole("region", { name: "Детали операции" }),
  ).toHaveCount(0);
  await panel
    .getByRole("button", { name: "Новые записи", exact: true })
    .click();
  await expect(panel.locator(".audit-record")).toHaveCount(20);
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  await expect(panel).toHaveCount(0);
});

for (const role of ["reader", "engineer"] as const) {
  test(`${role} has no journal controls and direct requests are denied`, async ({
    page,
  }) => {
    await connect(page, role);
    await expect(
      page.getByRole("region", { name: "Журнал операций", exact: true }),
    ).toHaveCount(0);
    const denied = await page.request.get("/api/v1/operation-audit", {
      headers: headers(role),
    });
    expect(denied.status()).toBe(403);
    expect(denied.headers()["x-operation-id"]).toMatch(/^[a-f0-9-]{36}$/);
  });
}

test("an incorrectly hashed receipt is rejected instead of displayed as a verified outcome", async ({
  page,
}) => {
  await connect(page);
  const saved = await page.request.get("/api/v1/session", {
    headers: headers(),
  });
  const id = saved.headers()["x-operation-id"]!;
  const original = await (
    await page.request.get(`/api/v1/operation-audit/${id}`, {
      headers: headers(),
    })
  ).json();
  await page.route(`**/api/v1/operation-audit/${id}`, (route) =>
    route.fulfill({
      json: {
        ...original,
        completion: { ...original.completion, receipt_sha256: "f".repeat(64) },
      },
    }),
  );
  const panel = page.getByRole("region", {
    name: "Журнал операций",
    exact: true,
  });
  await panel
    .getByRole("button", { name: "Открыть журнал", exact: true })
    .click();
  await panel
    .getByRole("button", { name: `Операция ${id}`, exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText(
    "Привязка записи журнала не подтверждена",
  );
  await expect(
    panel.getByRole("region", { name: "Детали операции" }),
  ).toHaveCount(0);
});

test("synthetic pending detail remains explicitly unconfirmed without promoting the original response", async ({
  page,
}) => {
  await connect(page);
  const saved = await page.request.get("/api/v1/session", {
    headers: headers(),
  });
  const id = saved.headers()["x-operation-id"]!;
  const original = await (
    await page.request.get(`/api/v1/operation-audit/${id}`, {
      headers: headers(),
    })
  ).json();
  await page.route(`**/api/v1/operation-audit/${id}`, (route) =>
    route.fulfill({
      json: {
        ...original,
        completion: null,
        outcome: "pending",
        authorization: "not_checked",
      },
    }),
  );
  const panel = page.getByRole("region", {
    name: "Журнал операций",
    exact: true,
  });
  await panel
    .getByRole("button", { name: "Открыть журнал", exact: true })
    .click();
  await panel
    .getByRole("button", { name: `Операция ${id}`, exact: true })
    .click();
  const detail = panel.getByRole("region", { name: "Детали операции" });
  await expect(detail).toContainText("Итог не подтверждён");
  await expect(detail).toContainText("Изменение могло сохраниться");
  await expect(detail).not.toContainText("Успешный ответ API");
});
