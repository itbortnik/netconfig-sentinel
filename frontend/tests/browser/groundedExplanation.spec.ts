import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const TOKEN = "browser-tests-service-token-32-characters-001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", { name: "Объяснение с источниками", exact: true });
const output = (page: Page) =>
  panel(page).locator('[aria-label="Серверное объяснение выбранных фактов"]');
const permission = (page: Page) =>
  panel(page).getByLabel("Разрешаю передачу этого контекста локальной модели");
const button = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Запросить серверное объяснение фактов",
    exact: true,
  });

async function prepare(page: Page, vendor = "cisco", rejection = false) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  const content =
    vendor === "cisco"
      ? "hostname grounded-owned\naaa new-model\n" +
        (rejection ? "ntp server 192.0.2.1\n" : "") +
        "ip ssh version 1\n"
      : "set system host-name grounded-owned\nset system services ssh protocol-version v1\n";
  await page.getByLabel("Текст конфигурации").fill(content);
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const analyzed = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" && item.url().endsWith("/analyze"),
  );
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  const analysis = await (await analyzed).json();
  await page
    .locator(".finding-button")
    .filter({ hasText: "management.ssh_version_1" })
    .click();
  await panel(page)
    .getByRole("combobox", { name: "Режим объяснения модели", exact: true })
    .selectOption("grounded");
  await expect(button(page)).toBeDisabled();
  return analysis;
}

for (const vendor of ["cisco", "juniper"]) {
  test(`owned ${vendor} closed explanation is source-bound and single-consent`, async ({
    page,
  }) => {
    let calls = 0;
    page.on("request", (request) => {
      if (/\/api\/v2\/findings\/[^/]+\/explain$/.test(request.url())) calls++;
    });
    const analysis = await prepare(page, vendor);
    expect(calls).toBe(0);
    await permission(page).check();
    const explained = page.waitForResponse((response) =>
      /\/api\/v2\/findings\/[^/]+\/explain$/.test(response.url()),
    );
    await button(page).click();
    expect((await explained).status()).toBe(200);
    await expect(output(page)).toBeVisible();
    await expect(output(page)).toContainText("Текст сформирован сервером");
    await expect(output(page)).toContainText("formal verification");
    await expect(output(page)).toContainText("not_stored_in_analysis");
    await expect(permission(page)).not.toBeChecked();
    await expect(button(page)).toBeDisabled();
    expect(calls).toBe(1);
    expect(
      await (
        await page.request.get(`/api/v1/analyses/${analysis.analysis_id}`, {
          headers,
        })
      ).json(),
    ).toEqual(analysis);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await panel(page)
      .getByRole("combobox", { name: "Режим объяснения модели", exact: true })
      .selectOption("legacy");
    await expect(output(page)).toHaveCount(0);
  });
}

test("mode changes consume consent without making a request", async ({
  page,
}) => {
  await prepare(page);
  await permission(page).check();
  await expect(button(page)).toBeEnabled();
  await panel(page)
    .getByRole("combobox", { name: "Режим объяснения модели", exact: true })
    .selectOption("legacy");
  await expect(permission(page)).not.toBeChecked();
  await panel(page)
    .getByRole("combobox", { name: "Режим объяснения модели", exact: true })
    .selectOption("grounded");
  await expect(button(page)).toBeDisabled();
});

test("provider's forbidden choice is rejected without a legacy fallback", async ({
  page,
}) => {
  const analysis = await prepare(page, "cisco", true);
  await permission(page).check();
  const response = page.waitForResponse((item) =>
    /\/api\/v2\/findings\/[^/]+\/explain$/.test(item.url()),
  );
  await button(page).click();
  expect((await response).status()).toBe(503);
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(output(page)).toHaveCount(0);
  await expect(permission(page)).not.toBeChecked();
  expect(
    await (
      await page.request.get(`/api/v1/analyses/${analysis.analysis_id}`, {
        headers,
      })
    ).json(),
  ).toEqual(analysis);
});

test("lost response makes one call and requires new explicit consent", async ({
  page,
}) => {
  await prepare(page);
  let calls = 0;
  await page.route("**/api/v2/findings/*/explain", async (route) => {
    calls++;
    const response = await route.fetch();
    expect(response.ok()).toBe(true);
    await route.abort("failed");
  });
  await permission(page).check();
  await button(page).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(output(page)).toHaveCount(0);
  await expect(permission(page)).not.toBeChecked();
  await expect(button(page)).toBeDisabled();
  expect(calls).toBe(1);
});

test("a modified projection with its old digest is not shown", async ({
  page,
}) => {
  await prepare(page);
  await page.route("**/api/v2/findings/*/explain", async (route) => {
    const response = await route.fetch();
    expect(response.ok()).toBe(true);
    const body = await response.json();
    const presentation = JSON.parse(body.projection_json);
    presentation.summary = "unsupported injected result";
    body.projection_json = JSON.stringify(presentation);
    await route.fulfill({ response, json: body });
  });
  await permission(page).check();
  await button(page).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(output(page)).toHaveCount(0);
  await expect(
    page.getByText("unsupported injected result", { exact: true }),
  ).toHaveCount(0);
});
