import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const TOKEN = "browser-tests-service-token-32-characters-001";
const option = (page: Page) =>
  page.getByRole("checkbox", {
    name: "Разбирать секции Cisco route-map",
    exact: true,
  });
const source =
  "hostname owned-route-map\nroute-map EXPORT permit 10\n match ip address prefix-list TRUSTED\n!\nroute-map EXPORT deny 20\n set metric 50\n!\n";
async function connect(page: Page) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
}
async function save(page: Page) {
  const response = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" &&
      item.url().endsWith("/api/v1/configurations"),
  );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  return response;
}

test("explicit Cisco profile renders configured order, compares snapshots and preserves old history", async ({
  page,
}) => {
  await connect(page);
  await expect(option(page)).not.toBeChecked();
  await page.getByLabel("Текст конфигурации").fill(source);
  const legacyResponse = await save(page);
  expect(legacyResponse.status()).toBe(201);
  const legacy = await legacyResponse.json();
  expect(legacy.canonical.schema_version).toBe("1.1");
  expect(legacy.canonical.route_maps).toBeUndefined();
  await page.getByLabel("Текст конфигурации").fill(source);
  await option(page).check();
  const beforeResponse = await save(page);
  expect(beforeResponse.status()).toBe(201);
  const before = await beforeResponse.json();
  expect(before.canonical.schema_version).toBe("1.2");
  expect(before.parser_coverage.adapter_version).toBe(
    "cisco-ios-route-maps-source-lines-0.1.0",
  );
  await expect(option(page)).not.toBeChecked();
  await page.getByText("Route-map (1)", { exact: true }).click();
  const snapshot = page.locator(".snapshot-panel");
  await expect(snapshot).toContainText("Номер 10 · permit");
  await expect(snapshot).toContainText("Номер 20 · deny");
  await expect(snapshot).toContainText("TRUSTED");
  await expect(snapshot).toContainText("влияние на сеть не проверены");
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  const afterSource = source
    .replace("EXPORT permit 10", "EXPORT permit 20")
    .replace("EXPORT deny 20", "EXPORT deny 10");
  await page.getByLabel("Текст конфигурации").fill(afterSource);
  await option(page).check();
  const afterResponse = await save(page);
  expect(afterResponse.status()).toBe(201);
  const after = await afterResponse.json();
  await page
    .getByRole("button", { name: "Показать различия объектов", exact: true })
    .click();
  const diff = page.getByRole("region", { name: "Сравнение снимков" });
  await expect(diff).toContainText("Route-map");
  await expect(diff).toContainText("Изменено: 1");
  for (const saved of [legacy, before, after]) {
    const stored = await page.request.get(
      `/api/v1/configurations/${saved.configuration_id}`,
      { headers: { Authorization: `Bearer ${TOKEN}` } },
    );
    expect(await stored.json()).toEqual(saved);
  }
  const layout = await page.evaluate(() => ({
    viewport: innerWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(layout.scroll).toBeLessThanOrEqual(layout.viewport);
});

test("profile choice resets with edited inputs and partial syntax stays visible", async ({
  page,
}) => {
  await connect(page);
  await option(page).check();
  await page.getByLabel("Имя файла", { exact: true }).fill("another.cfg");
  await expect(option(page)).not.toBeChecked();
  await option(page).check();
  await page
    .getByLabel("UUID устройства", { exact: true })
    .fill("00000000-0000-0000-0000-000000000012");
  await expect(option(page)).not.toBeChecked();
  await page
    .getByLabel("Текст конфигурации")
    .fill(source.replace("!\nroute-map", "!\n continue 20\nroute-map"));
  await option(page).check();
  const response = await save(page);
  expect(response.status()).toBe(201);
  const current = await response.json();
  expect(current.canonical.route_maps[0].normalization_complete).toBe(false);
  expect(current.parser_coverage.unparsed_units).toBe(1);
  await page.getByText("Route-map (1)", { exact: true }).click();
  await expect(page.locator(".snapshot-panel")).toContainText(
    "Частичный разбор route-map",
  );
  await option(page).check();
  await page.getByLabel("Выбрать конфигурацию").setInputFiles({
    name: "owned-junos.conf",
    mimeType: "text/plain",
    buffer: Buffer.from("set system host-name owned\n"),
  });
  await expect(option(page)).not.toBeChecked();
  await option(page).check();
  const refused = await save(page);
  expect(refused.status()).toBe(400);
  await expect(page.getByRole("alert").first()).toBeVisible();
});
