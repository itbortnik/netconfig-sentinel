import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { ConfigurationSnapshot } from "../../src/contracts";

const TOKEN = "browser-tests-service-token-32-characters-001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", { name: "Сравнение снимков" });
async function connect(page: Page) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
}
async function upload(
  page: Page,
  content: string,
  device?: string,
): Promise<ConfigurationSnapshot> {
  if (device)
    await page.getByLabel("UUID устройства", { exact: true }).fill(device);
  await page.getByLabel("Текст конфигурации").fill(content);
  const response = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" &&
      item.url().endsWith("/configurations"),
  );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const snapshot = (await (await response).json()) as ConfigurationSnapshot;
  await expect(
    page.getByRole("button", { name: "Выбрать для diff", exact: true }),
  ).toBeEnabled();
  return snapshot;
}
async function pair(page: Page) {
  const host = `diff-${test.info().project.name}-${Date.now()}`;
  const before = await upload(page, `hostname ${host}\n`);
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  const after = await upload(
    page,
    `hostname ${host}\nntp server 192.0.2.1\n`,
    before.device_id,
  );
  return { before, after };
}
async function compare(page: Page) {
  await page
    .getByRole("button", { name: "Показать различия объектов", exact: true })
    .click();
}

test("device accounts show explicit rights and metadata differences without supported credential values", async ({
  page,
}) => {
  await connect(page);
  const host = `accounts-${test.info().project.name}-${Date.now()}`;
  const before = await upload(
    page,
    `hostname ${host}\nusername admin privilege 1 secret 9 PRIVATE-OLD\n`,
  );
  expect(JSON.stringify(before)).not.toContain("PRIVATE");
  await page.getByText("Пользователи устройства (1)", { exact: true }).click();
  await expect(page.locator(".snapshot-panel")).toContainText("Privilege: 1");
  await expect(page.locator(".snapshot-panel")).not.toContainText("PRIVATE");
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  const after = await upload(
    page,
    `hostname ${host}\nusername admin privilege 15 secret 9 PRIVATE-NEW\n`,
    before.device_id,
  );
  expect(JSON.stringify(after)).not.toContain("PRIVATE");
  await compare(page);
  await expect(panel(page)).toContainText("Локальные пользователи устройства");
  await expect(panel(page)).toContainText("Изменено: 1");
  await expect(panel(page)).not.toContainText("PRIVATE");
});

test("real Cisco object changes retain side-specific anchors, render text safely and leave snapshots unchanged", async ({
  page,
}) => {
  await connect(page);
  const host = `diff-cisco-${Date.now()}`;
  const before = await upload(
    page,
    `hostname ${host}\ninterface Gi0/1\n description OLD\n!\ninterface Gi0/2\n shutdown\n!\n`,
  );
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  const untrusted =
    '<img src=x onerror="window.diffExecuted=1">' + "x".repeat(1200);
  const after = await upload(
    page,
    `hostname ${host}\ninterface Gi0/1\n description ${untrusted}\n!\ninterface Gi0/3\n shutdown\n!\n`,
    before.device_id,
  );
  await compare(page);
  await expect(panel(page)).toContainText(
    "Добавлено: 1 · Удалено: 1 · Изменено: 1",
  );
  await expect(panel(page).locator(".diff-change")).toHaveCount(3);
  await expect(panel(page)).toContainText(JSON.stringify(untrusted));
  await expect(panel(page).locator("img")).toHaveCount(0);
  expect(await page.evaluate(() => "diffExecuted" in window)).toBe(false);
  const removed = panel(page)
    .locator(".diff-change")
    .filter({ hasText: "Удалён" });
  await expect(removed.locator(".diff-side").nth(1)).toContainText(
    "Объект отсутствует",
  );
  await expect(
    removed.locator(".diff-side").nth(1).locator("details"),
  ).toHaveCount(0);
  await removed.locator("summary").click();
  await expect(removed.locator(".diff-side").first()).toContainText("Строки 5");
  for (const snapshot of [before, after]) {
    const stored = await page.request.get(
      `/api/v1/configurations/${snapshot.configuration_id}`,
      { headers },
    );
    expect(await stored.json()).toEqual(snapshot);
  }
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  if (test.info().project.name === "desktop") {
    for (const width of [1150, 1024, 800]) {
      await page.setViewportSize({ width, height: 720 });
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      ).toBe(true);
    }
  }
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: after.configuration_id.slice(0, 8) })
    .click();
  await expect(panel(page)).toContainText("До: Не выбран");
  await expect(panel(page).locator(".diff-result")).toHaveCount(0);
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
});

test("partial JunOS snapshots expose excluded unknown commands without claiming raw equality", async ({
  page,
}) => {
  await connect(page);
  const host = `diff-junos-${Date.now()}`;
  const before = await upload(
    page,
    `set system host-name ${host}\nset unknown PRIVATE-DIFF-BEFORE\n`,
  );
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  await upload(
    page,
    `set system host-name ${host}\nset unknown PRIVATE-DIFF-AFTER\n`,
    before.device_id,
  );
  await compare(page);
  await expect(panel(page)).toContainText("Неполная область сравнения");
  await expect(panel(page)).toContainText(
    "Изменения неизвестных команд не показаны",
  );
  await expect(panel(page)).toContainText(
    "В сравниваемых объектах различий нет",
  );
  await expect(panel(page)).toContainText("Исходные SHA-256 различаются");
  await expect(panel(page)).not.toContainText("PRIVATE-DIFF");
});

test("current, foreign and future references are refused locally before a comparison request", async ({
  page,
}) => {
  await connect(page);
  let requests = 0;
  page.on("request", (request) => {
    if (request.url().includes("/diff?")) requests++;
  });
  const { before, after } = await pair(page);
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  await compare(page);
  await expect(page.getByRole("alert")).toContainText(
    "более ранний снимок того же устройства",
  );
  await page
    .locator(".history-item")
    .filter({ hasText: before.configuration_id.slice(0, 8) })
    .click();
  await compare(page);
  await expect(page.getByRole("alert")).toContainText(
    "более ранний снимок того же устройства",
  );
  await upload(
    page,
    "hostname different-diff-device\n",
    "00000000-0000-0000-0000-000000009999",
  );
  await compare(page);
  await expect(page.getByRole("alert")).toContainText("того же устройства");
  expect(requests).toBe(0);
  expect(before.configuration_id).not.toBe(after.configuration_id);
});

test("large object lists paginate without dropping changes", async ({
  page,
}) => {
  await connect(page);
  const host = `diff-many-${Date.now()}`;
  const before = await upload(page, `hostname ${host}\n`);
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  await upload(
    page,
    `hostname ${host}\n` +
      Array.from(
        { length: 23 },
        (_, n) => `interface Gi0/${n}\n shutdown\n!\n`,
      ).join(""),
    before.device_id,
  );
  await compare(page);
  await expect(panel(page)).toContainText("Добавлено: 23");
  await expect(panel(page).locator(".diff-change")).toHaveCount(20);
  await page
    .getByRole("button", { name: "Следующие различия", exact: true })
    .click();
  await expect(panel(page).locator(".diff-change")).toHaveCount(3);
  await page
    .getByRole("button", { name: "Предыдущие различия", exact: true })
    .click();
  await expect(panel(page).locator(".diff-change")).toHaveCount(20);
});

test("altered response binding cannot be displayed as a comparison of the selected pair", async ({
  page,
}) => {
  await connect(page);
  await pair(page);
  await page.route("**/api/v1/configurations/*/diff?**", async (route) => {
    const response = await route.fetch();
    const report = await response.json();
    await route.fulfill({
      json: {
        ...report,
        after: { ...report.after, source_sha256: "f".repeat(64) },
      },
    });
  });
  await compare(page);
  await expect(page.getByRole("alert")).toContainText(
    "не соответствует выбранной паре снимков",
  );
  await expect(panel(page).locator(".diff-result")).toHaveCount(0);
});

test("logout ignores a delayed comparison response and clears selected IDs", async ({
  page,
}) => {
  await connect(page);
  await pair(page);
  let release: (() => void) | undefined;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/configurations/*/diff?**", async (route) => {
    const response = await route.fetch();
    await hold;
    await route.fulfill({ response });
  });
  await compare(page);
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  release!();
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await expect(panel(page)).toHaveCount(0);
  await expect(page.getByRole("alert")).toHaveCount(0);
});
