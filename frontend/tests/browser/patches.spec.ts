import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { ConfigurationSnapshot } from "../../src/contracts";
import type {
  CreatePatch,
  PatchDraft,
  VerificationRun,
  VerifyPatch,
} from "../../src/patches";
const TOKEN = "browser-tests-service-token-32-characters-001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const panel = (page: Page) =>
  page.getByRole("region", { name: "Черновики изменений", exact: true });
const save = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Сохранить черновик объектов",
    exact: true,
  });
const verify = (page: Page) =>
  panel(page).getByRole("button", {
    name: "Локальная проверка черновика",
    exact: true,
  });
async function connect(page: Page) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
}
async function upload(page: Page, content: string, device?: string) {
  if (device)
    await page.getByLabel("UUID устройства", { exact: true }).fill(device);
  await page.getByLabel("Текст конфигурации").fill(content);
  const received = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" &&
      item.url().endsWith("/configurations"),
  );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const snapshot = (await (await received).json()) as ConfigurationSnapshot;
  await expect(
    page.getByRole("button", { name: "Выбрать для diff", exact: true }),
  ).toBeEnabled();
  return snapshot;
}
async function pair(page: Page, partial = false) {
  const host = `patch-${test.info().project.name}-${Date.now()}`;
  const before = await upload(page, `hostname ${host}\n`);
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  const after = await upload(
    page,
    `hostname ${host}\nntp server 192.0.2.1\n${partial ? "unknown PRIVATE-PATCH-INPUT\n" : ""}`,
    before.device_id,
  );
  await page
    .getByRole("button", { name: "Показать различия объектов", exact: true })
    .click();
  await expect(save(page)).toBeEnabled();
  return { before, after };
}
async function create(page: Page) {
  const received = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" && item.url().endsWith("/patches"),
  );
  await save(page).click();
  const draft = (await (await received).json()) as PatchDraft;
  await expect(verify(page)).toBeEnabled();
  return draft;
}
test("saved draft and local review survive reconnect without changing snapshots or formal status", async ({
  page,
}) => {
  await connect(page);
  const { before, after } = await pair(page);
  const draft = await create(page);
  const response = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" && item.url().endsWith("/verify"),
  );
  await verify(page).click();
  const run = (await (await response).json()) as VerificationRun;
  await expect(
    panel(page).getByLabel("Локальная проверка", { exact: true }),
  ).toContainText("требуется рассмотрение");
  await expect(panel(page)).toContainText(
    "Формальная проверка: не запускалась",
  );
  expect(run.preflight.formal_verification).toBe("not_run");
  for (const snapshot of [before, after]) {
    expect(
      await (
        await page.request.get(
          `/api/v1/configurations/${snapshot.configuration_id}`,
          { headers },
        )
      ).json(),
    ).toEqual(snapshot);
  }
  await expect(verify(page)).toBeEnabled();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await connect(page);
  await page
    .locator(".history-item")
    .filter({ hasText: after.configuration_id.slice(0, 8) })
    .click();
  await panel(page)
    .getByRole("button", { name: "Обновить черновики", exact: true })
    .click();
  await panel(page)
    .getByRole("button", {
      name: new RegExp(`Открыть черновик ${draft.patch_id.slice(0, 8)}`),
    })
    .click();
  await panel(page)
    .getByRole("button", {
      name: new RegExp(`Открыть проверку ${run.verification_id.slice(0, 8)}`),
    })
    .click();
  await expect(panel(page)).toContainText(
    "Локальная проверка — требуется рассмотрение",
  );
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
});
test("lost draft and verification responses retry immutable IDs without duplicate history", async ({
  page,
}) => {
  await connect(page);
  const { after } = await pair(page);
  const drafts: CreatePatch[] = [],
    reviews: VerifyPatch[] = [];
  await page.route("**/api/v1/patches", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    drafts.push(route.request().postDataJSON() as CreatePatch);
    const response = await route.fetch();
    if (drafts.length === 1) await route.abort("connectionreset");
    else await route.fulfill({ response });
  });
  await save(page).click();
  await expect(panel(page)).toContainText("Запись могла сохраниться");
  await save(page).click();
  await expect(verify(page)).toBeEnabled();
  expect(drafts).toHaveLength(2);
  expect(drafts[0]).toEqual(drafts[1]);
  await page.route("**/api/v1/patches/*/verify", async (route) => {
    reviews.push(route.request().postDataJSON() as VerifyPatch);
    const response = await route.fetch();
    if (reviews.length === 1) await route.abort("connectionreset");
    else await route.fulfill({ response });
  });
  await verify(page).click();
  await expect(panel(page)).toContainText("Запись могла сохраниться");
  await verify(page).click();
  await expect(panel(page)).toContainText(
    "Локальная проверка — требуется рассмотрение",
  );
  await expect(verify(page)).toBeEnabled();
  expect(reviews).toHaveLength(2);
  expect(reviews[0]).toEqual(reviews[1]);
  const stored = await page.request.get(
    `/api/v1/patches?after_configuration_id=${after.configuration_id}`,
    { headers },
  );
  expect((await stored.json()).length).toBe(1);
  const history = await page.request.get(
    `/api/v1/patches/${drafts[0]!.patch_id}/verifications`,
    { headers },
  );
  expect((await history.json()).length).toBe(1);
});
test("partial input is never displayed as zero policy changes or a formal pass", async ({
  page,
}) => {
  await connect(page);
  await pair(page, true);
  await create(page);
  await verify(page).click();
  await expect(panel(page)).toContainText(
    "Изменения нарушений недоступны: неполный разбор",
  );
  await expect(panel(page)).toContainText("Не все команды разобраны");
  await expect(panel(page)).not.toContainText("PRIVATE-PATCH-INPUT");
  await expect(panel(page)).not.toContainText("Новых: 0");
});
test("foreign and authoritative-looking successful responses are rejected", async ({
  page,
}) => {
  await connect(page);
  await pair(page);
  for (const change of [
    { status: "approved" },
    { requires_human_review: false },
    { patch_id: "00000000-0000-0000-0000-000000000999" },
  ]) {
    await page.route("**/api/v1/patches", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      const response = await route.fetch();
      await route.fulfill({
        response,
        json: { ...(await response.json()), ...change },
      });
    });
    await save(page).click();
    await expect(panel(page)).toContainText("Запись могла сохраниться");
    await expect(save(page)).toBeEnabled();
    await expect(verify(page)).toHaveCount(0);
    await page.unroute("**/api/v1/patches");
  }
  await create(page);
  await page.route("**/api/v1/patches/*/verify", async (route) => {
    const response = await route.fetch();
    const run = (await response.json()) as VerificationRun;
    await route.fulfill({
      response,
      json: {
        ...run,
        preflight: { ...run.preflight, formal_verification: "passed" },
      },
    });
  });
  await verify(page).click();
  await expect(panel(page)).toContainText("Запись могла сохраниться");
  await expect(verify(page)).toBeEnabled();
  await expect(
    panel(page).getByLabel("Локальная проверка", { exact: true }),
  ).toHaveCount(0);
});
test("a late saved draft cannot reappear after logout", async ({ page }) => {
  await connect(page);
  await pair(page);
  let release: () => void = () => {};
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  let started: () => void = () => {};
  const received = new Promise<void>((resolve) => {
    started = resolve;
  });
  await page.route("**/api/v1/patches", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch();
    started();
    await wait;
    try {
      await route.fulfill({ response });
    } catch {
      /* disconnected request */
    }
  });
  await save(page).click();
  await received;
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  release();
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await expect(panel(page)).toHaveCount(0);
});

test("draft and verification histories paginate without losing the final record", async ({
  page,
}) => {
  test.setTimeout(60_000);
  await connect(page);
  const { before, after } = await pair(page);
  const draft = await create(page);
  for (let index = 0; index < 20; index++) {
    const response = await page.request.post("/api/v1/patches", {
      headers,
      data: {
        patch_id: crypto.randomUUID(),
        before_configuration_id: before.configuration_id,
        after_configuration_id: after.configuration_id,
        before_source_sha256: before.canonical.source.sha256,
        after_source_sha256: after.canonical.source.sha256,
      },
    });
    expect(response.status()).toBe(201);
  }
  await panel(page)
    .getByRole("button", { name: "Обновить черновики", exact: true })
    .click();
  const draftButtons = panel(page).getByRole("button", {
    name: /^Открыть черновик /,
  });
  await expect(draftButtons).toHaveCount(20);
  await panel(page)
    .getByRole("button", { name: "Следующие черновики", exact: true })
    .click();
  await expect(draftButtons).toHaveCount(1);
  await expect(draftButtons).toContainText(draft.patch_id.slice(0, 8));
  await expect(
    panel(page).getByRole("button", {
      name: "Следующие черновики",
      exact: true,
    }),
  ).toBeDisabled();
  for (let index = 0; index < 21; index++) {
    const response = await page.request.post(
      `/api/v1/patches/${draft.patch_id}/verify`,
      {
        headers,
        data: {
          verification_id: crypto.randomUUID(),
          draft_sha256: draft.draft_sha256,
        },
      },
    );
    expect(response.status()).toBe(201);
  }
  await draftButtons.click();
  const reviewButtons = panel(page).getByRole("button", {
    name: /^Открыть проверку /,
  });
  await expect(reviewButtons).toHaveCount(20);
  await panel(page)
    .getByRole("button", { name: "Следующие проверки", exact: true })
    .click();
  await expect(reviewButtons).toHaveCount(1);
  await reviewButtons.click();
  await expect(panel(page)).toContainText(
    "Локальная проверка — требуется рассмотрение",
  );
  await panel(page)
    .getByRole("button", { name: "Предыдущие проверки", exact: true })
    .click();
  await expect(reviewButtons).toHaveCount(20);
});

test("late local review is ignored after switching to another snapshot", async ({
  page,
}) => {
  await connect(page);
  const { after } = await pair(page);
  const draft = await create(page);
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let start: () => void = () => {};
  const started = new Promise<void>((resolve) => {
    start = resolve;
  });
  let finish: () => void = () => {};
  const finished = new Promise<void>((resolve) => {
    finish = resolve;
  });
  await page.route("**/api/v1/patches/*/verify", async (route) => {
    const response = await route.fetch();
    start();
    await held;
    try {
      await route.fulfill({ response });
    } finally {
      finish();
    }
  });
  await verify(page).click();
  await started;
  await upload(
    page,
    `hostname ${after.canonical.device.hostname}\nntp server 192.0.2.2\n`,
    after.device_id,
  );
  release();
  await finished;
  await expect(
    panel(page).getByLabel("Сохранённый черновик", { exact: true }),
  ).toHaveCount(0);
  await expect(
    panel(page).getByLabel("Локальная проверка", { exact: true }),
  ).toHaveCount(0);
  const recorded = await page.request.get(
    `/api/v1/patches/${draft.patch_id}/verifications`,
    { headers },
  );
  expect((await recorded.json()).length).toBe(1);
});
