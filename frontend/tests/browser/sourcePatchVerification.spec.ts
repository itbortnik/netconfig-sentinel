import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { ConfigurationSnapshot } from "../../src/contracts";
import type { PatchDraft } from "../../src/patches";
import { sourceNetworkResult } from "../../src/sourcePatchVerification";
import type {
  SourcePatchVerification,
  VerifySourcePatch,
} from "../../src/sourcePatchVerification";

const TOKEN = "browser-tests-service-token-32-characters-001";
const READER = "browser-tests-reader-service-token-000001";
const headers = { Authorization: `Bearer ${TOKEN}` };
const sourcePanel = (page: Page) =>
  page.getByRole("region", {
    name: "Сетевая проверка сохранённых исходников",
    exact: true,
  });
const patchPanel = (page: Page) =>
  page.getByRole("region", { name: "Черновики изменений", exact: true });
const launch = (page: Page) =>
  sourcePanel(page).getByRole("button", {
    name: "Проверить сохранённые исходники в сети",
    exact: true,
  });
const consent = (page: Page) =>
  sourcePanel(page).getByLabel(
    "Разрешаю передачу выбранных исходников локальному сетевому движку",
    { exact: true },
  );
async function connect(page: Page, token = TOKEN) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
}
async function upload(page: Page, content: string, device?: string) {
  if (device)
    await page.getByLabel("UUID устройства", { exact: true }).fill(device);
  await page.getByLabel("Выбрать конфигурацию").setInputFiles({
    name: "source-network.cfg",
    mimeType: "text/plain",
    buffer: Buffer.from(content),
  });
  await page
    .getByLabel("Сохранить точный исходный текст в зашифрованной БД")
    .check();
  const received = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/api/v1/configurations"),
  );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const response = await received;
  expect(response.status()).toBe(201);
  await expect(
    page.getByRole("button", { name: "Выбрать для diff", exact: true }),
  ).toBeEnabled();
  return (await response.json()) as ConfigurationSnapshot;
}
async function prepare(page: Page, sdkState = "observed", direction?: string) {
  await connect(page);
  const suffix = `${test.info().project.name}-${Date.now()}`;
  const hostname = `${direction ? `source-direction-${direction}-` : sdkState === "observed" ? "source-edge-" : `source-sdk-${sdkState.replaceAll("_", "-")}-`}${suffix}`,
    neighbor = `source-core-${suffix}`;
  const before = await upload(page, `hostname ${hostname}\n`);
  await page
    .getByRole("button", { name: "Выбрать для diff", exact: true })
    .click();
  const after = await upload(
    page,
    `hostname ${hostname}\nntp server 192.0.2.1\n`,
    before.device_id,
  );
  const companionResponse = await page.request.post("/api/v1/configurations", {
    headers,
    data: {
      device_id: await page.evaluate(() => crypto.randomUUID()),
      filename: "source-companion.cfg",
      content: `hostname ${neighbor}\n`,
      retain_original_source: true,
    },
  });
  expect(companionResponse.status()).toBe(201);
  const companion = (await companionResponse.json()) as ConfigurationSnapshot;
  await page
    .getByRole("button", { name: "Показать различия объектов", exact: true })
    .click();
  const created = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith("/api/v1/patches"),
  );
  await patchPanel(page)
    .getByRole("button", { name: "Сохранить черновик объектов", exact: true })
    .click();
  const draft = (await (await created).json()) as PatchDraft;
  await sourcePanel(page)
    .getByRole("button", {
      name: "Открыть сетевые проверки исходников",
      exact: true,
    })
    .click();
  await expect(sourcePanel(page)).toContainText(
    "Локальный сетевой движок настроен; его доступность не проверена",
  );
  await sourcePanel(page)
    .getByRole("button", {
      name: "Показать снимки соседних устройств",
      exact: true,
    })
    .click();
  await sourcePanel(page)
    .getByRole("checkbox", { name: new RegExp(neighbor) })
    .check();
  await sourcePanel(page)
    .getByLabel("Начальный узел сетевой проверки", { exact: true })
    .fill(hostname);
  await sourcePanel(page)
    .getByLabel("Назначение IPv4 сетевой проверки", { exact: true })
    .fill("198.51.100.1/32");
  return { before, after, companion, draft, hostname };
}
async function verify(page: Page) {
  await consent(page).check();
  const response = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" &&
      /\/api\/v2\/patches\/[^/]+\/verify$/.test(item.url()),
  );
  await launch(page).click();
  const received = await response;
  expect(received.status()).toBe(201);
  return (await received.json()) as SourcePatchVerification;
}

test("exact retained pair and explicit companion are verified, then readable after reconnect with reader access", async ({
  page,
}) => {
  const { before, after, companion, draft, hostname } = await prepare(page);
  await expect(launch(page)).toBeDisabled();
  await consent(page).check();
  await sourcePanel(page)
    .getByLabel("Назначение IPv4 сетевой проверки", { exact: true })
    .fill("203.0.113.1/32");
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
  await sourcePanel(page)
    .getByLabel("Назначение IPv4 сетевой проверки", { exact: true })
    .fill("198.51.100.1/32");
  const row = await verify(page);
  expect(row.version).toBe("source-patch-verification-0.4.0");
  expect(row.intent.request.version).toBe("source-patch-request-0.4.0");
  expect(row.outcome).toMatchObject({
    network_execution: {
      version: "batfish-execution-0.4.0",
      sdk_version: "owned-browser-sdk-0.36.0",
      sdk_observation: "observed",
      reachability_impact: {
        state: "observed",
        direction: "no_witnesses_returned",
        lost_witness_count: 0,
        gained_witness_count: 0,
      },
    },
  });
  expect(row.intent.before.configuration_id).toBe(before.configuration_id);
  expect(row.intent.after.configuration_id).toBe(after.configuration_id);
  expect(row.intent.request.companions).toEqual([
    {
      configuration_id: companion.configuration_id,
      source_sha256: companion.canonical.source.sha256,
    },
  ]);
  expect(row.intent.request.scope).toEqual({
    start_node: hostname,
    destination: "198.51.100.1/32",
  });
  expect(row.intent.before_network_sha256).not.toBe(
    before.canonical.source.sha256,
  );
  expect(sourceNetworkResult(row.outcome)?.engine_version).toBe(
    "owned-browser-fixture",
  );
  expect(row).toMatchObject({
    status: "needs_review",
    approved: false,
    applied: false,
    ml_status: "not_run",
  });
  expect(row.intent.preflight.formal_verification).toBe("not_run");
  await expect(
    sourcePanel(page).getByLabel("Результат проверки исходников", {
      exact: true,
    }),
  ).toContainText("no_differences_in_scope");
  await expect(sourcePanel(page)).toContainText(
    "Согласовано: нет. Применено: нет. ML: не запускался.",
  );
  await expect(sourcePanel(page)).toContainText(
    "Локальный preflight: формальная проверка не запускалась",
  );
  await expect(sourcePanel(page)).toContainText(
    "Удаление временной сети: подтверждено",
  );
  await expect(
    sourcePanel(page).getByLabel("Метаданные SDK сетевой проверки", {
      exact: true,
    }),
  ).toContainText("owned-browser-sdk-0.36.0");
  await expect(sourcePanel(page)).toContainText(
    "не удостоверяют исполняемый файл, качество или формальное одобрение",
  );
  await expect(
    sourcePanel(page).getByRole("region", {
      name: "Направление примеров достижимости",
      exact: true,
    }),
  ).toContainText("Запрос не вернул примеров различий");
  await expect(
    sourcePanel(page).getByRole("button", { name: /скачать.*исход/i }),
  ).toHaveCount(0);
  await expect(consent(page)).not.toBeChecked();
  for (const snapshot of [before, after, companion]) {
    const response = await page.request.get(
      `/api/v1/configurations/${snapshot.configuration_id}`,
      { headers },
    );
    expect(await response.json()).toEqual(snapshot);
  }
  const v1 = await page.request.get(
    `/api/v1/patches/${draft.patch_id}/verifications`,
    { headers },
  );
  expect(await v1.json()).toEqual([]);
  await connect(page, READER);
  await page
    .locator(".history-item")
    .filter({ hasText: after.configuration_id.slice(0, 8) })
    .click();
  await patchPanel(page)
    .getByRole("button", { name: "Обновить черновики", exact: true })
    .click();
  await patchPanel(page)
    .getByRole("button", {
      name: new RegExp(`Открыть черновик ${draft.patch_id.slice(0, 8)}`),
    })
    .click();
  await sourcePanel(page)
    .getByRole("button", {
      name: "Открыть сетевые проверки исходников",
      exact: true,
    })
    .click();
  await sourcePanel(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть сетевую проверку ${row.verification_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(sourcePanel(page)).toContainText(row.review_sha256);
  await expect(launch(page)).toHaveCount(0);
  await expect(consent(page)).toHaveCount(0);
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});

for (const state of ["metadata_unavailable", "not_observed"] as const)
  test(`saved SDK state ${state} is explicit and never inferred from the browser`, async ({
    page,
  }) => {
    await prepare(page, state);
    const row = await verify(page);
    expect(row.outcome).toMatchObject({
      network_execution: {
        sdk_version: null,
        sdk_observation: state,
        result: {
          status:
            state === "not_observed" ? "error" : "no_differences_in_scope",
        },
      },
    });
    await expect(
      sourcePanel(page).getByLabel("Метаданные SDK сетевой проверки", {
        exact: true,
      }),
    ).toContainText(state);
    await expect(sourcePanel(page)).not.toContainText(
      "owned-browser-sdk-0.36.0",
    );
    expect(row.approved).toBe(false);
    expect(row.status).toBe("needs_review");
  });

test("legacy source history remains byte-equal beside directional records", async ({
  page,
}) => {
  const { draft } = await prepare(page);
  const current = await verify(page);
  const legacyResponse = await page.request.post(
    `/api/v2/patches/${draft.patch_id}/verify`,
    {
      headers,
      data: {
        ...current.intent.request,
        version: "source-patch-request-0.1.0",
        verification_id: crypto.randomUUID(),
      },
    },
  );
  expect(legacyResponse.status()).toBe(201);
  const legacyRaw = await legacyResponse.text();
  const legacy = JSON.parse(legacyRaw) as SourcePatchVerification;
  expect(legacy.outcome).not.toHaveProperty("network_execution");
  await sourcePanel(page)
    .getByRole("button", { name: "Обновить сетевые проверки", exact: true })
    .click();
  await sourcePanel(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть сетевую проверку ${legacy.verification_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(
    sourcePanel(page).getByLabel("Метаданные SDK сетевой проверки", {
      exact: true,
    }),
  ).toContainText("исходная запись не сохраняла версию");
  await expect(
    sourcePanel(page).getByLabel("Метаданные SDK сетевой проверки", {
      exact: true,
    }),
  ).not.toContainText("observed");
  const reread = await page.request.get(
    `/api/v2/patches/${draft.patch_id}/verifications/${legacy.verification_id}`,
    { headers },
  );
  expect(await reread.text()).toBe(legacyRaw);
  await expect(sourcePanel(page)).toContainText(
    "Направление изменения в исходной записи не сохранялось",
  );
  const sdkResponse = await page.request.post(
    `/api/v2/patches/${draft.patch_id}/verify`,
    {
      headers,
      data: {
        ...current.intent.request,
        version: "source-patch-request-0.2.0",
        verification_id: crypto.randomUUID(),
      },
    },
  );
  expect(sdkResponse.status()).toBe(201);
  const sdkRaw = await sdkResponse.text(),
    sdk = JSON.parse(sdkRaw) as SourcePatchVerification;
  expect(sdk.version).toBe("source-patch-verification-0.2.0");
  expect(sdk.outcome).toHaveProperty(
    "network_execution.sdk_observation",
    "observed",
  );
  expect(sdk.outcome).not.toHaveProperty(
    "network_execution.reachability_impact",
  );
  await sourcePanel(page)
    .getByRole("button", { name: "Обновить сетевые проверки", exact: true })
    .click();
  await sourcePanel(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть сетевую проверку ${sdk.verification_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(sourcePanel(page)).toContainText(
    "Направление изменения в исходной записи не сохранялось",
  );
  const sdkReread = await page.request.get(
    `/api/v2/patches/${draft.patch_id}/verifications/${sdk.verification_id}`,
    { headers },
  );
  expect(await sdkReread.text()).toBe(sdkRaw);
});

for (const [direction, label, lost, gained] of [
  ["loss", "Наблюдены примеры потери успешной доставки", 1, 0],
  ["gain", "Наблюдены примеры появления успешной доставки", 0, 1],
  ["both", "Наблюдены примеры потери и появления успешной доставки", 1, 1],
] as const)
  test(`saved authored directional ${direction} witnesses are explicit without risk or formal promotion`, async ({
    page,
  }) => {
    await prepare(page, "observed", direction);
    const row = await verify(page);
    if (row.version !== "source-patch-verification-0.4.0")
      throw new Error("Expected directional protocol");
    const impact = row.outcome!.network_execution.reachability_impact;
    expect(impact).toMatchObject({
      state: "observed",
      lost_witness_count: lost,
      gained_witness_count: gained,
    });
    const view = sourcePanel(page).getByRole("region", {
      name: "Направление примеров достижимости",
      exact: true,
    });
    await expect(view).toContainText(label);
    await expect(view).toContainText(
      `Примеров потери: ${lost}; появления: ${gained}`,
    );
    await expect(
      view
        .getByRole("table", { name: "Сохранённые примеры изменения доставки" })
        .getByRole("row"),
    ).toHaveCount(lost + gained + 1);
    await expect(view).toContainText(
      "точки входа, существующие и активные в обоих снимках",
    );
    await expect(view).toContainText(
      "Адрес источника выводится по снимку после изменения",
    );
    await expect(view).toContainText("не число пакетов");
    await expect(sourcePanel(page)).toContainText(
      "Согласовано: нет. Применено: нет. ML: не запускался",
    );
    expect(row.approved).toBe(false);
    expect(row.intent.preflight.formal_verification).toBe("not_run");
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  });

for (const [direction, reason] of [
  ["unknown", "Набор путей неполон или усечён"],
  ["empty", "Достижимая область пуста"],
  ["cleanup", "Очистка исходников на движке не подтверждена"],
] as const)
  test(`authored directional ${direction} retains unknown counts and its actual reason`, async ({
    page,
  }) => {
    await prepare(page, "observed", direction);
    const row = await verify(page);
    if (row.version !== "source-patch-verification-0.4.0")
      throw new Error("Expected directional protocol");
    expect(row.outcome!.network_execution.reachability_impact).toMatchObject({
      direction: null,
      lost_witness_count: null,
      gained_witness_count: null,
      witnesses: [],
    });
    const view = sourcePanel(page).getByRole("region", {
      name: "Направление примеров достижимости",
      exact: true,
    });
    await expect(view).toContainText(reason);
    await expect(view).not.toContainText("Примеров потери: 0");
    await expect(view.getByRole("table")).toHaveCount(0);
  });

test("lost POST response is reconciled by immutable GET with one actual engine-fixture attempt", async ({
  page,
}) => {
  const { draft } = await prepare(page);
  const requests: VerifySourcePatch[] = [];
  await page.route("**/api/v2/patches/*/verify", async (route) => {
    requests.push(route.request().postDataJSON() as VerifySourcePatch);
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    await route.abort("connectionreset");
  });
  await consent(page).check();
  await launch(page).click();
  await expect(sourcePanel(page)).toContainText(
    "Итог не подтверждён. Новый запуск заблокирован",
  );
  await expect(launch(page)).toBeDisabled();
  await sourcePanel(page)
    .getByRole("button", { name: "Прочитать сетевую попытку", exact: true })
    .click();
  await expect(
    sourcePanel(page).getByLabel("Результат проверки исходников", {
      exact: true,
    }),
  ).toContainText("no_differences_in_scope");
  expect(requests).toHaveLength(1);
  const response = await page.request.get(
    `/api/v2/patches/${draft.patch_id}/verifications`,
    { headers },
  );
  const history = await response.json();
  expect(history).toHaveLength(1);
  expect(history[0].verification_id).toBe(requests[0]!.verification_id);
  await sourcePanel(page)
    .getByRole("button", {
      name: "Подготовить новую сетевую проверку",
      exact: true,
    })
    .click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
});

test("known rejection followed by GET404 allows explicit recovery with new consent and a new ID", async ({
  page,
}) => {
  await prepare(page);
  const requests: VerifySourcePatch[] = [];
  await page.route("**/api/v2/patches/*/verify", async (route) => {
    requests.push(route.request().postDataJSON() as VerifySourcePatch);
    if (requests.length === 1)
      await route.fulfill({
        status: 429,
        json: { detail: "Owned rejection before attempt reservation" },
      });
    else await route.continue();
  });
  await consent(page).check();
  await launch(page).click();
  await expect(sourcePanel(page)).toContainText("Сервер отклонил запрос");
  const reset = sourcePanel(page).getByRole("button", {
    name: "Сбросить отклонённый сетевой запрос",
    exact: true,
  });
  await expect(reset).toHaveCount(0);
  await sourcePanel(page)
    .getByRole("button", { name: "Прочитать сетевую попытку", exact: true })
    .click();
  await expect(reset).toBeEnabled();
  await reset.click();
  await expect(consent(page)).not.toBeChecked();
  await expect(launch(page)).toBeDisabled();
  await verify(page);
  expect(requests).toHaveLength(2);
  expect(requests[0]!.verification_id).not.toBe(requests[1]!.verification_id);
});

test("lost response with no visible record remains locked and disabled capabilities cannot authorize an upload", async ({
  page,
}) => {
  await prepare(page);
  let disabled = true;
  await page.route("**/api/v2/patches/capabilities", async (route) => {
    const response = await route.fetch();
    await route.fulfill({
      response,
      json: {
        ...(await response.json()),
        network_engine: disabled ? "disabled" : "configured",
      },
    });
  });
  await sourcePanel(page)
    .getByRole("button", { name: "Обновить сетевые проверки", exact: true })
    .click();
  await expect(sourcePanel(page)).toContainText(
    "Локальный сетевой движок отключён",
  );
  await expect(consent(page)).toBeDisabled();
  await expect(launch(page)).toBeDisabled();
  disabled = false;
  await sourcePanel(page)
    .getByRole("button", { name: "Обновить сетевые проверки", exact: true })
    .click();
  await expect(consent(page)).toBeEnabled();
  let posts = 0;
  await page.route("**/api/v2/patches/*/verify", async (route) => {
    posts++;
    await route.abort("connectionreset");
  });
  await consent(page).check();
  await launch(page).click();
  await sourcePanel(page)
    .getByRole("button", { name: "Прочитать сетевую попытку", exact: true })
    .click();
  await expect(
    sourcePanel(page).getByRole("button", {
      name: "Сбросить отклонённый сетевой запрос",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(launch(page)).toBeDisabled();
  expect(posts).toBe(1);
});
