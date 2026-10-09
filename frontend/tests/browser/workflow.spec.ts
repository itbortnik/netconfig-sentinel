import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const TOKEN = "browser-tests-service-token-32-characters-001";
const cisco =
  "hostname browser-edge\naaa new-model\nip ssh version 2\nline vty 0 4\n transport input ssh telnet\n!\nntp server 192.0.2.1\nlogging host 192.0.2.2\n";
const localStorageState = (page: Page) =>
  page.evaluate(() => ({
    local: { ...localStorage },
    session: { ...sessionStorage },
  }));

async function connect(page: Page) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
}
async function upload(page: Page, content: string, name = "browser.cfg") {
  await page.getByLabel("Выбрать конфигурацию").setInputFiles({
    name,
    mimeType: "text/plain",
    buffer: Buffer.from(content),
  });
  await expect(page.getByLabel("Текст конфигурации")).toHaveValue(content);
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Анализировать снимок", exact: true }),
  ).toBeVisible();
}

async function expectNoOverflow(page: Page) {
  const layout = await page.evaluate(() => ({
    viewport: window.innerWidth,
    scroll: document.documentElement.scrollWidth,
    offenders: [...document.querySelectorAll("main *")]
      .map((element) => ({
        tag: element.tagName,
        class: element.className,
        right: element.getBoundingClientRect().right,
        width: element.getBoundingClientRect().width,
        wrap: getComputedStyle(element).overflowWrap,
        overflow: getComputedStyle(element).overflowX,
        contentWidth: element.scrollWidth,
        innerWidth: element.clientWidth,
      }))
      .filter(
        (item) =>
          item.width > 0 &&
          (item.right > window.innerWidth + 1 ||
            (item.overflow === "visible" &&
              item.contentWidth > item.innerWidth + 1)),
      )
      .slice(0, 12),
  }));
  expect(layout.scroll <= layout.viewport, JSON.stringify(layout)).toBe(true);
}

for (const vendor of ["cisco", "juniper"] as const) {
  for (const scenario of ["reference", "peers", "partial"] as const) {
    test(`expanded ${vendor} ${scenario}: explicit version, sealed sources and saved history`, async ({
      page,
    }) => {
      await connect(page);
      const suffix = `${test.info().project.name}-${Date.now()}`;
      const normal = (host: string, address = "192.0.2.1") =>
        vendor === "cisco"
          ? `hostname ${host}\nntp server ${address}\n`
          : `set system host-name ${host}\nset system ntp server ${address}\n`;
      const device = await page
        .getByLabel("UUID устройства", { exact: true })
        .inputValue();
      if (scenario === "reference") {
        await upload(page, normal(`expanded-${suffix}`));
        await page
          .getByRole("button", { name: "Выбрать как эталон", exact: true })
          .click();
      } else {
        await page
          .getByText("Метки группы сравнения (необязательно)", { exact: true })
          .click();
        await page.getByLabel("Роль устройства", { exact: true }).fill("edge");
        await page.getByLabel("Класс площадки", { exact: true }).fill("branch");
        await page
          .getByLabel("Профиль сервиса", { exact: true })
          .fill("owned-expanded");
        for (let index = 0; index < 3; index++) {
          await page
            .getByRole("button", { name: "Новое", exact: true })
            .click();
          await upload(page, normal(`expanded-peer-${suffix}-${index}`));
          await page
            .getByRole("button", {
              name: "Добавить в группу сравнения",
              exact: true,
            })
            .click();
        }
      }
      await page.getByLabel("UUID устройства", { exact: true }).fill(device);
      await upload(
        page,
        normal(`expanded-${suffix}`, "192.0.2.9") +
          (scenario === "partial" ? "unknown PRIVATE_COMMAND\n" : ""),
      );
      await expect(
        page.getByLabel("Область сравнения", { exact: true }),
      ).toHaveValue("0.1.0");
      await page
        .getByLabel("Область сравнения", { exact: true })
        .selectOption("0.2.0");
      const saved = page.waitForResponse(
        (response) =>
          response.url().endsWith("/analyze") &&
          response.request().method() === "POST",
      );
      await page
        .getByRole("button", { name: "Анализировать снимок", exact: true })
        .click();
      const response = await saved;
      expect(response.status()).toBe(201);
      expect(response.request().postDataJSON().comparison_version).toBe(
        "0.2.0",
      );
      const result = await response.json();
      expect(result.version).toBe("analysis-api-0.4.0");
      await expect(
        page.getByRole("heading", { name: "Находки и доказательства" }),
      ).toBeVisible();
      await page
        .getByText("Входы сравнения и профиль группы", { exact: true })
        .click();
      await expect(page.locator(".analysis-summary")).toContainText(
        "Расширенное сравнение 0.2.0",
      );
      if (scenario === "partial") {
        await expect(page.locator(".analysis-summary")).toContainText(
          "Сравнение свойств пропущено",
        );
        expect(result.comparison.peer_evaluation.skipped_features).toHaveLength(
          19,
        );
        expect(result.risk).toBeNull();
      } else if (scenario === "peers") {
        await expect(page.locator(".analysis-summary")).toContainText(
          "Сравнено: 19",
        );
      }
      const finding = result.findings.find(
        (item: { model_version: string }) =>
          item.model_version ===
          (scenario === "reference"
            ? "expected-config-0.2.0"
            : "peer-baseline-0.2.0"),
      );
      expect(finding).toBeDefined();
      await page.getByLabel("Поиск по находкам").fill(finding.category);
      await page.locator(".finding-button").first().click();
      await page
        .getByRole("button", {
          name: "Показать источники объяснения",
          exact: true,
        })
        .click();
      await expect(
        page.getByRole("region", { name: "Объяснение с источниками" }),
      ).toContainText("project-knowledge-0.3.0");
      await expectNoOverflow(page);
      expect(await localStorageState(page)).toEqual({ local: {}, session: {} });
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
        "Расширенное сравнение 0.2.0",
      );
    });
  }
}

test("invalid authentication remains disconnected and no token persists", async ({
  page,
}) => {
  await page.goto("/ui/");
  await page
    .getByLabel("API-токен", { exact: true })
    .fill("wrong-service-token-at-least-32-characters");
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Токен не принят");
  await expect(page.getByLabel("API-токен", { exact: true })).toHaveValue("");
  expect(await localStorageState(page)).toEqual({ local: {}, session: {} });
});

test("original retention needs per-upload consent and resets after source changes and success", async ({
  page,
}) => {
  await connect(page);
  const consent = page.getByLabel(
    "Сохранить точный исходный текст в зашифрованной БД",
  );
  await expect(consent).not.toBeChecked();
  await page
    .getByLabel("Текст конфигурации")
    .fill("hostname retention-owned\n");
  await consent.check();
  await page
    .getByLabel("Текст конфигурации")
    .fill("hostname retention-owned\n! new version\n");
  await expect(consent).not.toBeChecked();
  await consent.check();
  const saved = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v1/configurations") &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  const response = await saved;
  expect(response.status()).toBe(201);
  expect(response.request().postDataJSON().retain_original_source).toBe(true);
  await expect(consent).not.toBeChecked();
  await expect(page.getByLabel("Текст конфигурации")).toHaveValue("");
  const snapshot = await response.json();
  expect(snapshot.content).toBeUndefined();
  expect(
    (
      await page.request.get(
        `/api/v1/configurations/${snapshot.configuration_id}/source`,
        { headers: { Authorization: `Bearer ${TOKEN}` } },
      )
    ).status(),
  ).toBe(404);
});

test("real Cisco upload, analysis, evidence, history and reload", async ({
  page,
}) => {
  const errors: string[] = [];
  const urls: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => urls.push(request.url()));
  await connect(page);
  const device = await page
    .getByLabel("UUID устройства", { exact: true })
    .inputValue();
  await upload(page, cisco);
  await expect(page.getByLabel("Текст конфигурации")).toHaveValue("");
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
  await page.getByLabel("Поиск по находкам").fill("telnet");
  await page.locator(".finding-button").first().click();
  await expect(
    page.getByRole("region", { name: "Детали находки" }),
  ).toContainText("Telnet");
  await expect(
    page.getByRole("region", { name: "Детали находки" }),
  ).toContainText("Строки 5");
  await expect(page.getByText("Не запускалась", { exact: true })).toBeVisible();
  await expect(
    page.getByText("ЛОКАЛЬНОЕ ОБЪЯСНЕНИЕ / БЕЗ LLM", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await expect(page.locator(".history-item").first()).toContainText("Анализ");
  expect(await localStorageState(page)).toEqual({ local: {}, session: {} });
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Конфигурации", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: "browser-edge" })
    .first()
    .click();
  await expect(page.locator(".snapshot-panel")).toContainText(device);
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await page.locator(".history-item").first().click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
  expect(urls.some((url) => url.includes(TOKEN))).toBe(false);
  expect(errors).toEqual([]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  if (process.env.NETCONFIG_CAPTURE_UI === "1") {
    await page.screenshot({
      path: `../artifacts/ui-workflow-${test.info().project.name}-20261002.png`,
      fullPage: false,
    });
  }
});

test("restoring a page clears a connected session and unsent login input", async ({
  page,
}) => {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.evaluate(() =>
    window.dispatchEvent(
      new PageTransitionEvent("pageshow", { persisted: true }),
    ),
  );
  await expect(page.getByLabel("API-токен", { exact: true })).toHaveValue("");
  await connect(page);
  await page.evaluate(() =>
    window.dispatchEvent(
      new PageTransitionEvent("pageshow", { persisted: true }),
    ),
  );
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await expect(page.locator(".history-item")).toHaveCount(0);
});

test("JunOS configuration is analyzed with genuine API data", async ({
  page,
}) => {
  await connect(page);
  await upload(page, "set system host-name browser-junos\n", "junos.conf");
  await expect(page.locator(".snapshot-panel")).toContainText("JUNIPER");
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
  await expect(
    page.getByText("Политики проверены", { exact: true }).first(),
  ).toBeVisible();
  await expect(page.locator(".finding-buttons")).not.toBeEmpty();
});

test("partial parse preserves untrusted text as text and suppresses aggregate risk", async ({
  page,
}) => {
  await connect(page);
  const untrusted = '<img src=x onerror="window.untrustedExecuted=1">';
  await upload(
    page,
    `hostname browser-partial\nunknown-command ${untrusted}\n`,
  );
  await expect(
    page.getByText("Неполный разбор", { exact: true }),
  ).toBeVisible();
  await page.getByText("Неподдержанные фрагменты (1)", { exact: true }).click();
  await expect(page.locator(".fragment-list pre")).toContainText(untrusted);
  expect(await page.evaluate(() => "untrustedExecuted" in window)).toBe(false);
  expect(await page.locator(".fragment-list img").count()).toBe(0);
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(
    page.getByText("Частичный результат", { exact: true }),
  ).toBeVisible();
  await expect(page.locator(".analysis-summary")).toContainText("Недоступен");
  expect(
    await page
      .locator(".analysis-summary")
      .getByText("Состав оценки риска", { exact: true })
      .count(),
  ).toBe(0);
});

test("local input limits reject oversized files before upload", async ({
  page,
}) => {
  await connect(page);
  let uploads = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().endsWith("/configurations")
    )
      uploads += 1;
  });
  await page.getByLabel("Выбрать конфигурацию").setInputFiles({
    name: "huge.cfg",
    mimeType: "text/plain",
    buffer: Buffer.alloc(2 * 1024 * 1024 + 1),
  });
  await expect(page.getByRole("alert")).toContainText("2 MiB");
  await page.getByLabel("Имя файла", { exact: true }).fill("../unsafe.cfg");
  await page.getByLabel("Текст конфигурации").fill(cisco);
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("без пути");
  expect(uploads).toBe(0);
});

test("disconnect cancels a delayed response and clears sensitive views", async ({
  page,
}) => {
  await connect(page);
  await upload(page, "hostname browser-disconnect\n");
  let release: (() => void) | undefined;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/configurations/*/analyze", async (route) => {
    await hold;
    await route.abort();
  });
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(
    page.getByText(
      "Операция выполняется. Перед повтором записи проверьте историю.",
    ),
  ).toBeVisible();
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  release!();
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await expect(page.locator(".snapshot-panel")).toHaveCount(0);
  await expect(page.locator(".analysis-area")).toHaveCount(0);
  expect(await localStorageState(page)).toEqual({ local: {}, session: {} });
});

test("working surface fits viewport and supports keyboard login", async ({
  page,
}) => {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByLabel("API-токен", { exact: true }).press("Enter");
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  const response = await page.request.get("/ui/");
  expect(response.headers()["content-security-policy"]).toContain(
    "script-src 'self'",
  );
  expect(response.headers()["content-security-policy"]).not.toContain(
    "unsafe-inline",
  );
});

test("explicit reference and three peers survive analysis history, not the browser session", async ({
  page,
}) => {
  await connect(page);
  const suffix = `${test.info().project.name}-${Date.now()}`;
  await page
    .getByText("Метки группы сравнения (необязательно)", { exact: true })
    .click();
  await page.getByLabel("Роль устройства", { exact: true }).fill("edge");
  await page.getByLabel("Класс площадки", { exact: true }).fill("branch");
  await page
    .getByLabel("Профиль сервиса", { exact: true })
    .fill("browser-test");
  const device = await page
    .getByLabel("UUID устройства", { exact: true })
    .inputValue();
  const normal = (host: string) =>
    `hostname ${host}\naaa new-model\nip ssh version 2\nline vty 0 4\n transport input ssh\n!\nntp server 192.0.2.1\nlogging host 192.0.2.2\ninterface Gi0/1\n switchport mode access\n switchport access vlan 10\n!\n`;
  const host = `compare-${suffix}`;
  await upload(page, normal(host), "reference.cfg");
  await page
    .getByRole("button", { name: "Выбрать как эталон", exact: true })
    .click();
  const selection = page.getByRole("region", { name: "Выбор сравнений" });
  await expect(selection).toContainText(host);
  for (let index = 0; index < 3; index += 1) {
    await page.getByRole("button", { name: "Новое", exact: true }).click();
    await upload(page, normal(`peer-${suffix}-${index}`), `peer-${index}.cfg`);
    await page
      .getByRole("button", { name: "Добавить в группу сравнения", exact: true })
      .click();
  }
  await expect(selection).toContainText("Группа: 3 из максимум 20 устройств");
  await page.getByLabel("UUID устройства", { exact: true }).fill(device);
  await upload(
    page,
    normal(host)
      .replace("input ssh\n", "input ssh telnet\n")
      .replace("vlan 10", "vlan 20"),
    "candidate.cfg",
  );
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
  await page.getByLabel("Поиск по находкам").fill("Peer baseline");
  await page.locator(".finding-button").first().click();
  await expect(
    page.getByRole("region", { name: "Детали находки" }),
  ).toContainText("peer_baseline");
  await expect(
    page.getByRole("region", { name: "Детали находки" }),
  ).toContainText("Строки 5");
  await page.getByLabel("Поиск по находкам").fill("Reference deviation");
  await page.locator(".finding-button").first().click();
  await expect(
    page.getByRole("region", { name: "Детали находки" }),
  ).toContainText("expected_configuration");
  await page
    .getByText("Входы сравнения и профиль группы", { exact: true })
    .click();
  await expect(page.locator(".analysis-summary .json-view")).toContainText(
    '"sample_count": 3',
  );
  await expectNoOverflow(page);
  if (test.info().project.name === "desktop") {
    for (const width of [1150, 1024, 800]) {
      await page.setViewportSize({ width, height: 720 });
      await expectNoOverflow(page);
    }
    await page.setViewportSize({ width: 1280, height: 720 });
  }
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Подключить рабочую сессию" }),
  ).toBeVisible();
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(selection).toContainText("Эталон: Не выбран");
  await expect(selection).toContainText("Группа: 0 из максимум 20 устройств");
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await page.locator(".history-item").first().click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
  await page
    .getByText("Входы сравнения и профиль группы", { exact: true })
    .click();
  await expect(page.locator(".analysis-summary .json-view")).toContainText(
    '"sample_count": 3',
  );
});

test("a current snapshot cannot silently become its own selected reference", async ({
  page,
}) => {
  await connect(page);
  await upload(page, `hostname selected-${Date.now()}\n`);
  await page
    .getByRole("button", { name: "Выбрать как эталон", exact: true })
    .click();
  let runs = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/analyze"))
      runs += 1;
  });
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("Эталон должен");
  expect(runs).toBe(0);
  await page
    .getByRole("button", { name: "Убрать эталон", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
});

test("explicit training, model selection, held-out analysis and persisted ML history", async ({
  page,
}) => {
  test.setTimeout(60_000);
  await connect(page);
  const suffix = `${test.info().project.name}-${Date.now()}`;
  await page
    .getByText("Метки группы сравнения (необязательно)", { exact: true })
    .click();
  await page.getByLabel("Роль устройства", { exact: true }).fill("edge");
  await page.getByLabel("Класс площадки", { exact: true }).fill("branch");
  await page
    .getByLabel("Профиль сервиса", { exact: true })
    .fill(`model-${suffix}`);
  const text = (host: string, count: number) =>
    `hostname ${host}\naaa new-model\nip ssh version 2\n` +
    Array.from(
      { length: count },
      (_, n) => `vlan ${10 + n}\n name VLAN-${n}\n!\n`,
    ).join("");
  for (let n = 0; n < 8; n++) {
    await page.getByRole("button", { name: "Новое", exact: true }).click();
    await upload(page, text(`training-${suffix}-${n}`, 1 + (n % 7)));
    await page
      .getByRole("button", { name: "Добавить в обучение модели", exact: true })
      .click();
  }
  const registry = page.getByRole("region", { name: "Реестр моделей" });
  await expect(registry).toContainText("Обучающие снимки: 8");
  const trainingResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/models/isolation-forest") &&
      response.request().method() === "POST",
  );
  await registry
    .getByRole("button", { name: "Обучить и сохранить модель", exact: true })
    .click();
  const response = await trainingResponse;
  expect(response.status()).toBe(201);
  const model = await response.json();
  await expect(registry).toContainText(model.model_id);
  await expect(registry).toContainText("Не выбрана — ML не запускается");
  await registry
    .getByRole("button", {
      name: `Выбрать модель ${model.model_id.slice(0, 8)}`,
      exact: true,
    })
    .click();
  // The currently open training device cannot be analyzed by its own model.
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("обучающим устройствам");
  await page.getByRole("button", { name: "Новое", exact: true }).click();
  await upload(page, text(`held-out-${suffix}`, 30));
  const heldOutResponse = page.waitForResponse(
    (item) =>
      item.request().method() === "POST" && item.url().endsWith("/analyze"),
  );
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  const heldOutAnalysis = await (await heldOutResponse).json();
  await expect(
    page.getByRole("heading", { name: "Находки и доказательства" }),
  ).toBeVisible();
  await page
    .getByText("Модель и статистический результат", { exact: true })
    .click();
  await expect(page.locator(".analysis-summary")).toContainText(model.model_id);
  await page.getByLabel("Поиск по находкам").fill("structured-feature outlier");
  await page.locator(".finding-button").first().click();
  await expect(
    page.getByRole("region", { name: "Детали находки" }),
  ).toContainText("isolation_forest");
  await expectNoOverflow(page);
  if (test.info().project.name === "desktop") {
    for (const width of [1150, 1024, 800]) {
      await page.setViewportSize({ width, height: 720 });
      await expectNoOverflow(page);
    }
    await page.setViewportSize({ width: 1280, height: 720 });
  }
  await page.getByRole("button", { name: "Отключиться", exact: true }).click();
  expect(await localStorageState(page)).toEqual({ local: {}, session: {} });
  const historyResponse = () =>
    page.waitForResponse(
      (item) =>
        item.request().method() === "GET" &&
        new URL(item.url()).pathname === "/api/v1/analyses",
    );
  let history = historyResponse();
  await connect(page);
  await expect(registry).toContainText("Не выбрана — ML не запускается");
  await expect(registry).toContainText("Обучающие снимки: 0");
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  let records: { analysis_id: string }[] = await (await history).json();
  for (
    let index = 0;
    index < 10 &&
    !records.some((item) => item.analysis_id === heldOutAnalysis.analysis_id);
    index++
  ) {
    history = historyResponse();
    await page.getByRole("button", { name: "Далее", exact: true }).click();
    records = await (await history).json();
  }
  const savedAnalysis = page
    .locator(".history-item")
    .filter({ hasText: heldOutAnalysis.analysis_id.slice(0, 8) });
  await expect(savedAnalysis).toBeVisible();
  await savedAnalysis.click();
  await page
    .getByText("Модель и статистический результат", { exact: true })
    .click();
  await expect(page.locator(".analysis-summary")).toContainText(model.model_id);
});
