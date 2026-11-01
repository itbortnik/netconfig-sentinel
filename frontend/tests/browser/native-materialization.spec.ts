import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { rolePermissions, stableJson } from "../../src/contracts";
import { materializationControl } from "./native-materialization-fixtures";

// Authored mocked transport controls; these cases do not establish actual execution.
const area = (page: Page) =>
  page.getByRole("region", {
    name: "Создание обычного черновика из native-кандидата",
    exact: true,
  });
const originArea = (page: Page) =>
  page.getByRole("region", {
    name: "Происхождение выбранного снимка",
    exact: true,
  });
const createName = "Создать снимок и обычный черновик";
const localConsent =
  "Разрешаю локальное создание снимка и обычного черновика из выбранного native-кандидата";
type Options = {
  reader?: boolean;
  saved?: boolean;
  lost?: boolean;
  absent?: boolean;
  corrupt?: boolean;
  originFailure?: boolean;
  secondDraft?: boolean;
  externalBusyGate?: Promise<void>;
};
async function setup(page: Page, index = 0, options: Options = {}) {
  const c = materializationControl(index);
  const secondDraft = {
    ...structuredClone(c.draft),
    patch_id: "f55e36d3-943b-4e59-8779-c3090376569f",
    draft_sha256: "b".repeat(64),
  };
  let saved = options.saved ?? false,
    posts = 0;
  const calls: {
    method: string;
    path: string;
    body: Record<string, unknown> | null;
  }[] = [];
  const prefix = `/api/v2/configurations/${c.candidate.configuration_id}/native-patches/${c.candidate.candidate_id}`;
  const summary = (snapshot: typeof c.after) => ({
    configuration_id: snapshot.configuration_id,
    device_id: snapshot.device_id,
    created_at: snapshot.created_at,
    filename: snapshot.canonical.source.filename,
    source_sha256: snapshot.canonical.source.sha256,
    hostname: snapshot.canonical.device.hostname,
    vendor: snapshot.canonical.device.vendor,
    platform: snapshot.canonical.device.platform,
    parser_confidence: 1,
    warning_count: 0,
    unparsed_count: 0,
  });
  await page.route("**/api/**", async (route) => {
    const r = route.request(),
      path = new URL(r.url()).pathname,
      body = r.postDataJSON() as Record<string, unknown> | null;
    calls.push({ method: r.method(), path, body });
    const send = (json: unknown, status = 200) =>
      route.fulfill({ json, status });
    if (path === "/api/v1/session")
      return send({
        version: "service-access-0.3.0",
        role: options.reader ? "reader" : "engineer",
        permissions: rolePermissions[options.reader ? "reader" : "engineer"],
        individual_identity_verified: false,
        device_scope: "all_saved_devices",
      });
    if (path === "/api/v1/configurations")
      return send(saved ? [summary(c.after)] : []);
    if (path === `/api/v1/configurations/${c.after.configuration_id}`)
      return send(c.after);
    if (path === `/api/v1/configurations/${c.after.configuration_id}/analyze`) {
      await options.externalBusyGate;
      return send({}, 503);
    }
    if (path === `/api/v1/configurations/${c.snapshot.configuration_id}`)
      return send(c.snapshot);
    if (path === "/api/v1/analyses")
      return send([
        {
          analysis_id: c.analysis.analysis_id,
          configuration_id: c.analysis.configuration_id,
          device_id: c.analysis.device_id,
          created_at: c.analysis.created_at,
          status: c.analysis.status,
          finding_count: c.analysis.findings.length,
          policy_catalog_version: c.analysis.policy_catalog_version,
        },
      ]);
    if (path === `/api/v1/analyses/${c.analysis.analysis_id}`)
      return send(c.analysis);
    if (path.endsWith("/native-patch-selection/" + c.analysis.analysis_id))
      return send(c.selection);
    if (path.endsWith("/native-patches")) return send([c.summary]);
    if (path === prefix) return send(c.candidate);
    if (path === prefix + "/materialization") {
      if (r.method() === "POST") {
        posts++;
        const row = c.materialization;
        row.request = body as unknown as typeof row.request;
        row.patch_id = body!.patch_id as string;
        row.after.configuration_id = body!.after_configuration_id as string;
        c.after.configuration_id = row.after.configuration_id;
        c.draft.patch_id = row.patch_id;
        c.draft.diff.after.configuration_id = row.after.configuration_id;
        const { review_json: _json, review_sha256: _sha, ...proof } = row;
        row.review_json = stableJson(proof);
        row.review_sha256 = createHash("sha256")
          .update(row.review_json)
          .digest("hex");
        saved = !options.absent || posts > 1;
        if ((options.lost || options.absent) && posts === 1)
          return send({}, 503);
        return send(
          options.corrupt ? { ...row, review_sha256: "f".repeat(64) } : row,
          201,
        );
      }
      return saved ? send(c.materialization) : send({}, 404);
    }
    if (path.endsWith("/native-origin"))
      return options.originFailure
        ? send({}, 503)
        : path.includes(c.after.configuration_id) && saved
          ? send(c.materialization)
          : send({}, 404);
    if (path === `/api/v1/patches/${c.draft.patch_id}`) return send(c.draft);
    if (path === `/api/v1/patches/${secondDraft.patch_id}`)
      return send(secondDraft);
    if (path === "/api/v1/patches")
      return send(
        saved
          ? [c.draft, ...(options.secondDraft ? [secondDraft] : [])].map(
              (draft) => ({
                version: "snapshot-patch-summary-0.1.0",
                patch_id: draft.patch_id,
                created_at: draft.created_at,
                draft_sha256: draft.draft_sha256,
                status: "draft",
                before: c.materialization.before,
                after: c.materialization.after,
                coverage: "supported_complete",
                change_count: 1,
              }),
            )
          : [],
      );
    if (
      path.endsWith("/capabilities") ||
      path.endsWith("/explanation-capabilities")
    )
      return send({}, 503);
    return send([]);
  });
  await page.goto("/ui/");
  await page
    .getByLabel("API-токен", { exact: true })
    .fill("authored-materialization-mock-token");
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: c.analysis.analysis_id.slice(0, 8) })
    .click();
  const native = page.getByRole("region", {
    name: "Native-кандидат без модели",
    exact: true,
  });
  await native
    .getByRole("button", { name: "Открыть native-кандидаты", exact: true })
    .click();
  await native
    .getByRole("button", {
      name: new RegExp(
        `Открыть native-кандидат ${c.candidate.candidate_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(area(page)).toBeVisible();
  return { c, calls, secondDraft };
}
async function create(page: Page) {
  await area(page).getByLabel(localConsent, { exact: true }).check();
  await area(page)
    .getByLabel(/Разрешаю новую приватную копию полного исходника/)
    .check();
  await area(page)
    .getByRole("button", { name: createName, exact: true })
    .click();
}
async function layout(page: Page) {
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  expect(
    await page.evaluate(() => ({
      local: { ...localStorage },
      session: { ...sessionStorage },
    })),
  ).toEqual({ local: {}, session: {} });
}
for (const index of [0, 1])
  test(`materialization ${index}: separate two consents, saved draft and generated origin through ordinary history`, async ({
    page,
  }, info) => {
    const { c, calls } = await setup(page, index);
    const button = area(page).getByRole("button", {
      name: createName,
      exact: true,
    });
    await expect(button).toBeDisabled();
    await area(page).getByLabel(localConsent, { exact: true }).check();
    await expect(button).toBeDisabled();
    expect(calls.filter((v) => v.method === "POST")).toHaveLength(0);
    await area(page)
      .getByLabel(/Разрешаю новую приватную копию полного исходника/)
      .check();
    await button.click();
    await expect(
      area(page).getByLabel("Созданный обычный черновик"),
    ).toBeVisible();
    const posts = calls.filter((v) => v.method === "POST");
    expect(posts).toHaveLength(1);
    expect(posts[0]!.body).toEqual(c.materialization.request);
    await area(page)
      .getByRole("button", {
        name: "Открыть созданный снимок и черновик",
        exact: true,
      })
      .click();
    await expect(
      page.getByLabel("Сохранённый черновик", { exact: true }),
    ).toBeVisible();
    await expect(originArea(page)).toContainText(
      "Сгенерированный снимок из native-кандидата",
    );
    await expect(
      page.getByRole("region", { name: "Черновики изменений", exact: true }),
    ).toContainText("Формальная проверка: не запускалась");
    expect(calls.filter((v) => v.method === "POST")).toHaveLength(1);
    await page
      .locator(".history-item")
      .filter({ hasText: c.after.configuration_id.slice(0, 8) })
      .click();
    await expect(originArea(page)).toContainText(
      "Наблюдение состояния устройства не подтверждено",
    );
    await originArea(page)
      .getByRole("button", {
        name: "Открыть связанный обычный черновик",
        exact: true,
      })
      .click();
    await expect(
      page.getByLabel("Сохранённый черновик", { exact: true }),
    ).toBeVisible();
    expect(calls.filter((v) => v.method === "POST")).toHaveLength(1);
    await layout(page);
    await originArea(page).screenshot({
      path: info.outputPath(`generated-origin-${index}.png`),
    });
  });
test("materialization lost completion reconciles GET without a second POST", async ({
  page,
}) => {
  const { calls } = await setup(page, 0, { lost: true });
  await create(page);
  await expect(area(page)).toContainText("Итог создания черновика неизвестен");
  await area(page)
    .getByRole("button", {
      name: "Прочитать результат создания черновика",
      exact: true,
    })
    .click();
  await expect(
    area(page).getByLabel("Созданный обычный черновик"),
  ).toBeVisible();
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(1);
});
test("materialization unknown absent result preserves both UUIDs and exact consent on explicit replay", async ({
  page,
}) => {
  const { calls } = await setup(page, 1, { absent: true });
  await create(page);
  await expect(area(page)).toContainText("Итог создания черновика неизвестен");
  await area(page)
    .getByRole("button", {
      name: "Прочитать результат создания черновика",
      exact: true,
    })
    .click();
  await expect(area(page)).toContainText("Это не подтверждает отмену отправки");
  for (const checkbox of await area(page).getByRole("checkbox").all())
    await expect(checkbox).toBeDisabled();
  await area(page)
    .getByRole("button", {
      name: "Повторить создание с теми же UUID",
      exact: true,
    })
    .click();
  await expect(
    area(page).getByLabel("Созданный обычный черновик"),
  ).toBeVisible();
  const posts = calls.filter((v) => v.method === "POST");
  expect(posts).toHaveLength(2);
  expect(posts[0]!.body).toEqual(posts[1]!.body);
  await layout(page);
});
test("materialization reader can open saved generated origin and draft without creating or verifying", async ({
  page,
}) => {
  const { calls } = await setup(page, 0, { reader: true, saved: true });
  await expect(area(page).getByRole("checkbox")).toHaveCount(0);
  await expect(
    area(page).getByRole("button", { name: createName, exact: true }),
  ).toHaveCount(0);
  await area(page)
    .getByRole("button", {
      name: "Открыть созданный снимок и черновик",
      exact: true,
    })
    .click();
  await expect(originArea(page)).toContainText(
    "Сгенерированный снимок из native-кандидата",
  );
  await expect(
    page.getByRole("button", {
      name: "Локальная проверка черновика",
      exact: true,
    }),
  ).toBeDisabled();
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(0);
});
test("materialization origin read failure remains unknown in ordinary history", async ({
  page,
}) => {
  const { c, calls } = await setup(page, 0, {
    saved: true,
    originFailure: true,
  });
  await page.getByRole("button", { name: "Конфигурации", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: c.after.configuration_id.slice(0, 8) })
    .click();
  await expect(originArea(page)).toContainText(
    "Происхождение снимка неизвестно",
  );
  await expect(originArea(page)).not.toContainText("не зарегистрировано");
  await expect(originArea(page)).not.toContainText(
    "Сгенерированный снимок из native-кандидата",
  );
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(0);
});
test("materialization invalid proof hides links and remains reconcilable", async ({
  page,
}) => {
  const { calls } = await setup(page, 0, { corrupt: true });
  await create(page);
  await expect(page.getByRole("alert")).toContainText(
    "Привязка созданного черновика не подтверждена",
  );
  await expect(area(page).getByLabel("Созданный обычный черновик")).toHaveCount(
    0,
  );
  await expect(
    area(page).getByRole("button", { name: createName, exact: true }),
  ).toBeDisabled();
  await area(page)
    .getByRole("button", {
      name: "Прочитать результат создания черновика",
      exact: true,
    })
    .click();
  await expect(
    area(page).getByLabel("Созданный обычный черновик"),
  ).toBeVisible();
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(1);
});

test("materialization opens its draft once and preserves a different manual selection across external busy state", async ({
  page,
}) => {
  let release!: () => void;
  const externalBusyGate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const { c, calls, secondDraft } = await setup(page, 0, {
    saved: true,
    secondDraft: true,
    externalBusyGate,
  });
  const getOriginDraft = () =>
    calls.filter(
      (call) =>
        call.method === "GET" &&
        call.path === `/api/v1/patches/${c.draft.patch_id}`,
    );
  await area(page)
    .getByRole("button", {
      name: "Открыть созданный снимок и черновик",
      exact: true,
    })
    .click();
  const selected = page.getByLabel("Сохранённый черновик", { exact: true });
  await expect(
    selected.getByRole("heading", { level: 4 }).first(),
  ).toContainText(c.draft.patch_id.slice(0, 8));
  expect(getOriginDraft()).toHaveLength(1);
  await page
    .getByRole("button", { name: "Обновить черновики", exact: true })
    .click();
  await page
    .getByRole("button", {
      name: new RegExp(`Открыть черновик ${secondDraft.patch_id.slice(0, 8)}`),
    })
    .click();
  await expect(
    selected.getByRole("heading", { level: 4 }).first(),
  ).toContainText(secondDraft.patch_id.slice(0, 8));
  expect(getOriginDraft()).toHaveLength(1);
  const started = page.waitForRequest(
    (request) =>
      request.url().endsWith("/analyze") && request.method() === "POST",
  );
  await page
    .getByRole("button", { name: "Анализировать снимок", exact: true })
    .click();
  await started;
  await expect(
    page.getByRole("button", {
      name: "Локальная проверка черновика",
      exact: true,
    }),
  ).toBeDisabled();
  release();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(
    page.getByRole("button", {
      name: "Локальная проверка черновика",
      exact: true,
    }),
  ).toBeEnabled();
  await expect(
    selected.getByRole("heading", { level: 4 }).first(),
  ).toContainText(secondDraft.patch_id.slice(0, 8));
  expect(getOriginDraft()).toHaveLength(1);
  await originArea(page)
    .getByRole("button", {
      name: "Открыть связанный обычный черновик",
      exact: true,
    })
    .click();
  await expect(
    selected.getByRole("heading", { level: 4 }).first(),
  ).toContainText(c.draft.patch_id.slice(0, 8));
  expect(getOriginDraft()).toHaveLength(2);
});
