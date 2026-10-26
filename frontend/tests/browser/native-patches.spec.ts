import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { rolePermissions } from "../../src/contracts";
import { nativeControls } from "./native-patches-fixtures";

const digest = (raw: string) => createHash("sha256").update(raw).digest("hex");
const panel = (page: Page) =>
  page.getByRole("region", { name: "Native-кандидат без модели", exact: true });
const generationConsent = (page: Page) =>
  panel(page).getByLabel(
    "Разрешаю локальное создание native-кандидата из сохранённого оригинала",
    { exact: true },
  );
const retentionConsent = (page: Page) =>
  panel(page).getByLabel(
    /Разрешаю приватное хранение полного оригинала и кандидата/,
  );
type Options = {
  role?: "engineer" | "reader";
  lost?: boolean;
  missing?: boolean;
  corrupt?: boolean;
  selectionFailure?: boolean;
  selectionGate?: Promise<void>;
  generationGate?: Promise<void>;
};
async function setup(page: Page, index = 0, options: Options = {}) {
  const c = nativeControls[index]!,
    role = options.role ?? "engineer";
  const calls: {
    url: string;
    method: string;
    body: Record<string, unknown> | null;
  }[] = [];
  const saved = new Map<string, typeof c.candidate>();
  saved.set(c.candidate.candidate_id, structuredClone(c.candidate));
  let posts = 0;
  await page.route("**/api/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    const body = request.postDataJSON() as Record<string, unknown> | null;
    calls.push({ url: path + url.search, method: request.method(), body });
    const send = (json: unknown, status = 200) =>
      route.fulfill({ status, json });
    if (path === "/api/v1/session")
      return send({
        version: "service-access-0.3.0",
        role,
        permissions: rolePermissions[role],
        individual_identity_verified: false,
        device_scope: "all_saved_devices",
      });
    if (path === "/api/v1/configurations") return send([]);
    if (path === "/api/v1/analyses")
      return send(
        nativeControls.map((v) => ({
          analysis_id: v.analysis.analysis_id,
          configuration_id: v.analysis.configuration_id,
          device_id: v.analysis.device_id,
          created_at: v.analysis.created_at,
          status: v.analysis.status,
          finding_count: v.analysis.findings.length,
          policy_catalog_version: v.analysis.policy_catalog_version,
        })),
      );
    const byAnalysis = nativeControls.find(
      (v) => path === `/api/v1/analyses/${v.analysis.analysis_id}`,
    );
    if (byAnalysis) return send(byAnalysis.analysis);
    const bySnapshot = nativeControls.find(
      (v) => path === `/api/v1/configurations/${v.snapshot.configuration_id}`,
    );
    if (bySnapshot) return send(bySnapshot.snapshot);
    if (path.endsWith("/configuration-model-runs/capabilities"))
      return send({}, 503);
    if (path.endsWith("/explanation-capabilities")) return send({}, 503);
    if (path.includes("/native-patch-selection/")) {
      const selected = nativeControls.find((v) =>
        path.endsWith(v.analysis.analysis_id),
      )!;
      if (selected === c) await options.selectionGate;
      return options.selectionFailure
        ? send({}, 503)
        : send(selected.selection);
    }
    if (path.endsWith("/native-patches") && request.method() === "GET")
      return send(
        [...saved.values()].map((row) => ({
          ...c.summary,
          candidate_id: row.candidate_id,
          review_sha256: row.review_sha256,
        })),
      );
    if (path.endsWith("/native-patches") && request.method() === "POST") {
      posts++;
      const row = structuredClone(c.candidate) as unknown as Record<
        string,
        unknown
      >;
      row.candidate_id = body!.candidate_id;
      row.request = body;
      row.review_json = c.candidate.review_json.replaceAll(
        c.candidate.candidate_id,
        body!.candidate_id as string,
      );
      row.review_sha256 = digest(row.review_json as string);
      if (!options.missing || posts > 1)
        saved.set(
          body!.candidate_id as string,
          row as unknown as typeof c.candidate,
        );
      if ((options.lost || options.missing) && posts === 1)
        return send({}, 503);
      if (options.corrupt) row.native_commands = ["show running-config"];
      await options.generationGate;
      return send(row, 201);
    }
    if (path.includes("/native-patches/"))
      return saved.has(path.split("/").at(-1)!)
        ? send(saved.get(path.split("/").at(-1)!))
        : send({}, 404);
    return send([]);
  });
  await page.goto("/ui/");
  await page
    .getByLabel("API-токен", { exact: true })
    .fill("authored-native-browser-fixture-token");
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
  await expect(panel(page)).toBeVisible();
  await panel(page)
    .getByRole("button", { name: "Открыть native-кандидаты", exact: true })
    .click();
  return { c, calls, saved };
}
async function create(page: Page) {
  await generationConsent(page).check();
  await retentionConsent(page).check();
  await panel(page)
    .getByRole("button", { name: "Создать native-кандидат", exact: true })
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
  test(`native ${nativeControls[index]!.vendor}: strict retention consent, safe saved commands and source-bound history without LLM`, async ({
    page,
  }, info) => {
    const { c, calls } = await setup(page, index);
    const createButton = panel(page).getByRole("button", {
      name: "Создать native-кандидат",
      exact: true,
    });
    await expect(createButton).toBeDisabled();
    await generationConsent(page).check();
    await expect(createButton).toBeDisabled();
    expect(calls.filter((v) => v.method === "POST")).toHaveLength(0);
    await retentionConsent(page).check();
    await createButton.click();
    await expect(
      panel(page).getByRole("heading", {
        name: "Сохранённый кандидат — требуется рассмотрение",
        exact: true,
      }),
    ).toBeVisible();
    await expect(panel(page).locator(".native-commands")).toHaveText(
      c.candidate.native_commands.join("\n"),
    );
    await expect(
      panel(page).getByText(
        /Формальная квалификация не доказана; качество и оценки не калиброваны/,
      ),
    ).toBeVisible();
    const writes = calls.filter((v) => v.method === "POST");
    expect(writes).toHaveLength(1);
    expect(writes[0]!.body).toMatchObject({
      allow_local_native_generation: true,
      allow_private_candidate_retention: true,
      analysis_sha256: c.selection.analysis_sha256,
      canonical_sha256: c.selection.canonical_sha256,
    });
    expect(writes[0]!.url).toBe(
      `/api/v2/configurations/${c.snapshot.configuration_id}/native-patches`,
    );
    await panel(page)
      .getByRole("button", { name: "Обновить native-историю", exact: true })
      .click();
    await panel(page)
      .getByRole("button", {
        name: new RegExp(
          `Открыть native-кандидат ${(writes[0]!.body!.candidate_id as string).slice(0, 8)}`,
        ),
      })
      .click();
    expect(calls.filter((v) => v.method === "POST")).toHaveLength(1);
    await expect(
      panel(page).getByRole("button", {
        name: /скачать|применить|Batfish|ML|утвердить/i,
      }),
    ).toHaveCount(0);
    await layout(page);
    await page.screenshot({
      path: info.outputPath(`${c.vendor}-safe-native.png`),
      fullPage: true,
    });
  });
test("reader opens immutable safe history even when new selection is unavailable", async ({
  page,
}) => {
  const { c, calls } = await setup(page, 0, {
    role: "reader",
    selectionFailure: true,
  });
  await expect(generationConsent(page)).toHaveCount(0);
  await expect(
    panel(page).getByRole("button", {
      name: "Создать native-кандидат",
      exact: true,
    }),
  ).toHaveCount(0);
  await panel(page)
    .getByRole("button", {
      name: new RegExp(
        `Открыть native-кандидат ${c.candidate.candidate_id.slice(0, 8)}`,
      ),
    })
    .click();
  await expect(panel(page).locator(".native-commands")).toHaveText(
    c.candidate.native_commands.join("\n"),
  );
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(0);
  await layout(page);
});
test("lost completion reconciles committed result with GET and no automatic POST", async ({
  page,
}) => {
  const { calls } = await setup(page, 0, { lost: true });
  await create(page);
  await expect(panel(page).getByText(/Итог отправки неизвестен/)).toBeVisible();
  await expect(
    panel(page).getByRole("button", {
      name: "Создать native-кандидат",
      exact: true,
    }),
  ).toBeDisabled();
  const sent = calls.find((v) => v.method === "POST")!;
  await panel(page)
    .getByRole("button", {
      name: "Прочитать результат native-отправки",
      exact: true,
    })
    .click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Сохранённый кандидат — требуется рассмотрение",
      exact: true,
    }),
  ).toBeVisible();
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(1);
  expect(
    calls.some(
      (v) =>
        v.method === "GET" &&
        v.url.endsWith(`/native-patches/${sent.body!.candidate_id}`),
    ),
  ).toBe(true);
  await layout(page);
});
test("unknown absent result keeps exact intent and explicit replay uses same UUID and consent", async ({
  page,
}) => {
  const { calls } = await setup(page, 1, { missing: true });
  await create(page);
  await expect(panel(page).getByText(/Итог отправки неизвестен/)).toBeVisible();
  await panel(page)
    .getByRole("button", {
      name: "Прочитать результат native-отправки",
      exact: true,
    })
    .click();
  await expect(
    panel(page).getByText(/Это не подтверждает отмену отправки/),
  ).toBeVisible();
  await panel(page)
    .getByRole("button", {
      name: "Повторить native-запрос с тем же UUID",
      exact: true,
    })
    .click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Сохранённый кандидат — требуется рассмотрение",
      exact: true,
    }),
  ).toBeVisible();
  const posts = calls.filter((v) => v.method === "POST");
  expect(posts).toHaveLength(2);
  expect(posts[0]!.body).toEqual(posts[1]!.body);
  await layout(page);
});
test("corrupted native commands are rejected and hidden", async ({ page }) => {
  const { calls } = await setup(page, 0, { corrupt: true });
  await create(page);
  await expect(page.getByRole("alert")).toContainText(
    "Ответ API не соответствует поддерживаемому контракту",
  );
  await expect(panel(page).locator(".native-commands")).toHaveCount(0);
  await expect(
    panel(page).getByText("show running-config", { exact: true }),
  ).toHaveCount(0);
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(1);
});
test("late selection from a replaced analysis cannot unlock the new panel", async ({
  page,
}) => {
  let release!: () => void;
  const selectionGate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const { calls } = await setup(page, 0, { selectionGate });
  await page
    .locator(".history-item")
    .filter({ hasText: nativeControls[1]!.analysis.analysis_id.slice(0, 8) })
    .click();
  await expect(
    panel(page).getByRole("button", {
      name: "Открыть native-кандидаты",
      exact: true,
    }),
  ).toBeVisible();
  const completed = page.waitForResponse((r) =>
    r
      .url()
      .includes(
        `/native-patch-selection/${nativeControls[0]!.analysis.analysis_id}`,
      ),
  );
  release();
  await completed;
  await expect(generationConsent(page)).toHaveCount(0);
  await expect(panel(page).locator(".native-commands")).toHaveCount(0);
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(0);
});
test("late generation cannot display or report an old candidate under a new analysis", async ({
  page,
}) => {
  let release!: () => void;
  const generationGate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const { calls } = await setup(page, 0, { generationGate });
  const started = page.waitForRequest(
    (r) => r.method() === "POST" && r.url().endsWith("/native-patches"),
  );
  await create(page);
  await started;
  await page
    .locator(".history-item")
    .filter({ hasText: nativeControls[1]!.analysis.analysis_id.slice(0, 8) })
    .click();
  await expect(
    panel(page).getByRole("button", {
      name: "Открыть native-кандидаты",
      exact: true,
    }),
  ).toBeVisible();
  const completed = page.waitForResponse(
    (r) =>
      r.request().method() === "POST" && r.url().endsWith("/native-patches"),
  );
  release();
  await completed;
  await expect(panel(page).locator(".native-commands")).toHaveCount(0);
  await expect(
    panel(page).getByRole("heading", {
      name: "Сохранённый кандидат — требуется рассмотрение",
      exact: true,
    }),
  ).toHaveCount(0);
  expect(calls.filter((v) => v.method === "POST")).toHaveLength(1);
  await layout(page);
});
