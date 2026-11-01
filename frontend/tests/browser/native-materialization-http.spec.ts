import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import type { APIRequestContext, Page } from "@playwright/test";
import { analysisSchema, snapshotSchema } from "../../src/contracts";
import {
  nativePatchCandidateSchema,
  nativeProofMatches,
} from "../../src/nativePatches";
import {
  nativeMaterializationSchema,
  nativeMaterializationProofMatches,
  nativeMaterializationBound,
  nativeOriginDraftBound,
  nativeOriginSnapshotBound,
} from "../../src/nativeMaterializations";
import { patchDraftSchema } from "../../src/patches";
import { sourceDeterministicRecheckSchema } from "../../src/sourceDeterministicRecheck";

// Real loopback HTTP, parser, native generator, atomic bridge, deterministic recheck,
// encrypted disposable storage and process restart. Two reused authored families,
// repeated at desktop/mobile sizes, provide functional evidence only.
const ADMIN = "native-http-test-admin-service-token-0000001";
const ENGINEER = "native-http-test-engineer-service-token-001";
const READER = "native-http-test-reader-service-token-00001";
const CONTROL = "native-http-test-owned-control-token-000001";
const markers = [
  "owned-native-password-marker",
  "owned-native-community-marker",
];
const headers = (token: string) => ({ Authorization: `Bearer ${token}` });
const safe = (wire: string) =>
  markers.every((marker) => !wire.includes(marker));
const sha = (wire: string) => createHash("sha256").update(wire).digest("hex");
const nativeArea = (page: Page) =>
  page.getByRole("region", { name: "Native-кандидат без модели", exact: true });
const materialArea = (page: Page) =>
  page.getByRole("region", {
    name: "Создание обычного черновика из native-кандидата",
    exact: true,
  });
const originArea = (page: Page) =>
  page.getByRole("region", {
    name: "Происхождение выбранного снимка",
    exact: true,
  });
const deterministicArea = (page: Page) =>
  page.getByRole("region", {
    name: "Перепроверка исходного анализа",
    exact: true,
  });
type State = {
  pid: number;
  history_only: boolean;
  generator_calls: number;
  materialization_calls: number;
  deterministic_calls: number;
  forbidden_calls: number;
  model_configured: boolean;
  network_engine_configured: boolean;
};
async function state(request: APIRequestContext): Promise<State> {
  const response = await request.get("/_test/native/state", {
    headers: headers(CONTROL),
  });
  expect(response.status()).toBe(200);
  return response.json() as Promise<State>;
}
async function restart(request: APIRequestContext, mode: "normal" | "history") {
  const before = await state(request);
  expect(
    (
      await request.post(`/_test/native/restart/${mode}`, {
        headers: headers(CONTROL),
      })
    ).status(),
  ).toBe(200);
  await expect
    .poll(
      async () => {
        try {
          const next = await state(request);
          return (
            next.pid !== before.pid &&
            next.history_only === (mode === "history")
          );
        } catch {
          return false;
        }
      },
      { timeout: 20_000, intervals: [100, 200, 400] },
    )
    .toBe(true);
  return { before, after: await state(request) };
}
async function connect(page: Page, token: string) {
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Загрузка истории…")).toBeHidden();
}
async function safeDOM(page: Page) {
  expect(safe(await page.content())).toBe(true);
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
function source(vendor: "cisco" | "juniper") {
  return vendor === "cisco"
    ? `hostname owned\nip ssh version 2\nusername operator privilege 15 secret 0 ${markers[0]}\nsnmp-server community ${markers[1]} RO\nline vty 0 4\n transport input ssh telnet\n!\n`
    : `set system host-name owned\nset system services ssh\nset system login user operator authentication encrypted-password "${markers[0]}"\nset snmp community ${markers[1]} authorization read-only\nset system services telnet\n`;
}
async function privateSummary(request: APIRequestContext, candidate: string) {
  const response = await request.get(
    `/_test/native/materialized/${candidate}`,
    { headers: headers(CONTROL) },
  );
  expect(response.status()).toBe(200);
  const wire = await response.text();
  expect(safe(wire)).toBe(true);
  return JSON.parse(wire) as Record<string, unknown>;
}
test.afterEach(async ({ request }, info) => {
  if (
    info.project.name === "mobile" &&
    info.title.startsWith("actual materialization HTTP juniper:")
  ) {
    expect(
      (
        await request.post("/_test/native/shutdown", {
          headers: headers(CONTROL),
        })
      ).status(),
    ).toBe(200);
    let closed = 0;
    await expect
      .poll(
        async () => {
          try {
            await request.get("/_test/native/state", {
              headers: headers(CONTROL),
              timeout: 1000,
            });
            closed = 0;
          } catch {
            closed++;
          }
          return closed >= 2;
        },
        { timeout: 10_000, intervals: [100, 200, 400] },
      )
      .toBe(true);
    const cleanupReceipt = `../artifacts/native-materialization-http-browser-${process.env.NETCONFIG_NATIVE_MATERIALIZATION_HTTP_ATTEMPT}-cleanup.json`;
    await expect
      .poll(
        async () => {
          try {
            return JSON.parse(await readFile(cleanupReceipt, "utf8"));
          } catch {
            return null;
          }
        },
        { timeout: 10_000, intervals: [100, 200, 400] },
      )
      .toEqual({
        version: "owned-native-materialization-cleanup-0.1.0",
        owned_temporary_storage_removed: true,
        supervisor_normal_exit: true,
      });
  }
});
for (const vendor of ["cisco", "juniper"] as const)
  test(`actual materialization HTTP ${vendor}: generation, atomic draft, explicit policy recheck and immutable history after restart`, async ({
    page,
  }, info) => {
    const previous = await state(page.request);
    if (
      previous.history_only ||
      previous.generator_calls ||
      previous.materialization_calls ||
      previous.deterministic_calls ||
      previous.forbidden_calls
    )
      await restart(page.request, "normal");
    expect(await state(page.request)).toMatchObject({
      history_only: false,
      generator_calls: 0,
      materialization_calls: 0,
      deterministic_calls: 0,
      forbidden_calls: 0,
      model_configured: false,
      network_engine_configured: false,
    });
    expect(
      (
        await page.request.get("/_test/native/materialized/" + randomUUID())
      ).status(),
    ).toBe(403);
    const upload = await page.request.post("/api/v1/configurations", {
      headers: headers(ADMIN),
      data: {
        device_id: randomUUID(),
        filename: "owned-native-materialization.cfg",
        content: source(vendor),
        retain_original_source: true,
      },
    });
    expect(upload.status()).toBe(201);
    const beforeWire = await upload.text();
    expect(safe(beforeWire)).toBe(true);
    const before = snapshotSchema.parse(JSON.parse(beforeWire));
    expect(before.canonical.parser_confidence).toBe(1);
    const analyzed = await page.request.post(
      `/api/v1/configurations/${before.configuration_id}/analyze`,
      { headers: headers(ADMIN), data: {} },
    );
    expect(analyzed.status()).toBe(201);
    const analysisWire = await analyzed.text();
    expect(safe(analysisWire)).toBe(true);
    const analysis = analysisSchema.parse(JSON.parse(analysisWire));
    await connect(page, ENGINEER);
    await page.getByRole("button", { name: "Анализы", exact: true }).click();
    await page
      .locator(".history-item")
      .filter({ hasText: analysis.analysis_id.slice(0, 8) })
      .click();
    await nativeArea(page)
      .getByRole("button", { name: "Открыть native-кандидаты", exact: true })
      .click();
    await nativeArea(page)
      .getByLabel(
        "Разрешаю локальное создание native-кандидата из сохранённого оригинала",
        { exact: true },
      )
      .check();
    await nativeArea(page)
      .getByLabel(/Разрешаю приватное хранение полного оригинала и кандидата/)
      .check();
    const nativePrefix = `/api/v2/configurations/${before.configuration_id}/native-patches`;
    const nativeResponse = page.waitForResponse(
      (r) => r.url().endsWith(nativePrefix) && r.request().method() === "POST",
    );
    await nativeArea(page)
      .getByRole("button", { name: "Создать native-кандидат", exact: true })
      .click();
    const generated = await nativeResponse;
    expect(generated.status()).toBe(201);
    const candidateWire = await generated.text();
    expect(safe(candidateWire)).toBe(true);
    const candidate = nativePatchCandidateSchema.parse(
      JSON.parse(candidateWire),
    );
    expect(await nativeProofMatches(candidate)).toBe(true);
    const route = `${nativePrefix}/${candidate.candidate_id}/materialization`;
    const unusedIntent = {
      version: "native-materialization-request-0.1.0",
      after_configuration_id: randomUUID(),
      patch_id: randomUUID(),
      native_review_sha256: candidate.review_sha256,
      allow_local_source_materialization: true,
      allow_private_candidate_source_retention: true,
    };
    const denied = await page.request.post(route, {
      headers: headers(READER),
      data: unusedIntent,
    });
    expect(denied.status()).toBe(403);
    expect(safe(await denied.text())).toBe(true);
    const noConsent = await page.request.post(route, {
      headers: headers(ENGINEER),
      data: {
        ...unusedIntent,
        allow_private_candidate_source_retention: false,
      },
    });
    expect(noConsent.status()).toBe(400);
    expect(safe(await noConsent.text())).toBe(true);
    const create = materialArea(page).getByRole("button", {
      name: "Создать снимок и обычный черновик",
      exact: true,
    });
    await expect(create).toBeDisabled();
    await materialArea(page)
      .getByLabel(
        "Разрешаю локальное создание снимка и обычного черновика из выбранного native-кандидата",
        { exact: true },
      )
      .check();
    await expect(create).toBeDisabled();
    expect((await state(page.request)).materialization_calls).toBe(0);
    await materialArea(page)
      .getByLabel(/Разрешаю новую приватную копию полного исходника/)
      .check();
    const bridgeResponse = page.waitForResponse(
      (r) => r.url().endsWith(route) && r.request().method() === "POST",
    );
    await create.click();
    const bridged = await bridgeResponse;
    expect(bridged.status()).toBe(201);
    const materializationWire = await bridged.text();
    expect(safe(materializationWire)).toBe(true);
    const record = nativeMaterializationSchema.parse(
      JSON.parse(materializationWire),
    );
    expect(await nativeMaterializationProofMatches(record)).toBe(true);
    expect(nativeMaterializationBound(record, candidate)).toBe(true);
    expect(record).toMatchObject({
      origin: "generated_native_candidate",
      status: "draft_created",
      formal_qualification: "not_proven",
      fresh_policy_recheck_performed: false,
      model_recheck_performed: false,
      network_verification_performed: false,
      individual_identity_verified: false,
      approved: false,
      applied: false,
    });
    const afterResponse = await page.request.get(
      `/api/v1/configurations/${record.after.configuration_id}`,
      { headers: headers(READER) },
    );
    expect(afterResponse.status()).toBe(200);
    const afterWire = await afterResponse.text();
    expect(safe(afterWire)).toBe(true);
    const after = snapshotSchema.parse(JSON.parse(afterWire));
    expect(nativeOriginSnapshotBound(record, after)).toBe(true);
    const draftResponse = await page.request.get(
      `/api/v1/patches/${record.patch_id}`,
      { headers: headers(READER) },
    );
    expect(draftResponse.status()).toBe(200);
    const draftWire = await draftResponse.text();
    expect(safe(draftWire)).toBe(true);
    const draft = patchDraftSchema.parse(JSON.parse(draftWire));
    expect(nativeOriginDraftBound(record, draft)).toBe(true);
    expect(draft.status).toBe("draft");
    const privateBefore = await privateSummary(
      page.request,
      candidate.candidate_id,
    );
    expect(privateBefore).toMatchObject({
      retained_after_present: true,
      exact_private_candidate_source: true,
      both_markers_in_retained_after: true,
      ciphertexts_omit_markers: true,
      original_source_present: true,
      ordinary_draft_status: "draft",
      local_verifications: 0,
      deterministic_attempts: 0,
      domain_creation_events: {
        "configuration.created": 1,
        "configuration.source_retained": 1,
        "patch.draft_created": 1,
        "native_patch.materialized": 1,
      },
    });
    expect(await state(page.request)).toMatchObject({
      generator_calls: 1,
      materialization_calls: 1,
      deterministic_calls: 0,
    });
    const operation = bridged.headers()["x-operation-id"];
    expect(Boolean(operation)).toBe(true);
    const audit = await page.request.get(
      `/api/v1/operation-audit/${operation}`,
      { headers: headers(ADMIN) },
    );
    expect(audit.status()).toBe(200);
    expect(safe(await audit.text())).toBe(true);
    await materialArea(page)
      .getByRole("button", {
        name: "Открыть созданный снимок и черновик",
        exact: true,
      })
      .click();
    await expect(originArea(page)).toContainText(
      "Сгенерированный снимок из native-кандидата",
    );
    await expect(
      page.getByLabel("Сохранённый черновик", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("region", { name: "Черновики изменений", exact: true }),
    ).toContainText("Формальная проверка: не запускалась");
    await deterministicArea(page)
      .getByRole("button", {
        name: "Открыть перепроверку анализа",
        exact: true,
      })
      .click();
    await deterministicArea(page)
      .getByLabel("UUID сохранённого анализа до изменения", { exact: true })
      .fill(analysis.analysis_id);
    await deterministicArea(page)
      .getByRole("button", {
        name: "Загрузить исходный анализ политик и сравнений",
        exact: true,
      })
      .click();
    await expect(
      deterministicArea(page).getByLabel("Выбранный исходный анализ", {
        exact: true,
      }),
    ).toBeVisible();
    const rerun = deterministicArea(page).getByRole("button", {
      name: "Пересчитать исходный анализ до и после",
      exact: true,
    });
    await expect(rerun).toBeDisabled();
    expect((await state(page.request)).deterministic_calls).toBe(0);
    await deterministicArea(page)
      .getByLabel(/Разрешаю отдельную локальную перепроверку исходного анализа/)
      .check();
    const deterministicRoute = `/api/v2/patches/${record.patch_id}/deterministic-rechecks`;
    const recheckResponse = page.waitForResponse(
      (r) =>
        r.url().endsWith(deterministicRoute) && r.request().method() === "POST",
    );
    await rerun.click();
    const rechecked = await recheckResponse;
    expect(rechecked.status()).toBe(201);
    const recheckWire = await rechecked.text();
    expect(safe(recheckWire)).toBe(true);
    const recheck = sourceDeterministicRecheckSchema.parse(
      JSON.parse(recheckWire),
    );
    expect(recheck).toMatchObject({
      execution_status: "completed",
      status: "needs_review",
      formal_verification: "not_run",
      calibrated: false,
      quality_proven: false,
      approved: false,
      applied: false,
    });
    const report = recheck.outcome?.report;
    expect(report?.version).toBe("source-deterministic-report-0.1.0");
    if (report?.version !== "source-deterministic-report-0.1.0")
      throw new Error("Expected complete policy recheck report");
    expect(
      report.before.policy_findings.some(
        (f) => f.category === "management.telnet_enabled",
      ),
    ).toBe(true);
    expect(
      report.after.policy_findings.some(
        (f) => f.category === "management.telnet_enabled",
      ),
    ).toBe(false);
    expect(
      report.policy_changes.resolved.some(
        (f) => f.category === "management.telnet_enabled",
      ),
    ).toBe(true);
    expect(report.before.reference_findings).toBeNull();
    expect(report.before.peer_findings).toBeNull();
    expect(report.after.policy_findings.length).toBeGreaterThan(0);
    await expect(deterministicArea(page)).toContainText(
      "отчёт сохранён (completed)",
    );
    expect(await state(page.request)).toMatchObject({
      generator_calls: 1,
      materialization_calls: 1,
      deterministic_calls: 1,
    });
    await safeDOM(page);
    await originArea(page).screenshot({
      path: info.outputPath(`${vendor}-generated-origin.png`),
    });
    await deterministicArea(page).screenshot({
      path: info.outputPath(`${vendor}-explicit-policy-recheck.png`),
    });
    expect(
      (
        await page.request.post(
          `/_test/native/retire-source/${candidate.candidate_id}`,
          { headers: headers(CONTROL) },
        )
      ).status(),
    ).toBe(200);
    const beforeRestart = await privateSummary(
      page.request,
      candidate.candidate_id,
    );
    expect(beforeRestart).toMatchObject({
      exact_private_candidate_source: true,
      original_source_present: false,
      deterministic_attempts: 1,
    });
    const restarted = await restart(page.request, "history");
    expect(restarted.after).toMatchObject({
      history_only: true,
      generator_calls: 0,
      materialization_calls: 0,
      deterministic_calls: 0,
      forbidden_calls: 0,
    });
    for (const url of [
      route,
      `/api/v2/configurations/${record.after.configuration_id}/native-origin`,
    ]) {
      const response = await page.request.get(url, {
        headers: headers(READER),
      });
      expect(response.status()).toBe(200);
      const wire = await response.text();
      expect(safe(wire)).toBe(true);
      expect(wire).toBe(materializationWire);
    }
    const replay = await page.request.post(route, {
      headers: headers(ENGINEER),
      data: record.request,
    });
    expect(replay.status()).toBe(200);
    const replayWire = await replay.text();
    expect(safe(replayWire)).toBe(true);
    expect(replayWire).toBe(materializationWire);
    const recheckRead = await page.request.get(
      `${deterministicRoute}/${recheck.recheck_id}`,
      { headers: headers(READER) },
    );
    expect(recheckRead.status()).toBe(200);
    const rereadWire = await recheckRead.text();
    expect(safe(rereadWire)).toBe(true);
    expect(rereadWire).toBe(recheckWire);
    await connect(page, READER);
    await page
      .locator(".history-item")
      .filter({ hasText: record.after.configuration_id.slice(0, 8) })
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
    await expect(
      page.getByRole("button", {
        name: "Локальная проверка черновика",
        exact: true,
      }),
    ).toBeDisabled();
    await expect(originArea(page)).toContainText(
      "Формальная квалификация не доказана",
    );
    await safeDOM(page);
    await originArea(page).screenshot({
      path: info.outputPath(`${vendor}-ordinary-reader-history.png`),
    });
    expect(await privateSummary(page.request, candidate.candidate_id)).toEqual(
      beforeRestart,
    );
    const final = await state(page.request);
    expect(final).toMatchObject({
      history_only: true,
      generator_calls: 0,
      materialization_calls: 0,
      deterministic_calls: 0,
      forbidden_calls: 0,
    });
    const evidence = {
      version: "owned-native-materialization-http-browser-evidence-0.1.0",
      vendor,
      viewport: info.project.name,
      attempt: process.env.NETCONFIG_NATIVE_MATERIALIZATION_HTTP_ATTEMPT,
      reused_authored_family: `native-${vendor}`,
      independent_quality_measured: false,
      before_configuration_id: before.configuration_id,
      after_configuration_id: after.configuration_id,
      analysis_id: analysis.analysis_id,
      candidate_id: candidate.candidate_id,
      patch_id: draft.patch_id,
      recheck_id: recheck.recheck_id,
      operation_id: operation,
      materialization_review_sha256: record.review_sha256,
      candidate_review_sha256: candidate.review_sha256,
      materialization_wire_sha256: sha(materializationWire),
      recheck_wire_sha256: sha(recheckWire),
      actual_generation_calls: 1,
      actual_materialization_calls: 1,
      actual_deterministic_calls: 1,
      original_source_removed: true,
      actual_process_restart: true,
      old_pid: restarted.before.pid,
      new_pid: final.pid,
      history_runtime_forbidden: true,
      final_state: final,
      private_retention_check: beforeRestart,
      unchanged_materialization_get_origin_replay: true,
      unchanged_deterministic_get: true,
      ordinary_reader_history_generated_origin: true,
      marker_privacy_api_dom: true,
      formal_qualification: "not_proven",
      approved: false,
      applied: false,
      model_inference_invocations: 0,
      network_engine_invocations: 0,
    };
    const evidenceWire = JSON.stringify(evidence, null, 2) + "\n";
    expect(safe(evidenceWire)).toBe(true);
    await writeFile(info.outputPath(`${vendor}-receipt.json`), evidenceWire);
    await info.attach("materialization-http-receipt", {
      body: evidenceWire,
      contentType: "application/json",
    });
  });
