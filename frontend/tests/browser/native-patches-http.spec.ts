import { createHash, randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import type { APIRequestContext, Page } from "@playwright/test";
import { analysisSchema, snapshotSchema } from "../../src/contracts";
import type { AnalysisResult } from "../../src/contracts";
import {
  nativePatchCandidateSchema,
  nativePatchSelectionSchema,
  nativePatchRequest,
  nativeProofMatches,
} from "../../src/nativePatches";

// Real isolated loopback HTTP, parser, policy engine, native generator and encrypted DB.
// Two reused authored families across two viewports; no independent-quality denominator.
const ADMIN = "native-http-test-admin-service-token-0000001";
const ENGINEER = "native-http-test-engineer-service-token-001";
const READER = "native-http-test-reader-service-token-00001";
const CONTROL = "native-http-test-owned-control-token-000001";
const MARKERS = [
  "owned-native-password-marker",
  "owned-native-community-marker",
];
const headers = (token: string) => ({ Authorization: `Bearer ${token}` });
const safe = (wire: string) =>
  MARKERS.every((marker) => !wire.includes(marker));
const sha = (wire: string) => createHash("sha256").update(wire).digest("hex");
const panel = (page: Page) =>
  page.getByRole("region", { name: "Native-кандидат без модели", exact: true });
type WorkerState = {
  pid: number;
  history_only: boolean;
  generator_calls: number;
  forbidden_calls: number;
  model_configured: boolean;
  network_engine_configured: boolean;
};
test.afterEach(async ({ request }, info) => {
  // One worker, fixed desktop/mobile order and no retries: the final case asks the
  // supervisor to exit normally so TemporaryDirectory erases its owned encrypted DB.
  if (
    info.project.name === "mobile" &&
    info.title.startsWith("actual native HTTP juniper:")
  ) {
    const response = await request.post("/_test/native/shutdown", {
      headers: headers(CONTROL),
    });
    expect(response.status()).toBe(200);
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
  }
});
async function workerState(request: APIRequestContext): Promise<WorkerState> {
  const response = await request.get("/_test/native/state", {
    headers: headers(CONTROL),
  });
  expect(response.status()).toBe(200);
  return response.json() as Promise<WorkerState>;
}
async function restart(request: APIRequestContext, mode: "normal" | "history") {
  const before = await workerState(request);
  const response = await request.post(`/_test/native/restart/${mode}`, {
    headers: headers(CONTROL),
  });
  expect(response.status()).toBe(200);
  await expect
    .poll(
      async () => {
        try {
          const state = await workerState(request);
          return (
            state.pid !== before.pid &&
            state.history_only === (mode === "history")
          );
        } catch {
          return false;
        }
      },
      { timeout: 20_000, intervals: [100, 200, 400] },
    )
    .toBe(true);
  const after = await workerState(request);
  expect(after.pid).not.toBe(before.pid);
  return { before, after };
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
async function openAnalysis(page: Page, analysis: AnalysisResult) {
  await page.getByRole("button", { name: "Анализы", exact: true }).click();
  await page
    .locator(".history-item")
    .filter({ hasText: analysis.analysis_id.slice(0, 8) })
    .click();
  await expect(panel(page)).toBeVisible();
  await panel(page)
    .getByRole("button", { name: "Открыть native-кандидаты", exact: true })
    .click();
}
async function openCandidate(page: Page, id: string) {
  await panel(page)
    .getByRole("button", {
      name: new RegExp(`Открыть native-кандидат ${id.slice(0, 8)}`),
    })
    .click();
  await expect(
    panel(page).getByRole("heading", {
      name: "Сохранённый кандидат — требуется рассмотрение",
      exact: true,
    }),
  ).toBeVisible();
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
    ? `hostname owned\nip ssh version 2\nusername operator privilege 15 secret 0 ${MARKERS[0]}\nsnmp-server community ${MARKERS[1]} RO\nline vty 0 4\n transport input ssh telnet\n!\n`
    : `set system host-name owned\nset system services ssh\nset system login user operator authentication encrypted-password "${MARKERS[0]}"\nset snmp community ${MARKERS[1]} authorization read-only\nset system services telnet\n`;
}
for (const vendor of ["cisco", "juniper"] as const)
  test(`actual native HTTP ${vendor}: retained credentials, consent, immutable history and process restart`, async ({
    page,
  }, info) => {
    const previous = await workerState(page.request);
    if (
      previous.history_only ||
      previous.generator_calls !== 0 ||
      previous.forbidden_calls !== 0
    )
      await restart(page.request, "normal");
    const initial = await workerState(page.request);
    expect(initial).toMatchObject({
      generator_calls: 0,
      forbidden_calls: 0,
      model_configured: false,
      network_engine_configured: false,
    });
    // The management surface exists solely in this test executable and requires its own token.
    const controlDenied = await page.request.get("/_test/native/state");
    expect(controlDenied.status()).toBe(403);
    const oversizedControl = await page.request.post(
      "/_test/native/restart/history",
      { headers: headers(CONTROL), data: "unexpected-body" },
    );
    expect(oversizedControl.status()).toBe(403);
    const uploaded = await page.request.post("/api/v1/configurations", {
      headers: headers(ADMIN),
      data: {
        device_id: randomUUID(),
        filename: "owned-native.cfg",
        content: source(vendor),
        retain_original_source: true,
      },
    });
    expect(uploaded.status()).toBe(201);
    const snapshotWire = await uploaded.text();
    expect(safe(snapshotWire)).toBe(true);
    const snapshot = snapshotSchema.parse(JSON.parse(snapshotWire));
    expect(snapshot.canonical.parser_confidence).toBe(1);
    const analyzed = await page.request.post(
      `/api/v1/configurations/${snapshot.configuration_id}/analyze`,
      { headers: headers(ADMIN), data: {} },
    );
    expect(analyzed.status()).toBe(201);
    const analysisWire = await analyzed.text();
    expect(safe(analysisWire)).toBe(true);
    const analysis = analysisSchema.parse(JSON.parse(analysisWire));
    const selected = await page.request.get(
      `/api/v2/configurations/${snapshot.configuration_id}/native-patch-selection/${analysis.analysis_id}`,
      { headers: headers(READER) },
    );
    expect(selected.status()).toBe(200);
    const selectionWire = await selected.text();
    expect(safe(selectionWire)).toBe(true);
    const selection = nativePatchSelectionSchema.parse(
      JSON.parse(selectionWire),
    );
    const finding = analysis.findings.find(
      (f) => f.category === "management.telnet_enabled",
    )!;
    const unusedRequest = nativePatchRequest(selection, finding, randomUUID());
    const prefix = `/api/v2/configurations/${snapshot.configuration_id}/native-patches`;
    const noConsent = await page.request.post(prefix, {
      headers: headers(ENGINEER),
      data: { ...unusedRequest, allow_private_candidate_retention: false },
    });
    expect(noConsent.status()).toBe(400);
    expect(safe(await noConsent.text())).toBe(true);
    const readerDenied = await page.request.post(prefix, {
      headers: headers(READER),
      data: unusedRequest,
    });
    expect(readerDenied.status()).toBe(403);
    expect(safe(await readerDenied.text())).toBe(true);
    await connect(page, ENGINEER);
    await openAnalysis(page, analysis);
    const createButton = panel(page).getByRole("button", {
      name: "Создать native-кандидат",
      exact: true,
    });
    await expect(createButton).toBeDisabled();
    await panel(page)
      .getByLabel(
        "Разрешаю локальное создание native-кандидата из сохранённого оригинала",
        { exact: true },
      )
      .check();
    await expect(createButton).toBeDisabled();
    expect((await workerState(page.request)).generator_calls).toBe(0);
    await panel(page)
      .getByLabel(/Разрешаю приватное хранение полного оригинала и кандидата/)
      .check();
    const generation = page.waitForResponse(
      (r) => r.url().endsWith(prefix) && r.request().method() === "POST",
    );
    await createButton.click();
    const response = await generation;
    expect(response.status()).toBe(201);
    const publicWire = await response.text();
    expect(safe(publicWire)).toBe(true);
    const candidate = nativePatchCandidateSchema.parse(JSON.parse(publicWire));
    expect(await nativeProofMatches(candidate)).toBe(true);
    expect(candidate.request).toEqual(
      nativePatchRequest(selection, finding, candidate.candidate_id),
    );
    expect(candidate).toMatchObject({
      service_role: "engineer",
      status: "needs_review",
      formal_qualification: "not_proven",
      approved: false,
      applied: false,
      calibrated: false,
      quality_proven: false,
      individual_identity_verified: false,
    });
    const commands =
      vendor === "cisco"
        ? ["line vty 0 4", "transport input ssh", "exit"]
        : ["delete system services telnet"];
    expect(candidate.native_commands).toEqual(commands);
    await expect(panel(page).locator(".native-commands")).toHaveText(
      commands.join("\n"),
    );
    await expect(
      panel(page).getByText(
        /Формальная квалификация не доказана; качество и оценки не калиброваны/,
      ),
    ).toBeVisible();
    await expect(
      panel(page).getByRole("button", {
        name: /скачать|применить|Batfish|утвердить/i,
      }),
    ).toHaveCount(0);
    const createdState = await workerState(page.request);
    expect(createdState.generator_calls).toBe(1);
    const privateResponse = await page.request.get(
      `/_test/native/private/${candidate.candidate_id}`,
      { headers: headers(CONTROL) },
    );
    expect(privateResponse.status()).toBe(200);
    const privateWire = await privateResponse.text();
    expect(safe(privateWire)).toBe(true);
    const privateBefore = JSON.parse(privateWire);
    expect(privateBefore).toMatchObject({
      both_markers_in_before: true,
      both_markers_in_candidate: true,
      ciphertext_omits_markers: true,
      exact_expected_transformation: true,
      original_source_present: true,
      domain_creation_events: 1,
      before_sha256: sha(source(vendor)),
      candidate_sha256: candidate.metadata.review.proposal.after_sha256,
      review_sha256: candidate.review_sha256,
    });
    const operationId = response.headers()["x-operation-id"];
    expect(operationId).toBeTruthy();
    const audit = await page.request.get(
      `/api/v1/operation-audit/${operationId}`,
      { headers: headers(ADMIN) },
    );
    expect(audit.status()).toBe(200);
    expect(safe(await audit.text())).toBe(true);
    await safeDOM(page);
    await panel(page).screenshot({
      path: info.outputPath(`${vendor}-native-generated.png`),
    });
    await page.reload();
    await connect(page, ENGINEER);
    await openAnalysis(page, analysis);
    await openCandidate(page, candidate.candidate_id);
    await expect(panel(page).locator(".native-commands")).toHaveText(
      commands.join("\n"),
    );
    const retirement = await page.request.post(
      `/_test/native/retire-source/${candidate.candidate_id}`,
      { headers: headers(CONTROL) },
    );
    expect(retirement.status()).toBe(200);
    const privateAfterRemoval = await retirement.json();
    expect(privateAfterRemoval).toMatchObject({
      both_markers_in_before: true,
      both_markers_in_candidate: true,
      original_source_present: false,
      review_sha256: candidate.review_sha256,
      domain_creation_events: 1,
    });
    const restarted = await restart(page.request, "history");
    expect(restarted.after).toMatchObject({
      history_only: true,
      generator_calls: 0,
      forbidden_calls: 0,
      model_configured: false,
      network_engine_configured: false,
    });
    const reread = await page.request.get(
      `${prefix}/${candidate.candidate_id}`,
      { headers: headers(READER) },
    );
    expect(reread.status()).toBe(200);
    const rereadWire = await reread.text();
    expect(safe(rereadWire)).toBe(true);
    expect(rereadWire).toBe(publicWire);
    const listing = await page.request.get(prefix, {
      headers: headers(READER),
    });
    expect(listing.status()).toBe(200);
    const listWire = await listing.text();
    expect(safe(listWire)).toBe(true);
    expect(JSON.parse(listWire)[0]).toMatchObject({
      candidate_id: candidate.candidate_id,
      review_sha256: candidate.review_sha256,
    });
    const replay = await page.request.post(prefix, {
      headers: headers(ENGINEER),
      data: candidate.request,
    });
    expect(replay.status()).toBe(200);
    const replayWire = await replay.text();
    expect(safe(replayWire)).toBe(true);
    expect(replayWire).toBe(publicWire);
    await connect(page, READER);
    await openAnalysis(page, analysis);
    await openCandidate(page, candidate.candidate_id);
    await expect(panel(page).getByRole("checkbox")).toHaveCount(0);
    await expect(
      panel(page).getByRole("button", {
        name: "Создать native-кандидат",
        exact: true,
      }),
    ).toHaveCount(0);
    await expect(panel(page).locator(".native-commands")).toHaveText(
      commands.join("\n"),
    );
    await safeDOM(page);
    await panel(page).screenshot({
      path: info.outputPath(`${vendor}-native-reader-after-restart.png`),
    });
    const afterPrivate = await page.request.get(
      `/_test/native/private/${candidate.candidate_id}`,
      { headers: headers(CONTROL) },
    );
    expect(afterPrivate.status()).toBe(200);
    const afterPrivateWire = await afterPrivate.text();
    expect(safe(afterPrivateWire)).toBe(true);
    expect(JSON.parse(afterPrivateWire)).toEqual(privateAfterRemoval);
    const finalState = await workerState(page.request);
    expect(finalState).toMatchObject({
      history_only: true,
      generator_calls: 0,
      forbidden_calls: 0,
    });
    const evidence = {
      version: "owned-native-http-browser-evidence-0.1.0",
      vendor,
      viewport: info.project.name,
      attempt: process.env.NETCONFIG_NATIVE_HTTP_ATTEMPT,
      family: `reused-authored-native-${vendor}`,
      independent_quality_measured: false,
      configuration_id: snapshot.configuration_id,
      analysis_id: analysis.analysis_id,
      candidate_id: candidate.candidate_id,
      operation_id: operationId,
      review_sha256: candidate.review_sha256,
      public_wire_sha256: sha(publicWire),
      request_sha256: sha(JSON.stringify(candidate.request)),
      actual_native_generator_invocations: createdState.generator_calls,
      source_removed: true,
      actual_process_restart: true,
      old_pid: restarted.before.pid,
      new_pid: restarted.after.pid,
      runtime_forbidden_after_restart: true,
      final_state: finalState,
      private_retention_check: privateAfterRemoval,
      unchanged_get_list_replay: true,
      reader_history: true,
      raw_markers_omitted_from_api_and_dom: true,
      approved: false,
      applied: false,
      model_inference_invocations: 0,
      network_engine_invocations: 0,
    };
    const evidenceWire = JSON.stringify(evidence, null, 2) + "\n";
    expect(safe(evidenceWire)).toBe(true);
    await writeFile(info.outputPath(`${vendor}-receipt.json`), evidenceWire);
    await info.attach("native-http-receipt", {
      body: evidenceWire,
      contentType: "application/json",
    });
  });
