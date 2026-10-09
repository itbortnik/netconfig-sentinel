import { expect, test } from "@playwright/test";

const TOKEN = "browser-tests-service-token-32-characters-001";

for (const scenario of ["cisco", "junos-set", "junos-blocks"] as const) {
  test(`measured ${scenario} source coverage is distinct from confidence`, async ({
    page,
  }) => {
    await page.goto("/ui/");
    await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
    await page
      .getByRole("button", { name: "Подключиться", exact: true })
      .click();
    await expect(
      page.getByText("Сессия подключена", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText("Загрузка истории…")).toBeHidden();
    const source =
      scenario === "cisco"
        ? "! owned\nhostname owned-coverage\nunknown PRIVATE_VALUE\nend\n"
        : scenario === "junos-set"
          ? "# owned\nset system host-name owned-coverage\nset unknown PRIVATE_VALUE\n"
          : "system {\n host-name owned-coverage;\n unknown PRIVATE_VALUE;\n}\n";
    await page.getByLabel("Выбрать конфигурацию").setInputFiles({
      name: "owned-coverage.cfg",
      mimeType: "text/plain",
      buffer: Buffer.from(source),
    });
    const responsePromise = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        response.url().endsWith("/api/v1/configurations"),
    );
    await page
      .getByRole("button", { name: "Сохранить снимок", exact: true })
      .click();
    const response = await responsePromise;
    expect(response.status()).toBe(201);
    const snapshot = await response.json();
    const report = snapshot.parser_coverage;
    expect(report.unparsed_fraction).toBe(
      scenario === "junos-blocks" ? 1 / 3 : 0.5,
    );
    expect(1 - snapshot.canonical.parser_confidence).not.toBe(
      report.unparsed_fraction,
    );
    const section = page.getByRole("region", {
      name: "Покрытие разбора исходных строк",
      exact: true,
    });
    await expect(section).toBeVisible();
    await expect(section).toContainText(
      scenario === "junos-blocks" ? /33,3\s*%/u : /50\s*%/u,
    );
    await expect(section).toContainText("не означает полную семантическую");
    await expect(section).not.toContainText("PRIVATE_VALUE");
    await expect(
      page.getByText("Итоговый риск для этого снимка не рассчитывается.", {
        exact: false,
      }),
    ).toBeVisible();
    const saved = await page.request.get(
      `/api/v1/configurations/${snapshot.configuration_id}`,
      { headers: { Authorization: `Bearer ${TOKEN}` } },
    );
    expect(await saved.json()).toEqual(snapshot);
    const layout = await page.evaluate(() => ({
      viewport: innerWidth,
      scroll: document.documentElement.scrollWidth,
    }));
    expect(layout.scroll).toBeLessThanOrEqual(layout.viewport);
  });
}

test("legacy snapshot without a report is shown as unmeasured, not zero", async ({
  page,
}) => {
  await page.route("**/api/v1/configurations", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const response = await route.fetch();
    const snapshot = await response.json();
    delete snapshot.parser_coverage;
    // Synthetic historical wire shape only; backend measurement is not disabled.
    await route.fulfill({ response, json: snapshot });
  });
  await page.goto("/ui/");
  await page.getByLabel("API-токен", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "Подключиться", exact: true }).click();
  await expect(
    page.getByText("Сессия подключена", { exact: true }),
  ).toBeVisible();
  await page.getByLabel("Выбрать конфигурацию").setInputFiles({
    name: "owned-legacy.cfg",
    mimeType: "text/plain",
    buffer: Buffer.from("hostname owned-legacy\n"),
  });
  await page
    .getByRole("button", { name: "Сохранить снимок", exact: true })
    .click();
  await expect(
    page.getByText("Покрытие не измерено для этого исторического снимка.", {
      exact: false,
    }),
  ).toBeVisible();
  await expect(
    page.getByText("Доля неподдержанных строк", { exact: true }),
  ).toHaveCount(0);
});
