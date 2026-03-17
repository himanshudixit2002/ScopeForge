import { expect, test } from "@playwright/test";

test("offline scan, evidence review, export, and reload persistence", async ({
  page,
  request,
}) => {
  const externalRequests: string[] = [];
  page.on("request", (event) => {
    if (!event.url().startsWith("http://127.0.0.1:8000/"))
      externalRequests.push(event.url());
  });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Your research, in focus." }),
  ).toBeVisible();
  await expect(page.getByText("Local service online")).toBeVisible();
  const queued = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/scans") &&
      response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Explore demo", exact: true }).click();
  const scan = await (await queued).json();
  await expect
    .poll(
      async () =>
        (await (await request.get(`/api/scans/${scan.id}`)).json()).status,
    )
    .toBe("completed");
  const completed = await (await request.get(`/api/scans/${scan.id}`)).json();
  expect(completed.requests_made).toBe(0);
  expect(completed.findings_count).toBeGreaterThan(0);
  await page.getByRole("button", { name: "Refresh workspace" }).click();
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("button", { name: /^Findings/ })
    .click();
  const findings = await (await request.get("/api/findings")).json();
  const finding = findings[0];
  expect(findings.every((item: { is_demo: boolean }) => item.is_demo)).toBe(
    true,
  );
  await page.getByRole("button", { name: finding.title, exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByText("Synthetic fixture", { exact: true }),
  ).toBeVisible();
  await expect(dialog.locator("pre")).toContainText("SYNTHETIC");
  await dialog.getByLabel("Assessment status").selectOption("dismissed");
  const notes =
    "Offline workflow verification: synthetic observation, no real target assessed.";
  await dialog.getByLabel("Research notes").fill(notes);
  await dialog
    .getByRole("button", { name: "Save assessment", exact: true })
    .click();
  await expect
    .poll(async () => {
      const result = await (await request.get("/api/findings")).json();
      return result.find((item: { id: string }) => item.id === finding.id)
        .notes;
    })
    .toBe(notes);
  const downloading = page.waitForEvent("download");
  await dialog.getByRole("link", { name: "Download report" }).click();
  const download = await downloading;
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  const report = Buffer.concat(chunks).toString("utf8");
  expect(report).toMatch(/synthetic/i);
  expect(report).toContain(notes);
  expect(report).not.toContain("SYNTHETIC_NOT_A_SECRET");
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: finding.title, exact: true }).click();
  await expect(page.getByLabel("Research notes")).toHaveValue(notes);
  await expect(page.getByLabel("Assessment status")).toHaveValue("dismissed");
  expect(externalRequests).toEqual([]);
});

test("record exact scope, reject an excluded URL, and revoke permission", async ({
  page,
  request,
}) => {
  await page.goto("/#programs");
  await page.getByRole("button", { name: "Add program", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByLabel("Program name", { exact: true })
    .fill("Browser Test Program");
  await dialog
    .getByLabel("Program policy URL")
    .fill("https://owned.scopeforge.test/security");
  await dialog
    .getByLabel("Authorization record")
    .fill(
      "Synthetic permission record for local UI tests; no target networking.",
    );
  await dialog
    .getByLabel("Exact in-scope origins")
    .fill("https://owned.scopeforge.test");
  await dialog.getByLabel("Excluded path prefixes").fill("/admin\n/logout");
  await dialog
    .getByRole("checkbox", { name: /I have explicit permission/ })
    .check();
  const creating = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/programs") &&
      response.request().method() === "POST",
  );
  await dialog.getByRole("button", { name: "Create program" }).click();
  const creation = await creating;
  expect(creation.status()).toBe(201);
  const program = await creation.json();
  await expect(dialog).not.toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Browser Test Program", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("button", { name: "Scans", exact: true })
    .click();
  await page
    .getByRole("button", { name: "New scan", exact: true })
    .first()
    .click();
  await dialog.getByLabel("Authorized program").selectOption(program.id);
  await dialog
    .getByLabel("Target URL")
    .fill("https://owned.scopeforge.test/admin/settings");
  const scanCount = (await (await request.get("/api/scans")).json()).length;
  const refusing = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/scans") &&
      response.request().method() === "POST",
  );
  await dialog.getByRole("button", { name: "Queue posture check" }).click();
  const refusal = await refusing;
  expect(refusal.status()).toBe(422);
  expect((await refusal.json()).detail).toMatch(/exclu/i);
  await expect(
    dialog
      .getByRole("alert")
      .filter({ hasText: "Target path matches a program exclusion." }),
  ).toBeVisible();
  expect((await (await request.get("/api/scans")).json()).length).toBe(
    scanCount,
  );
  await page.keyboard.press("Escape");
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("button", { name: "Programs & scope", exact: true })
    .click();
  await page
    .locator("article")
    .filter({
      has: page.getByRole("heading", {
        name: "Browser Test Program",
        exact: true,
      }),
    })
    .getByRole("button", { name: "View scope" })
    .click();
  await dialog.getByRole("button", { name: "Revoke authorization" }).click();
  await expect(
    dialog.getByText("Authorization inactive", { exact: true }),
  ).toBeVisible();
  const programs = await (await request.get("/api/programs")).json();
  expect(
    programs.find((item: { id: string }) => item.id === program.id).authorized,
  ).toBe(false);
});

test("mobile layout and keyboard dialog navigation", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Your research, in focus." }),
  ).toBeVisible();
  await expect(page.getByText("Local service online")).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("button", { name: "Programs & scope", exact: true })
    .click();
  await page.getByRole("button", { name: "Add program", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("button", { name: "Close dialog" }),
  ).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(
    dialog.getByRole("button", { name: "Create program" }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(
    page.getByRole("button", { name: "Add program", exact: true }),
  ).toBeFocused();
});
