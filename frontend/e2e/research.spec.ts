import { expect, test } from "@playwright/test";

const mutationHeaders = { "X-ScopeForge-Client": "dashboard" };

test("offline HTTP capture, repeated observations, preserved triage, and redacted export", async ({
  page,
  request,
}) => {
  await page.goto("/#lab");
  await page
    .getByRole("button", { name: "Load synthetic HTTP", exact: true })
    .click();
  const editor = page.getByLabel("JSON evidence editor");
  const capture = JSON.parse(await editor.inputValue());
  capture.headers.push({
    name: "Authorization",
    value: "Bearer browser-private-marker",
  });
  await editor.fill(JSON.stringify(capture));
  const runImport = async () => {
    const finished = page.waitForResponse(
      (response) =>
        response.url().endsWith("/api/imports/analyze") &&
        response.request().method() === "POST",
    );
    await page
      .getByRole("button", { name: "Analyze offline", exact: true })
      .click();
    const response = await finished;
    expect(response.status()).toBe(201);
    const result = await response.json();
    expect(result.scan.requests_made).toBe(0);
    expect(result.scan.source).toBe("http-import");
    expect(result.scan.summary.raw_content_retained).toBe(false);
    await expect(
      page.getByRole("region", { name: "Offline analysis result" }),
    ).toContainText("Synthetic training evidence");
    return result;
  };
  const first = await runImport();
  const findings = await (await request.get("/api/findings")).json();
  const finding = findings.find(
    (item: { scan_id: string }) => item.scan_id === first.scan.id,
  );
  expect(finding).toBeTruthy();
  const notes =
    "Verified synthetic capture provenance; impact remains unverified.";
  expect(
    (
      await request.patch(`/api/findings/${finding.id}`, {
        headers: mutationHeaders,
        data: { status: "dismissed", notes },
      })
    ).ok(),
  ).toBe(true);
  await runImport();
  const repeated = (await (await request.get("/api/findings")).json()).find(
    (item: { id: string }) => item.id === finding.id,
  );
  expect(repeated.occurrence_count).toBe(2);
  expect(repeated.notes).toBe(notes);
  expect(repeated.status).toBe("dismissed");
  await page
    .getByRole("button", { name: "Review saved findings", exact: true })
    .click();
  await page
    .getByRole("button", { name: finding.title, exact: true })
    .last()
    .click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("Research notes")).toHaveValue(notes);
  await dialog.getByRole("button", { name: /View occurrence history/ }).click();
  await expect(dialog.locator(".occurrence-list > li")).toHaveCount(2);
  await dialog
    .getByText("Review saved evidence", { exact: true })
    .first()
    .click();
  await expect(dialog.locator(".occurrence-list pre").first()).toContainText(
    /user-provided/i,
  );
  const report = await (
    await request.get(`/api/findings/${finding.id}/report`)
  ).text();
  expect(report).toContain("No target request was sent");
  expect(report).toContain(notes);
  expect(report).not.toContain("browser-private-marker");
  expect(report).not.toContain("SYNTHETIC_NOT_A_SECRET");
});

test("OpenAPI file import stays offline and catalog filters actual implemented rules", async ({
  page,
  request,
}) => {
  await page.goto("/#lab");
  await page
    .getByRole("button", { name: "Load synthetic OpenAPI", exact: true })
    .click();
  const input = JSON.parse(
    await page.getByLabel("JSON evidence editor").inputValue(),
  );
  input.components = {
    schemas: {
      External: {
        $ref: "https://never-fetch.scopeforge.test/private-reference",
      },
    },
  };
  await page
    .getByLabel("Import JSON file")
    .setInputFiles({
      name: "synthetic-api.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(input)),
    });
  const finished = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/imports/analyze") &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Analyze offline", exact: true })
    .click();
  const result = await (await finished).json();
  expect(result.scan.requests_made).toBe(0);
  expect(result.scan.source).toBe("openapi");
  expect(result.findings_count).toBeGreaterThan(0);
  await expect(
    page.getByRole("region", { name: "Offline analysis result" }),
  ).toContainText("OpenAPI review");
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("button", { name: "Check catalog", exact: true })
    .click();
  const checks = await (await request.get("/api/checks")).json();
  await expect(page.locator(".check-card")).toHaveCount(checks.length);
  await page.getByLabel("Filter check profile").selectOption("openapi");
  await expect(page.locator(".check-card")).toHaveCount(
    checks.filter((item: { profiles: string[] }) =>
      item.profiles.includes("openapi"),
    ).length,
  );
  await page
    .getByLabel("Search check catalog")
    .fill("openapi:unauthenticated-write");
  await expect(page.locator(".check-card")).toHaveCount(1);
  await expect(page.locator(".check-card")).toContainText(
    "What this does not establish",
  );
  await expect(
    page.locator(".check-card").getByRole("link", { name: /Reference/ }),
  ).toHaveAttribute("href", /^https:\/\//);
});

test("manual evidence keeps analyst provenance in program exports", async ({
  page,
  request,
}) => {
  await page.goto("/#findings");
  await page
    .getByRole("button", { name: "Add manual finding", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  const programs = await (await request.get("/api/programs")).json();
  const demo = programs.find(
    (program: { is_demo: boolean }) => program.is_demo,
  );
  await dialog.getByLabel("Finding program").selectOption(demo.id);
  await dialog
    .getByLabel("Finding title")
    .fill("Synthetic manual workflow observation");
  await dialog
    .getByLabel("Description", { exact: true })
    .fill(
      "An analyst-created synthetic example for local workflow verification.",
    );
  await dialog
    .getByLabel("Observed impact")
    .fill("No real users or target were assessed. Impact remains unverified.");
  await dialog
    .getByLabel("Remediation", { exact: true })
    .fill("Review the original evidence with the authorized owner.");
  await dialog
    .getByLabel("Redacted evidence")
    .fill("Synthetic record only. No credentials or personal data.");
  await dialog.getByLabel("CWE identifier").fill("CWE-200");
  const saved = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/findings") &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Save manual finding", exact: true })
    .click();
  const response = await saved;
  expect(response.status()).toBe(201);
  const finding = await response.json();
  expect(finding.source).toBe("manual");
  expect(finding.is_demo).toBe(true);
  expect(
    (await (await request.get(`/api/scans/${finding.scan_id}`)).json())
      .requests_made,
  ).toBe(0);
  await expect(
    dialog.getByRole("heading", { name: finding.title, exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await page.goto("/#programs");
  await page
    .locator("article")
    .filter({
      has: page.getByRole("heading", { name: demo.name, exact: true }),
    })
    .getByRole("button", { name: "View scope" })
    .click();
  const downloading = page.waitForEvent("download");
  await dialog.getByRole("link", { name: "JSON", exact: true }).click();
  const stream = await (await downloading).createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  const bundle = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  expect(
    bundle.findings.find((item: { id: string }) => item.id === finding.id)
      .source,
  ).toBe("manual");
  const markdown = await (
    await request.get(`/api/programs/${demo.id}/report?format=markdown`)
  ).text();
  expect(markdown).toContain("Analyst-entered record");
  expect(markdown).toContain("SYNTHETIC");
});

test("batch validation rejects the whole set before any job is queued", async ({
  page,
  request,
}) => {
  const response = await request.post("/api/programs", {
    headers: mutationHeaders,
    data: {
      name: "Batch UI fixture",
      policy_url: "https://batch.scopeforge.test/policy",
      authorization_note:
        "Synthetic batch admission test; no network activity permitted.",
      scope_origins: ["https://batch.scopeforge.test"],
      excluded_paths: ["/admin"],
      request_interval_ms: 1000,
      authorization_expires_at: new Date(Date.now() + 86_400_000).toISOString(),
      authorized: true,
      allowed_profiles: ["headers"],
    },
  });
  expect(response.status()).toBe(201);
  const program = await response.json();
  await page.goto("/#scans");
  await expect(
    page.getByRole("button", { name: "Stop all active", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Batch URLs", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Batch program").selectOption(program.id);
  await expect(
    dialog.getByLabel("Check profile").locator("option"),
  ).toHaveCount(1);
  await dialog
    .getByLabel("Explicit target URLs")
    .fill("https://batch.scopeforge.test/\nhttps://batch.scopeforge.test/");
  await expect(
    dialog.getByRole("button", { name: /Queue batch/ }),
  ).toBeDisabled();
  await dialog
    .getByLabel("Explicit target URLs")
    .fill(
      "https://batch.scopeforge.test/\nhttps://batch.scopeforge.test/admin",
    );
  const before = (await (await request.get("/api/scans")).json()).length;
  const rejected = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/scans/batch") &&
      response.request().method() === "POST",
  );
  await dialog.getByRole("button", { name: /Queue batch/ }).click();
  expect((await rejected).status()).toBe(422);
  await expect(
    dialog.getByRole("alert").filter({ hasText: /exclusion/ }),
  ).toBeVisible();
  expect((await (await request.get("/api/scans")).json()).length).toBe(before);
});

test("research lab rejects oversized files and stays usable on mobile", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/#lab");
  await page
    .getByRole("button", { name: "Load synthetic HTTP", exact: true })
    .click();
  const original = await page.getByLabel("JSON evidence editor").inputValue();
  await page
    .getByLabel("Import JSON file")
    .setInputFiles({
      name: "too-large.json",
      mimeType: "application/json",
      buffer: Buffer.alloc(256 * 1024 + 1, 32),
    });
  await expect(page.getByRole("alert")).toContainText("exceeds 256 KiB");
  await expect(page.getByLabel("JSON evidence editor")).toHaveValue(original);
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
  await page.getByRole("button", { name: "Clear input", exact: true }).click();
  await expect(page.getByLabel("JSON evidence editor")).toHaveValue("");
  await expect(
    page.getByRole("button", { name: "Analyze offline", exact: true }),
  ).toBeDisabled();
});
