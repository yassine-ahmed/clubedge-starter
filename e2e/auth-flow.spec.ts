import { expect, test } from "@playwright/test";

// Signs a new user up, out, and back in through the real forms. It needs a configured auth
// provider and database, so it runs only with E2E_AUTH_FLOW=1 (the Starter's CI does this for
// Better Auth with PostgreSQL).
test.skip(!process.env.E2E_AUTH_FLOW, "needs a configured auth provider and database");

test("signs up, signs out, and signs back in", async ({ page }) => {
  const email = `e2e-${Date.now()}@example.com`;
  const password = "correct horse battery";

  await page.goto("/login?mode=signup");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);

  await page.getByRole("button", { name: "Sign out" }).first().click();
  await expect(page).toHaveURL(/\/login$/);

  // Signed out, the dashboard sends visitors to the login page.
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login/);

  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
});
