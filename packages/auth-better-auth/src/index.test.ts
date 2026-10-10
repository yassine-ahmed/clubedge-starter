import { randomBytes } from "node:crypto";
import { memoryAdapter } from "better-auth/adapters/memory";
import { beforeEach, describe, expect, it } from "vitest";
import type { CookieStore, CookieToSet } from "@clubedge/auth";
import { createBetterAuth, createBetterAuthServer, type BetterAuthServer } from "./index";

// Real Better Auth on its in-memory database: these tests exercise the cookie bridge and the
// AuthProvider contract end to end, without PostgreSQL.

/** A browser's cookie jar, as the framework would expose it through CookieStore. */
function cookieJar() {
  const values = new Map<string, string>();
  const writes: CookieToSet[] = [];
  const store: CookieStore = {
    getAll: () => [...values].map(([name, value]) => ({ name, value })),
    setAll(cookies) {
      for (const cookie of cookies) {
        writes.push(cookie);
        if (cookie.options?.maxAge === 0) values.delete(cookie.name);
        else values.set(cookie.name, cookie.value);
      }
    },
  };
  return { store, writes, values };
}

const credentials = { email: "ada@example.com", password: "correct horse battery" };
let server: BetterAuthServer;

beforeEach(() => {
  server = createBetterAuthServer({
    database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    secret: randomBytes(32).toString("hex"),
    baseUrl: "http://localhost:3000",
  });
});

describe("Better Auth adapter", () => {
  it("signs a new user up and in with an HTTP-only session cookie", async () => {
    const jar = cookieJar();
    const auth = createBetterAuth({ server, cookies: jar.store });

    const result = await auth.signUp({ ...credentials, emailRedirectTo: "unused" });

    expect(result).toMatchObject({ ok: true, value: { needsConfirmation: false } });
    const user = result.ok ? result.value.user : null;
    expect(user?.email).toBe("ada@example.com");
    expect(user?.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(jar.writes[0]?.options).toMatchObject({ httpOnly: true, sameSite: "lax", path: "/" });
    expect(await auth.getUser()).toEqual(user);
  });

  it("signs an existing user in on a new device", async () => {
    await createBetterAuth({ server, cookies: cookieJar().store }).signUp({
      ...credentials,
      emailRedirectTo: "unused",
    });
    const jar = cookieJar();
    const auth = createBetterAuth({ server, cookies: jar.store });

    expect(await auth.getUser()).toBeNull();
    const result = await auth.signInWithPassword(credentials);

    expect(result).toMatchObject({ ok: true, value: { email: "ada@example.com" } });
    expect(await auth.getUser()).toMatchObject({ email: "ada@example.com" });
  });

  it("reports a wrong password without setting cookies", async () => {
    await createBetterAuth({ server, cookies: cookieJar().store }).signUp({
      ...credentials,
      emailRedirectTo: "unused",
    });
    const jar = cookieJar();
    const result = await createBetterAuth({ server, cookies: jar.store }).signInWithPassword({
      email: credentials.email,
      password: "wrong password",
    });

    expect(result).toEqual({ ok: false, error: "invalid-credentials" });
    expect(jar.writes).toEqual([]);
  });

  it("refuses a second account for the same email", async () => {
    const auth = createBetterAuth({ server, cookies: cookieJar().store });
    await auth.signUp({ ...credentials, emailRedirectTo: "unused" });

    const again = await createBetterAuth({ server, cookies: cookieJar().store }).signUp({
      ...credentials,
      emailRedirectTo: "unused",
    });
    expect(again).toEqual({ ok: false, error: "signup-failed" });
  });

  it("signs out by expiring the session cookie", async () => {
    const jar = cookieJar();
    const auth = createBetterAuth({ server, cookies: jar.store });
    await auth.signUp({ ...credentials, emailRedirectTo: "unused" });

    await auth.signOut();

    expect(jar.values.size).toBe(0);
    expect(await auth.getUser()).toBeNull();
  });

  it("refreshes quietly when there is no session", async () => {
    const jar = cookieJar();
    await createBetterAuth({ server, cookies: jar.store }).refreshSession();
    expect(jar.writes).toEqual([]);
  });

  it("has no email-link codes to exchange", async () => {
    const auth = createBetterAuth({ server, cookies: cookieJar().store });
    expect(await auth.exchangeCodeForSession("anything")).toEqual({
      ok: false,
      error: "invalid-code",
    });
  });
});
