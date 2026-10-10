import { betterAuth } from "better-auth/minimal";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { parseSetCookieHeader, splitSetCookieHeader, toCookieOptions } from "better-auth/cookies";
import type { AuthProvider, AuthUser, CookieStore, CookieToSet } from "@clubedge/auth";
import { err, ok } from "@clubedge/core";
import { betterAuthTables } from "./schema";

export { betterAuthTables } from "./schema";

type DatabaseAdapter = Parameters<typeof betterAuth>[0]["database"];

export interface BetterAuthServerConfig {
  /** Where Better Auth stores users and sessions; see `drizzleDatabase`. */
  database: DatabaseAdapter;
  /** At least 32 random characters, for signing session cookies. */
  secret: string;
  /** The app's public origin, such as https://app.example. */
  baseUrl: string;
}

/** Stores Better Auth's tables in a Drizzle PostgreSQL database (see ./schema). */
export function drizzleDatabase(db: Parameters<typeof drizzleAdapter>[0]): DatabaseAdapter {
  return drizzleAdapter(db, { provider: "pg", schema: betterAuthTables });
}

/** One Better Auth server per process; `createBetterAuth` adapts it per request. */
export function createBetterAuthServer({ database, secret, baseUrl }: BetterAuthServerConfig) {
  return betterAuth({
    database,
    secret,
    baseURL: baseUrl,
    emailAndPassword: { enabled: true, minPasswordLength: 8, maxPasswordLength: 128 },
    advanced: { database: { generateId: "uuid" } },
    // The app rate-limits sign-in and sign-up itself, per client address.
    rateLimit: { enabled: false },
  });
}

export type BetterAuthServer = ReturnType<typeof createBetterAuthServer>;

function toAuthUser(user: { id: string; email: string }): AuthUser {
  return { id: user.id, email: user.email };
}

/** The request's cookies, in the form Better Auth reads them. */
function requestHeaders(cookies: CookieStore): Headers {
  const header = cookies
    .getAll()
    .map(({ name, value }) => `${name}=${encodeURIComponent(value)}`)
    .join("; ");
  return new Headers(header ? { cookie: header } : {});
}

/** Writes every cookie Better Auth set through the framework's cookie store. */
function applyCookies(cookies: CookieStore, headers: Headers) {
  const header = headers.get("set-cookie");
  if (!header) return;
  const values: CookieToSet[] = splitSetCookieHeader(header).flatMap((cookie) =>
    [...parseSetCookieHeader(cookie)].map(([name, attributes]) => ({
      name,
      value: attributes.value,
      options: toCookieOptions(attributes),
    })),
  );
  if (values.length) cookies.setAll(values);
}

/** Better Auth reports expected failures, such as a wrong password, as API errors. */
function isApiError(error: unknown): boolean {
  return error instanceof Error && error.name === "APIError";
}

export function createBetterAuth({
  server,
  cookies,
}: {
  server: BetterAuthServer;
  cookies: CookieStore;
}): AuthProvider {
  return {
    async getUser() {
      const session = await server.api.getSession({ headers: requestHeaders(cookies) });
      return session ? toAuthUser(session.user) : null;
    },
    async signInWithPassword(credentials) {
      try {
        const { headers, response } = await server.api.signInEmail({
          body: credentials,
          headers: requestHeaders(cookies),
          returnHeaders: true,
        });
        applyCookies(cookies, headers);
        return ok(toAuthUser(response.user));
      } catch (error) {
        if (isApiError(error)) return err("invalid-credentials");
        throw error;
      }
    },
    async signUp({ email, password }) {
      try {
        const { headers, response } = await server.api.signUpEmail({
          // Better Auth requires a display name; start with the email's local part.
          body: { email, password, name: email.split("@")[0] ?? email },
          headers: requestHeaders(cookies),
          returnHeaders: true,
        });
        applyCookies(cookies, headers);
        // Sign-up signs the user in; email verification is not required by default.
        return ok({ user: toAuthUser(response.user), needsConfirmation: false });
      } catch (error) {
        if (isApiError(error)) return err("signup-failed");
        throw error;
      }
    },
    async exchangeCodeForSession() {
      // Email-link flows are not enabled, so there is never a code to exchange.
      return err("invalid-code");
    },
    async refreshSession() {
      // Reading the session extends it when due and returns the refreshed cookies.
      const { headers } = await server.api.getSession({
        headers: requestHeaders(cookies),
        returnHeaders: true,
      });
      applyCookies(cookies, headers);
    },
    async signOut() {
      const { headers } = await server.api.signOut({
        headers: requestHeaders(cookies),
        returnHeaders: true,
      });
      applyCookies(cookies, headers);
    },
  };
}
