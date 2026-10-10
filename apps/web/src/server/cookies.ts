import "server-only";
import { cookies } from "next/headers";
import type { CookieStore } from "@clubedge/auth";

/** Bridges Next.js request cookies to the framework-agnostic CookieStore. */
export async function nextCookieStore(): Promise<CookieStore> {
  const cookieStore = await cookies();
  return {
    getAll: () => cookieStore.getAll(),
    setAll(values) {
      try {
        values.forEach(({ name, value, options }) => cookieStore.set(name, value, options));
      } catch {
        // Server Components cannot write cookies. The proxy refreshes sessions instead.
      }
    },
  };
}
