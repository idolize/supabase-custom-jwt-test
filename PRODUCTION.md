# Productionizing this pattern: Supabase + Next.js on Vercel

This is a translation of the local PoC into a real deployment. The SQL is unchanged; what changes is **where the private key lives**, **how the Next.js server mints tokens per request**, and **how the browser stays out of the Data API for business data**.

## 1. Trust model

```
                                ┌────────────────────────────────┐
   Browser                      │   Vercel (Next.js server)      │
   ───────                      │   ────────────────────────     │
   - calls Supabase Auth only   │   - getUser() via cookie       │
     (sign in / out / reset)    │   - mints backend JWT (RS256)  │      Supabase
   - cookies (session)  ────────┤   - calls Data API as          │      ────────
   - fetch /api/* ──────────────┤     nodejs_backend             │
   - never fetches /rest/v1     │                                │ ─▶  - GoTrue (Auth)
                                │   Holds: SUPABASE_PRIVATE_KEY  │     - PostgREST (Data API)
                                └────────────────────────────────┘     - Postgres + RLS
```

Key things to preserve from the PoC:

- The browser **only** talks to `${SUPABASE_URL}/auth/v1` (sign in/out, password reset). It never sends requests to `/rest/v1`, `/rpc`, `/graphql/v1` for business data.
- The Next.js server is the only thing that mints `role: nodejs_backend` JWTs.
- The `api` schema has `USAGE` granted **only** to `nodejs_backend`. RLS on every table uses `auth.uid() = user_id` (or `auth.jwt() -> app_metadata ->> 'org_id'`, etc.).

## 2. Key material

You can either share one keypair between GoTrue and the backend, or use two.

### Option A — one shared keypair (simpler, recommended to start)

1. Generate locally: `supabase gen signing-key --algorithm RS256 > key.json`. The file has both the private and public components.
2. In the Supabase Dashboard → **Authentication → JWT Signing Keys**, import the JWK (status `in_use`). GoTrue now signs Auth-issued tokens with it, and publishes the public side at `https://<ref>.supabase.co/auth/v1/.well-known/jwks.json`.
3. Strip everything except the private components and store the JWK JSON in Vercel as `SUPABASE_SIGNING_JWK` (encrypted env var, server-only). The Node backend uses this to sign `nodejs_backend` JWTs.

Trade-off: anyone with the private key can forge **any** role, including `service_role`. Mitigation is short-lived backend JWTs + rotation + never logging the key.

### Option B — two keypairs (better isolation)

1. Keep GoTrue's signing key inside Supabase (let the dashboard generate it).
2. Generate a *separate* RS256 keypair for the backend. Import its public side into Supabase as an additional signing key with status `standby` — this puts the public JWK into the JWKS feed so PostgREST will verify signatures from it, even though GoTrue never signs with it.
3. Vercel holds only the backend keypair's private side. Supabase staff/dashboard never sees it.

Trade-off: a leak of GoTrue's key only lets an attacker forge user session tokens (still bad, but they hit RLS as `authenticated` and can't reach `api`). A leak of the backend key lets them forge `nodejs_backend`. This is the right structure for higher-assurance setups.

Either way, **the private key must never appear in any `NEXT_PUBLIC_*` env var or any code that ships to the browser bundle.**

## 3. Schema and roles

The local migration ports directly. Apply via CI (`supabase db push` against the linked project, or your migration tool of choice). The only thing to double-check on a hosted project:

- **Dashboard → API Settings → Exposed schemas**: add `api` here in addition to listing it in `config.toml`. The dashboard setting is what hosted PostgREST reads.
- **Dashboard → API Settings → Extra search path**: leave `public, extensions` unless you have a reason to change it.
- Confirm `anon` and `authenticated` have **no** grants on the `api` schema (run the same revoke statements). The dashboard's "auto-expose new tables" toggle should be off for `api`, or the GRANT will be re-added behind your back.

Add this safety check to a migration / advisor:

```sql
-- Should return zero rows. If anything appears, anon or authenticated
-- can see api tables.
select grantee, table_schema, table_name, privilege_type
from information_schema.role_table_grants
where table_schema = 'api'
  and grantee in ('anon', 'authenticated');
```

## 4. Next.js wiring

Three server-only modules. None of them may be imported from a Client Component or a Client Action.

### `lib/supabase/signing-key.ts`

```ts
import "server-only";
import { importJWK } from "jose";

const jwk = JSON.parse(process.env.SUPABASE_SIGNING_JWK!); // single JWK or array
const activeJwk = Array.isArray(jwk)
  ? (jwk.find((k) => k.status === "in_use")?.key ?? jwk[0])
  : jwk;

export const PRIVATE_KEY = await importJWK(activeJwk, "RS256");
export const KID = activeJwk.kid;
```

(For Edge runtime, do the import lazily inside the request handler — top-level await isn't reliable in every Vercel edge environment.)

### `lib/supabase/mint.ts`

```ts
import "server-only";
import { SignJWT } from "jose";
import { PRIVATE_KEY, KID } from "./signing-key";

const ISS = `${process.env.NEXT_PUBLIC_SUPABASE_URL}/auth/v1`;

export async function mintBackendJwt(userId: string, ttlSeconds = 60) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ role: "nodejs_backend" })
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: KID })
    .setIssuer(ISS)
    .setAudience("authenticated")
    .setSubject(userId)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(PRIVATE_KEY);
}
```

A TTL of 60s is plenty for a single request. Don't cache these across requests; the cost of minting is negligible.

### `lib/supabase/data-api.ts`

```ts
import "server-only";
import { createClient } from "@supabase/supabase-js";
import { mintBackendJwt } from "./mint";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const ANON = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!;

export async function dataApiFor(userId: string) {
  const jwt = await mintBackendJwt(userId);
  return createClient(SUPABASE_URL, ANON, {
    global: {
      headers: {
        Authorization: `Bearer ${jwt}`,
        "Accept-Profile": "api",
        "Content-Profile": "api",
      },
    },
    auth: { persistSession: false, autoRefreshToken: false },
  });
}
```

`supabase-js` reuses the same `Authorization` header for the lifetime of the client, so create a fresh client per request.

### Putting it together in a Server Component / Route Handler

```ts
// app/notes/page.tsx
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { dataApiFor } from "@/lib/supabase/data-api";

export default async function NotesPage() {
  // 1. Verify the user via the Supabase session cookie. This client uses the
  //    publishable key and the user's cookies — it can ONLY see auth.users
  //    and whatever anon/authenticated can reach (which is nothing in `api`).
  const authClient = createServerClient(/* @supabase/ssr config */);
  const { data: { user } } = await authClient.auth.getUser();
  if (!user) redirect("/login");

  // 2. Mint a backend JWT for this user and call the Data API as nodejs_backend.
  const db = await dataApiFor(user.id);
  const { data: notes, error } = await db.from("notes").select("*");
  if (error) throw error;

  return <NotesList notes={notes} />;
}
```

The user's session cookie never reaches `/rest/v1`. The backend JWT never reaches the browser.

## 5. Environment variables (Vercel)

| Name                                    | Where           | Notes                                                                  |
| --------------------------------------- | --------------- | ---------------------------------------------------------------------- |
| `NEXT_PUBLIC_SUPABASE_URL`              | Public + server | e.g. `https://<ref>.supabase.co`                                       |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`  | Public + server | The new `sb_publishable_*` key. Used by `@supabase/ssr` in the browser. |
| `SUPABASE_SIGNING_JWK`                  | **Server only** | The full private JWK (or array) for `nodejs_backend` minting.          |
| `SUPABASE_SECRET_KEY` (optional)        | **Server only** | Only if you also need service-role access for migrations/admin tasks. |

Audit: search the build output for `SUPABASE_SIGNING_JWK` and `SUPABASE_SECRET_KEY` — neither string should appear in any `.js` shipped to the browser.

## 6. Key rotation

Supabase's signing-keys API supports the four statuses: `in_use`, `standby`, `previous`, `revoked`. The safe rotation flow:

1. Generate a new RS256 JWK. Add it to Supabase as `standby`. JWKS now publishes both old and new public keys.
2. Wait long enough for any CDN/edge caches in front of JWKS to refresh (Supabase JWKS has a `Cache-Control: max-age` of a few minutes — wait at least 2× that).
3. Promote the new key to `in_use`. The old key automatically becomes `previous` — tokens it already signed continue to verify.
4. Update `SUPABASE_SIGNING_JWK` in Vercel to the new private key and redeploy. (Use two-step: deploy with the new JWK reachable but still signing with the old, then flip. Or stage via a feature flag.)
5. Wait for the longest possible TTL of any token signed by the old key (60s in our setup → wait 5 min for safety).
6. Mark the old key `revoked`. JWKS drops it.

Automate via the Supabase Management API (`PATCH /v1/projects/{ref}/config/auth/signing-keys`) on a quarterly schedule.

## 7. What this protects, and what it doesn't

**Protects:**

- A random authenticated Supabase user copying their session cookie and curling `/rest/v1/notes?select=*` — gets nothing (no USAGE on `api`).
- A leaked publishable/anon key being used to enumerate the database — same, no access to `api`.
- An attacker who finds your Postgres `service_role` key in a screenshot — still bad, but they can't forge `nodejs_backend` tokens to impersonate specific users for audit purposes; the leak path is different.
- RLS still applies end-to-end; even your backend can't accidentally fetch user A's data when answering a request for user B (the JWT sub mismatch produces zero rows).

**Does NOT protect:**

- A compromised Vercel deployment. If an attacker can run code in your Next.js process they have the signing key and can mint arbitrary JWTs. The defense is the usual: secret rotation, audit logs, principle of least privilege in CI.
- Bugs in *your* Next.js code that pass the wrong `user.id` to `dataApiFor()`. RLS is enforced, but if your code asks the Data API for user B's notes while logged in as A, that's an application bug RLS can't catch.
- Storage, Realtime, and GraphQL. Each has its own access surface:
  - **Storage**: write RLS policies on `storage.objects` that mirror the `api` model. The `nodejs_backend` role pattern works here too if you grant it the right `storage.*` permissions.
  - **Realtime**: subscriptions are evaluated against the connecting JWT's role. If you don't want browsers subscribing directly to `api` tables, either disable Realtime on those tables (`alter publication supabase_realtime drop table api.notes`) or ensure RLS denies anon/authenticated.
  - **GraphQL** (`pg_graphql`): runs as the JWT's role. With no grants for anon/authenticated on `api`, GraphQL can't see it. Still worth turning off `graphql_public` if you don't use GraphQL at all — one less surface.
- The `auth.users` table itself. Standard Supabase Auth flows mean users can read their own row via `auth.getUser()`. If you need stricter, consider not putting PII in `auth.users.raw_user_meta_data`.

## 8. Pre-launch checklist

- [ ] `api` schema listed in Dashboard → API Settings → Exposed schemas.
- [ ] `anon` and `authenticated` have zero grants in `api` (verify via the SQL query in §3).
- [ ] Every table in `api` has `enable row level security` AND `force row level security`.
- [ ] Every RLS policy is scoped `to nodejs_backend` (or whatever role you chose) so it can't accidentally pass for `authenticated`.
- [ ] Backend JWT TTL ≤ 5 minutes; default to 60s if you can.
- [ ] `SUPABASE_SIGNING_JWK` is a Vercel "encrypted" env var; not exposed to client.
- [ ] Build output greps clean for the JWK / service-role strings.
- [ ] CI runs the equivalent of `pnpm verify` against a staging Supabase project after every migration.
- [ ] Rotation runbook documented; calendar reminder set.
- [ ] GraphQL endpoint either disabled or audited; Realtime publications reviewed for accidental exposure of `api` tables.
- [ ] Storage RLS reviewed if you use Storage for user-owned files.
- [ ] Backend logs do **not** include the signing key, full JWTs, or `service_role` key. Truncate at `eyJ...`.

## 9. Open variations worth knowing about

- **Per-organization access** instead of per-user: mint JWTs with an extra `org_id` claim under `app_metadata`, and write RLS policies that read `auth.jwt() -> 'app_metadata' ->> 'org_id'`. Same trust model, broader scope.
- **Read replicas**: PostgREST-on-replica respects RLS the same way. The pattern carries over without changes.
- **Edge runtime**: `jose` works on Vercel Edge; `jsonwebtoken` does not (depends on Node `crypto`). If you want to mint JWTs from an Edge middleware, stay on `jose`.
- **Mint inside the database** instead of the backend: Postgres `pgjwt` extension can sign tokens in SQL using a key stored in `vault.secrets`. Slower and harder to rotate; only worth it if you can't run a Node process.
