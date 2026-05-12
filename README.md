# Supabase custom JWT + RLS example

Minimal **local runnable example**: a backend signs short-lived JWTs with a Postgres role (`nodejs_backend`) that is the **only** role with access to an `api` schema. Row-level security policies use **`auth.uid()`**, so PostgREST returns rows as if the request were on behalf of the JWT’s `sub`—while normal `anon` / `authenticated` tokens cannot read that schema.

This repo is deliberately small (no web app): migrations, seed data, a JWT mint script, and a verification script you can run after `supabase start`.

---

## Why this pattern exists

Many apps use Supabase-hosted Postgres + PostgREST (the Data API) from a **server** they control, while the browser only uses Supabase for auth (sign in, sign out, password reset). If the Data API is callable with the publishable key and a normal user session, a motivated user could call `/rest/v1` directly and bypass your API routes.

You can disable the Data API or use only the service role from the backend, but that often means giving up defense-in-depth RLS on those code paths—or reimplementing authorization entirely in application code.

This example shows another approach:

- Expose PostgREST, but put **business tables** in a schema (here, `api`) where **only** a dedicated backend role has `USAGE` and table privileges.
- The server mints JWTs signed with Supabase-compatible **RS256** keys, sets `role: nodejs_backend` and `sub: <user id>`, and calls the Data API with those tokens.
- RLS policies on `api` tables reference **`auth.uid()`**, which resolves to that JWT subject inside PostgREST—so impersonation behavior is observable from actual query results.

The browser model in production is unchanged: **the client never uses the Data API for business data**. This repo uses `curl`/Node scripts from your machine only to mimic the backend.

For deploying the same SQL and trust model to **Next.js on Vercel** (minting on the server, env vars, key rotation, checklist), see **[PRODUCTION.md](./PRODUCTION.md)**.

---

## What’s in the repo

| Path                         | Role                                                                                       |
| ---------------------------- | ------------------------------------------------------------------------------------------ |
| `supabase/config.toml`       | Exposes `api` to PostgREST; points Auth at `signing_keys.json` for JWT verification        |
| `supabase/signing_keys.json` | RS256 JWK array (generate locally; **gitignored**)                                         |
| `supabase/migrations/`       | Creates `nodejs_backend`, private `api` schema, `api.notes`, RLS, locked-down `public` RPC |
| `supabase/seed.sql`          | Sample rows for verification                                                               |
| `scripts/mint-jwt.js`        | Mint a backend JWT for a given user UUID (`sub`)                                           |
| `scripts/verify.js`          | Automated checks (happy path, isolation, negative cases, `auth.uid()` behavior)            |
| `.env` / `.env.example`      | Base URL and keys for scripts (defaults work for local)                                    |

Conceptually:

- **`[api].schemas`** includes `api`, so requests must send **`Accept-Profile: api`** (and `Content-Profile` when writing) unless you change defaults.
- **`signing_keys_path`** wires local GoTrue/PostgREST to verify tokens minted from the same JWK material.
- **`authenticator`** is granted `nodejs_backend` so PostgREST can **`SET ROLE`** according to the JWT’s `role` claim.
- **`api.notes`** has RLS (+ `FORCE`) with policies **`to nodejs_backend`** using `user_id = auth.uid()`.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (for Supabase local stack)
- [Supabase CLI](https://supabase.com/docs/guides/cli)
- Node.js and [pnpm](https://pnpm.io/) on your `PATH`

---

## Quick start (cold run)

```bash
# 1. Install Node dependencies
pnpm install

# 2. Generate an RS256 signing key for local dev.
#    The CLI prints a single JWK; wrap it in a JSON array — that is what
#    signing_keys_path expects.
supabase gen signing-key --algorithm RS256 --yes \
  | head -1 \
  | python3 -c "import sys, json; k=json.load(sys.stdin); json.dump([k], open('supabase/signing_keys.json','w'), indent=2)"

# 3. Start the stack (applies migrations and seed.sql)
supabase start

# 4. Environment (defaults are fine for local)
cp .env.example .env

# 5. Run all verification checks
pnpm verify
```

You should see **nine** passing checks ending with `All checks passed.` (see [Verification](#verification) below).

```text
PostgREST URL: http://127.0.0.1:54321

PASS  A1: backend JWT for user A returns only A's rows
PASS  A2: backend JWT for user A can insert + then delete its own row
PASS  A3: backend JWT for user A CANNOT insert a row for user B (RLS WITH CHECK)
PASS  B1: anon JWT cannot read api.notes (no USAGE on schema)
PASS  B2: anon cannot call locked-down RPC public.backend_only_ping
PASS  B3: normal authenticated user JWT cannot read api.notes
PASS  B4: normal authenticated user JWT cannot call backend_only_ping
PASS  C1: switching JWT sub from A to B changes visible rows
PASS  C2: orphan row is invisible to both A and B

All checks passed.
```

REST base URL for PostgREST is typically `http://127.0.0.1:54321/rest/v1` (shown in `supabase status`).

---

## NPM scripts

| Command            | Description                                                                    |
| ------------------ | ------------------------------------------------------------------------------ |
| `pnpm verify`      | Runs `scripts/verify.js` — end-to-end proof of backend JWT vs anon/session JWT |
| `pnpm mint <uuid>` | Prints a RS256 JWT for `sub=<uuid>` and `role=nodejs_backend`                  |

---

## Mint a JWT manually and call PostgREST

```bash
# Example: mint for seeded user A
pnpm mint 00000000-0000-0000-0000-0000000000aa

TOKEN=$(pnpm -s mint 00000000-0000-0000-0000-0000000000aa)
ANON_KEY=$(supabase status -o env | sed -n 's/^ANON_KEY="\(.*\)"$/\1/p')

curl -s "http://127.0.0.1:54321/rest/v1/notes?select=*" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept-Profile: api"
# Returns only rows where user_id matches that sub (RLS).
```

Using the anon key as `Authorization: Bearer` (or a normal **authenticated** user session JWT) against `api.notes` should fail with permission errors—no rows from `api`.

---

## Verification

`pnpm verify` encodes these behaviors:

**Backend JWT (happy path)**
Requests with a minted `nodejs_backend` token see rows **only for that user’s `sub`**; can insert/delete own rows where policy allows; **cannot** insert a row attributed to another user (RLS `WITH CHECK`).

**Isolation**
Switching minted JWT from user A to user B changes visible rows; an “orphan” row belonging to neither is invisible to both.

**Locked down from normal API roles**
`anon` has no schema `USAGE` on `api` and cannot invoke a deliberately restricted RPC on `public`. A normal **`authenticated`** (GoTrue-style) JWT also cannot read `api` nor call `backend_only_ping`.

Rough mapping to scenario names in script output:

- A1–A3: backend role + RLS insert/select/delete
- B1–B4: anon / authenticated cannot reach protected surfaces
- C1–C2: `auth.uid()` behavior across two `sub` values + orphan row

---

## JWT shape (local)

`scripts/mint-jwt.js` signs with the active JWK from `supabase/signing_keys.json` using **RS256**, with a header including `kid`, and payload including at least:

- `aud`: `"authenticated"`
- `role`: `"nodejs_backend"` (must match the Postgres role granted to PostgREST’s session)
- `sub`: user UUID (this becomes **`auth.uid()`** in RLS for that request)

`iat` / `exp` are set; `iss` is included for parity with hosted setups. Exact validation of `iss` can differ slightly between local and hosted—your production checklist should align with **[PRODUCTION.md](./PRODUCTION.md)**.

---

## Design notes / FAQ

**Does PostgREST expose only intended data?**
With `[api].schemas` listing `public`, `graphql_public`, and `api`, callers choose schema via profiles. Even if someone targets `api`, **`anon` / `authenticated` have no `USAGE`** on `api`, so tables there are not readable with normal user tokens.

**What about grants on `public`?**
The example exposes a **`public.backend_only_ping()`** RPC whose `EXECUTE` is revoked from `anon` / `authenticated` to show one way to tighten RPC surfaces. Anything you add later under `public` should follow explicit grants/revokes; private data stays in `api`.

**Minimal claims for asymmetric local dev**
Header: `kid`, `alg: RS256`. Payload: `sub`, `role: nodejs_backend`, `aud: authenticated`, `exp` (plus usual `iat`). The role name must match Postgres.

**This is not a replacement for verifying the user server-side.**
Before minting a backend JWT in a real app, your backend must establish identity (e.g. `auth.getUser()` with the session cookie). The minted JWT is a **short-lived capability**; issue it only after you trust who is asking.

---

## Known limitations

- **GraphQL** (`/graphql/v1`): default stack may expose GraphQL; in this layout, **`api` is unreachable** without `USAGE` on the schema—but if you add `api` to GraphQL exposure, reassess grants and visibility.
- **Storage / Realtime** are not exercised here; see [PRODUCTION §7](./PRODUCTION.md#7-what-this-protects-and-what-it-doesnt) for how those surfaces behave.
- Local behavior validates migrations and JWKS-backed verification; hosted projects need Dashboard **API → Exposed schemas**, signing keys in the dashboard, and the operational steps in **[PRODUCTION.md](./PRODUCTION.md)**.

---

## Going to production

**[PRODUCTION.md](./PRODUCTION.md)** walks through:

- Trust model (browser vs Next.js server vs Supabase)
- Shared vs split keypairs for GoTrue vs backend minting
- Porting this SQL (`api` grants, dashboard settings, advisor query for stray grants)
- Next.js snippets: server-only signing, `mintBackendJwt`, `dataApiFor` with `Accept-Profile` / `Content-Profile`
- Vercel env vars, key rotation, pre-launch checklist, and what this pattern does / does not protect
