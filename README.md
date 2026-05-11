# Custom supabase JWT + RLS proof of concept

Proof of concept for custom JWT signing and RLS enforcement.

## Problem / Goals

I have an app that uses Supabase as the hosted DB, and uses Row-Level Security for each table with some specific rules that are critical for data safety. The app uses a separate node.js backend hosted outside of Supabase to query the data and render the React application.

Right now, the node.js app uses the supabase "Data API" (aka postgREST) with the publishable key (aka anon key) to talk to Supabase on behalf of the user, but it does so entirely on API routes that I control. _The client-side app never calls the Data API and never will_ - it only uses the Supabase client for a few authentication actions (sign out, reset password).

I want to lock down the Data API such that no random authenticated user can query it without going through the Node.js backend. I know I can (1) disable the Data API and use raw Postgres connections on our backend, but that requires moving off of PostgREST, or (2) move everything to a private schema and query it via the secret key (aka service role key), but that bypasses RLS which I want to keep for defense-in-depth.

Summary of my goals:

- Node backend can continue to query DB via the Data API
- RLS is still honored, even when the backend makes a query
- Users cannot manually query their data via the Data API (without going through the Node API) - or if they do no real data is returned (and no Postgres DB functions can be directly executed via .rpc)

## Proposed Solution

I want to investigate if using custom signed JWTs could solve this problem by allowing our backend to act on behalf of a given user while also using a custom role with access to certain DB objects that anon/authenticated roles don't have permission to access.

Note that I am using the new Supabase asymmetric keys, and I have access to the JWT signing keys (private key).

For example:

```ts
import jwt from "jsonwebtoken";

// This is the token we'll use in the 'Authorization' header
const token = jwt.sign(
  {
    aud: "authenticated",
    role: "nodejs_backend", // Your custom role
    sub: user_id_from_session,
    exp: Math.floor(Date.now() / 1000) + 60 * 5,
  },
  process.env.SUPABASE_PRIVATE_KEY, // Your RS256 Private Key
  { algorithm: "RS256" },
);
```

Then we can make an `api` DB schema that only the `nodejs_backend` role can access.

I also want to verify that any RLS policies which access `auth.uid()` still work and return the expected user ID for the user that called the nodejs backend.

## Request (spec for implementing agent)

Build a **minimal, runnable proof of concept** that proves or disproves the custom-JWT + restricted-role + RLS approach described above. The outcome should be something a human can clone, run with the Supabase CLI, and execute scripted checks against—without needing production credentials.

### Deliverables

1. **Local Supabase project** (`supabase/config.toml`, migrations, seed data if helpful) that includes:
   - A dedicated DB schema (e.g. `api`) holding at least one table with sample rows.
   - **`nodejs_backend` role** (or equivalent name) that is the **only** role granted `USAGE` on `api` and `SELECT`/`INSERT`/etc. as needed; `anon` and `authenticated` must **not** be able to read `api` tables directly (verify via PostgREST/Data API).
   - **RLS enabled** on `api` tables where **row access is enforced inside the policy expressions using `auth.uid()`** (e.g. `using (user_id = auth.uid())` or equivalent—not only `auth.jwt()`), so correctness is proven by **which rows the Data API returns**, not by calling `auth.uid()` from an unrelated SQL surface.
   - **Public schema** (or a deliberately exposed schema) with a trivial table or RPC if needed **only** to demonstrate that `.rpc` / dangerous surfaces can be locked down for anon/authenticated—align this with the stated goal that users cannot execute arbitrary DB functions via PostgREST.

2. **JWT minting script** (Node.js is fine; match the asymmetric RS256 pattern in “Proposed Solution”) that:
   - Signs a short-lived JWT with the **same key material** Supabase local dev expects for `authenticated` audience (document env vars and where to paste public/private keys if the CLI workflow requires it).
   - Sets claims minimally: `role: nodejs_backend`, `sub: <uuid>`, `aud: authenticated`, `exp`, and any other claims Supabase documents as required for validation.

3. **Verification harness** (choose one or combine):
   - Small Node script **or** `curl` examples **or** automated tests that show:
     - **Happy path:** Request to Data API with backend JWT → rows visible **only** for that user per RLS.
     - **Isolation:** Same request shape with JWT for user B → no access to user A’s rows.
     - **Negative:** `anon` key or normal **authenticated** Supabase user JWT (session from Auth) **cannot** read `api` schema data via PostgREST.
     - **`auth.uid()` inside RLS:** Demonstrate that **`auth.uid()` works as expected within RLS policies** by minting two backend JWTs with different `sub` values against the same table:
       - With JWT A, queries return **only** rows whose owning user matches A’s `sub` (per policy).
       - With JWT B, A’s rows are **invisible** and B’s rows appear as expected.
       - Optionally include one row that **no** policy should expose to either user (should never appear).
         This is the primary proof that `auth.uid()` resolves to the JWT subject **in the RLS evaluation context** used by PostgREST—not a separate `SELECT auth.uid()` helper unless you add it only as supplementary documentation.

4. **README section for operators** with exact commands: `supabase start`, how to apply migrations, how to run the mint script, base URL for PostgREST, and **expected outputs** for each check.

### Constraints and assumptions

- Target **local Supabase** via CLI; do not assume hosted-project-only features unless you clearly gate them behind notes.
- Preserve the mental model: **browser/app never calls Data API for business data** in production; this PoC may still use curl from the host machine to simulate the Node backend.
- Use **asymmetric JWT signing** consistent with current Supabase JWT verification (RS256); avoid HS256-only shortcuts unless you document why local dev differs.
- Prefer **simple** SQL and few tables over a full app framework.

### Acceptance criteria (must all be demonstrable)

| #   | Criterion                                                                                                                                                                                                                                                                    |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A   | Data API requests using the **backend minted JWT** succeed for permitted operations and see **RLS-filtered** data per `sub`.                                                                                                                                                 |
| B   | Data API requests using **anon** or normal **user** JWT cannot read protected `api` objects (403/empty as appropriate).                                                                                                                                                      |
| C   | **RLS policies that reference `auth.uid()`** enforce row visibility correctly: backend JWT with `sub = user A` yields only A’s rows; switching to `sub = user B` changes visible rows accordingly (document the policy SQL and the exact requests/responses used to verify). |
| D   | Repo runs from cold start with documented commands; no undocumented manual dashboard steps unless unavoidable (then list them explicitly).                                                                                                                                   |

### Out of scope (unless trivial)

- Production deployment, rotation, or multi-tenant key management.
- Full React or Next.js app; a backend-shaped script is enough.
- Replacing **all** Supabase Auth flows—only enough fake/fixture users to test RLS.

### Handoff notes for the implementing agent

- If Supabase local JWT verification or role naming differs from assumptions (e.g. reserved roles, claim requirements), **adjust the PoC** and document the actual behavior rather than leaving the reader guessing.
- Explicitly call out **limitations**: e.g. anything that still allows RPC exposure, GraphQL if enabled, or other APIs that bypass the intended lockdown.
- Keep secrets out of git; use `.env.example` only.

### Open questions to resolve

- Does PostgREST expose only intended schemas when `api` is private to `nodejs_backend`?
- Are any default grants on `public` or extensions enough to leak data—if so, list remediations tested.
- Exact minimal claim set Supabase accepts for custom roles with asymmetric keys in local dev.

Once this PoC passes acceptance A–D, the approach is **validated for local behavior**; production parity still requires a separate checklist (URL, JWKS, roles, and API settings).

---

## Running this PoC (operator section)

The implemented PoC lives in this repo:

```
supabase/
  config.toml                         # api schema exposed; signing_keys_path set
  signing_keys.json                   # RS256 JWK (gitignored)
  migrations/2026..._init_api_schema.sql
  seed.sql
scripts/
  mint-jwt.js                         # mint a backend JWT for a given sub
  verify.js                           # runs all acceptance checks A–D
package.json
.env.example
```

### Prereqs

Docker running, plus `supabase`, `node`, and `pnpm` on PATH.

### Cold-start

```bash
# 1. Install Node deps
pnpm install

# 2. Generate an RS256 signing key (if you don't already have one).
#    The CLI prints a single JWK; we wrap it in a JSON array — that's the
#    format the CLI's signing_keys_path expects.
supabase gen signing-key --algorithm RS256 --yes \
  | head -1 \
  | python3 -c "import sys, json; k=json.load(sys.stdin); json.dump([k], open('supabase/signing_keys.json','w'), indent=2)"

# 3. Bring up the local stack (applies migrations + seed.sql).
supabase start

# 4. Copy env (defaults are fine for the PoC).
cp .env.example .env

# 5. Run the acceptance harness.
pnpm verify
```

Expected output (all 9 checks PASS):

```
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

### Mint a JWT by hand

```bash
# user A
pnpm mint 00000000-0000-0000-0000-0000000000aa

# Use it against PostgREST. Both Accept-Profile and Content-Profile must be
# set to `api` because the api schema is not the default.
TOKEN=$(pnpm -s mint 00000000-0000-0000-0000-0000000000aa)
ANON_KEY=$(supabase status -o env | sed -n 's/^ANON_KEY="\(.*\)"$/\1/p')

curl -s "http://127.0.0.1:54321/rest/v1/notes?select=*" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept-Profile: api"
# => only rows where user_id = 0000...00aa
```

Same request with an `anon`-role JWT (`-H "Authorization: Bearer $ANON_KEY"`) returns `{"code":"42501",...}` or a `permission denied`-shaped error — no rows leak.

### How the pieces fit together

- **`supabase/config.toml`** adds `api` to `[api].schemas`, so PostgREST serves it via `Accept-Profile: api`. It also sets `[auth].signing_keys_path = "./signing_keys.json"`, so GoTrue (and therefore PostgREST via JWKS) verifies tokens signed with that RS256 key.
- **Migration** creates the `nodejs_backend` role, grants `nodejs_backend` to `authenticator` (so PostgREST can `SET LOCAL ROLE nodejs_backend` based on the JWT `role` claim), creates schema `api` with `USAGE` granted _only_ to `nodejs_backend`, and creates `api.notes` with `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY`. Policies are scoped `to nodejs_backend` and use `user_id = auth.uid()`.
- **`auth.uid()`** is the supplied Supabase helper that returns `current_setting('request.jwt.claim.sub')::uuid` — i.e. the `sub` claim of whatever JWT PostgREST verified for this request. That is the exact mechanism that lets a backend-minted JWT impersonate a user inside RLS.
- **`scripts/mint-jwt.js`** loads `supabase/signing_keys.json`, picks the active JWK, and signs an RS256 JWT with header `{kid, alg:RS256, typ:JWT}` and payload `{iss, aud:"authenticated", sub, role:"nodejs_backend", iat, exp}`.

### Behaviour that's worth noting (answers to README's open questions)

- **Does PostgREST expose only intended schemas?** Yes. With `[api].schemas = ["public","graphql_public","api"]`, requests against `api` require `Accept-Profile: api`. Even when reachable, the schema is locked because `anon`/`authenticated` have no `USAGE` grant.
- **Default grants on `public`?** The PoC's `public` schema only contains `backend_only_ping()`, whose `EXECUTE` is revoked from `public` and from `anon`/`authenticated`. Any future tables added to `public` should explicitly `grant`/`revoke`. The seeded `api.notes` is in a private schema, so the default `public` grant is irrelevant for the protected data.
- **Minimal claim set for asymmetric local dev:** `kid` (header) + `alg: RS256` (header) + `sub` (uuid) + `role: nodejs_backend` (must match the Postgres role) + `aud: "authenticated"` + `exp`. `iat` is conventional; `iss` is included for parity with hosted but local PostgREST does not strictly validate it (the locally-printed anon/service JWTs use `iss: "supabase-demo"`, while real GoTrue-issued tokens use the full URL form — both verify).

### Known limitations

- GraphQL is also exposed by default (`/graphql/v1`). Tables in `api` are not reachable via the GraphQL endpoint because that endpoint runs as `anon`/`authenticated` and they have no `USAGE` on `api`. If you ever add `api` to the GraphQL exposed schemas, you must re-do this analysis.
- The Storage and Realtime APIs are not addressed here. If you store user-owned data in Storage, mirror the same RLS pattern on `storage.objects`.
- This PoC does NOT replace Supabase Auth — your backend is still responsible for verifying the user's session (e.g. via `auth.getUser()` server-side with the user's cookie) before minting a backend JWT for that `sub`. The backend JWT is a capability token; mint it short-lived (default 5 min here) and only after you've verified the requesting user.
- For production: rotate the RS256 keypair via Supabase's signing-key rotation (a second JWK with `status: "standby"`, then promoted), keep the private key out of the Node process where possible (KMS/HSM), and consider an explicit `iss` check in any custom verification path.
