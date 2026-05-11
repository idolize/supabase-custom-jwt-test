// End-to-end PoC harness. Runs the four acceptance checks from README.md
// against a local `supabase start` and prints PASS/FAIL for each.
//
// Run:  pnpm verify

import { execSync } from "node:child_process";
import "dotenv/config";
import { mintBackendJwt } from "./mint-jwt.js";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const USER_A = process.env.USER_A_ID ?? "00000000-0000-0000-0000-0000000000aa";
const USER_B = process.env.USER_B_ID ?? "00000000-0000-0000-0000-0000000000bb";
const USER_ORPHAN = process.env.USER_ORPHAN_ID ?? "00000000-0000-0000-0000-0000000000cc";

// Pull the anon publishable key from `supabase status` so we don't have to
// hardcode it. Anyone running the PoC just needs the CLI on PATH.
function loadAnonKey() {
  if (process.env.SUPABASE_ANON_KEY) return process.env.SUPABASE_ANON_KEY;
  const out = execSync("supabase status -o env", { stdio: ["ignore", "pipe", "ignore"] }).toString();
  const m = out.match(/^ANON_KEY="?([^"\n]+)"?$/m);
  if (!m) throw new Error("Could not extract ANON_KEY from `supabase status -o env`");
  return m[1];
}

const ANON_KEY = loadAnonKey();

// PostgREST request to the `api` schema. Supabase requires the
// `Accept-Profile` header to address a non-default schema.
async function pgrest(path, { jwt, method = "GET", body, profile = "api", prefer } = {}) {
  const headers = {
    "Accept-Profile": profile,
    "Content-Profile": profile,
    apikey: ANON_KEY,
  };
  if (jwt) headers["Authorization"] = `Bearer ${jwt}`;
  if (body) headers["Content-Type"] = "application/json";
  if (prefer) headers["Prefer"] = prefer;
  const res = await fetch(`${SUPABASE_URL}/rest/v1${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : null; } catch { json = text; }
  return { status: res.status, body: json };
}

// Each test returns { ok: bool, detail: string }.
const checks = [];
function check(label, fn) { checks.push({ label, fn }); }

// ---------------------------------------------------------------- A
check("A1: backend JWT for user A returns only A's rows", async () => {
  const jwt = await mintBackendJwt({ sub: USER_A });
  const { status, body } = await pgrest("/notes?select=id,user_id,body&order=body", { jwt });
  const ok = status === 200
    && Array.isArray(body)
    && body.length >= 2
    && body.every((r) => r.user_id === USER_A);
  return { ok, detail: `status=${status} rows=${JSON.stringify(body)}` };
});

check("A2: backend JWT for user A can insert + then delete its own row", async () => {
  const jwt = await mintBackendJwt({ sub: USER_A });
  const ins = await pgrest("/notes?select=id", {
    jwt,
    method: "POST",
    prefer: "return=representation",
    body: { user_id: USER_A, body: "A: inserted via Data API" },
  });
  // PostgREST returns 201 with body=[{id}] when given Prefer: return=representation,
  // but by default returns 201 with empty body. We sent select= which forces a body.
  const id = Array.isArray(ins.body) ? ins.body[0]?.id : null;
  if (!id || (ins.status !== 201 && ins.status !== 200)) {
    return { ok: false, detail: `insert status=${ins.status} body=${JSON.stringify(ins.body)}` };
  }
  const del = await pgrest(`/notes?id=eq.${id}`, { jwt, method: "DELETE" });
  const ok = del.status >= 200 && del.status < 300;
  return { ok, detail: `insert=${ins.status} delete=${del.status} body=${JSON.stringify(del.body)}` };
});

check("A3: backend JWT for user A CANNOT insert a row for user B (RLS WITH CHECK)", async () => {
  const jwt = await mintBackendJwt({ sub: USER_A });
  const { status, body } = await pgrest("/notes", {
    jwt,
    method: "POST",
    body: { user_id: USER_B, body: "A trying to write as B" },
  });
  // Postgres returns 403 (RLS violation) or PGRST simulates same.
  const ok = status === 403 || status === 401 || status === 400 || status === 409;
  return { ok, detail: `status=${status} body=${JSON.stringify(body)}` };
});

// ---------------------------------------------------------------- B
check("B1: anon JWT cannot read api.notes (no USAGE on schema)", async () => {
  const { status, body } = await pgrest("/notes?select=*", { jwt: ANON_KEY });
  // Either 401/403 or 404 (schema invisible) is acceptable; the row list
  // must NOT come back.
  const leaked = Array.isArray(body) && body.length > 0;
  const ok = !leaked && status >= 400;
  return { ok, detail: `status=${status} body=${JSON.stringify(body)}` };
});

check("B2: anon cannot call locked-down RPC public.backend_only_ping", async () => {
  const { status, body } = await pgrest("/rpc/backend_only_ping", {
    jwt: ANON_KEY,
    method: "POST",
    body: {},
    profile: "public",
  });
  const ok = status >= 400; // EXECUTE was revoked
  return { ok, detail: `status=${status} body=${JSON.stringify(body)}` };
});

// Mint a "normal Supabase user" JWT (role: authenticated) using the same
// signing key. This is what a real session JWT from Supabase Auth looks
// like — and it should NOT be able to read api.notes either.
check("B3: normal authenticated user JWT cannot read api.notes", async () => {
  const jwt = await mintBackendJwt({ sub: USER_A, role: "authenticated" });
  const { status, body } = await pgrest("/notes?select=*", { jwt });
  const leaked = Array.isArray(body) && body.length > 0;
  const ok = !leaked && status >= 400;
  return { ok, detail: `status=${status} body=${JSON.stringify(body)}` };
});

check("B4: normal authenticated user JWT cannot call backend_only_ping", async () => {
  const jwt = await mintBackendJwt({ sub: USER_A, role: "authenticated" });
  const { status, body } = await pgrest("/rpc/backend_only_ping", {
    jwt,
    method: "POST",
    body: {},
    profile: "public",
  });
  const ok = status >= 400;
  return { ok, detail: `status=${status} body=${JSON.stringify(body)}` };
});

// ---------------------------------------------------------------- C
check("C1: switching JWT sub from A to B changes visible rows", async () => {
  const jwtB = await mintBackendJwt({ sub: USER_B });
  const { status, body } = await pgrest("/notes?select=id,user_id,body&order=body", {
    jwt: jwtB,
  });
  const ok = status === 200
    && Array.isArray(body)
    && body.length === 2
    && body.every((r) => r.user_id === USER_B);
  return { ok, detail: `status=${status} rows=${JSON.stringify(body)}` };
});

check("C2: orphan row is invisible to both A and B", async () => {
  const jwtA = await mintBackendJwt({ sub: USER_A });
  const jwtB = await mintBackendJwt({ sub: USER_B });
  const a = await pgrest("/notes?user_id=eq." + USER_ORPHAN, { jwt: jwtA });
  const b = await pgrest("/notes?user_id=eq." + USER_ORPHAN, { jwt: jwtB });
  const ok = a.status === 200 && b.status === 200
    && Array.isArray(a.body) && a.body.length === 0
    && Array.isArray(b.body) && b.body.length === 0;
  return { ok, detail: `A=${JSON.stringify(a)} B=${JSON.stringify(b)}` };
});

// Run -------------------------------------------------------------

let failed = 0;
console.log(`PostgREST URL: ${SUPABASE_URL}\n`);
for (const { label, fn } of checks) {
  try {
    const { ok, detail } = await fn();
    console.log(`${ok ? "PASS" : "FAIL"}  ${label}`);
    if (!ok) {
      console.log(`        ${detail}`);
      failed++;
    }
  } catch (e) {
    console.log(`FAIL  ${label}\n        ${e.message}`);
    failed++;
  }
}

console.log(`\n${failed === 0 ? "All checks passed." : `${failed} check(s) failed.`}`);
process.exit(failed === 0 ? 0 : 1);
