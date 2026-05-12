// End-to-end PoC harness. Runs the four acceptance checks from README.md
// against a local `supabase start` and prints PASS/FAIL for each.
//
// Run:  pnpm verify

import { execSync } from "node:child_process";
import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
import { mintBackendJwt } from "./mint-jwt.js";

const SUPABASE_URL = process.env.SUPABASE_URL ?? "http://127.0.0.1:54321";
const USER_A = process.env.USER_A_ID ?? "00000000-0000-0000-0000-0000000000aa";
const USER_B = process.env.USER_B_ID ?? "00000000-0000-0000-0000-0000000000bb";
const USER_ORPHAN =
  process.env.USER_ORPHAN_ID ?? "00000000-0000-0000-0000-0000000000cc";

// Pull the publishable key from `supabase status` so we don't have to
// hardcode it. Unlike the legacy ANON_KEY (a long-lived JWT), this is the
// new opaque `sb_publishable_...` token tied to the asymmetric signing
// keys. Anyone running the PoC just needs the CLI on PATH.
function loadPublishableKey() {
  if (process.env.SUPABASE_PUBLISHABLE_KEY)
    return process.env.SUPABASE_PUBLISHABLE_KEY;
  const out = execSync("supabase status -o env", {
    stdio: ["ignore", "pipe", "ignore"],
  }).toString();
  const m = out.match(/^PUBLISHABLE_KEY="?([^"\n]+)"?$/m);
  if (!m)
    throw new Error(
      "Could not extract PUBLISHABLE_KEY from `supabase status -o env`",
    );
  return m[1];
}

const PUBLISHABLE_KEY = loadPublishableKey();

// Fresh supabase-js client per test. The publishable key always goes in
// `apikey` (via the second createClient arg). `db.schema` makes the client
// send the `Accept-Profile` / `Content-Profile` headers needed to address
// our private `api` schema. When `jwt` is provided, it overrides the
// `Authorization` header so PostgREST verifies that JWT instead of falling
// back to the anon role implied by the publishable key.
function clientFor(jwt, { schema = "api" } = {}) {
  const headers = {};
  if (jwt) headers["Authorization"] = `Bearer ${jwt}`;
  return createClient(SUPABASE_URL, PUBLISHABLE_KEY, {
    db: { schema },
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers },
  });
}

const checks = [];
function check(label, fn) {
  checks.push({ label, fn });
}
const errMsg = (e) => e?.message ?? "none";

// ---------------------------------------------------------------- A
check("A1: backend JWT for user A returns only A's rows", async () => {
  const jwt = await mintBackendJwt({ sub: USER_A });
  const sb = clientFor(jwt);
  const { data, error, status } = await sb
    .from("notes")
    .select("id,user_id,body")
    .order("body");
  const ok =
    !error &&
    Array.isArray(data) &&
    data.length >= 2 &&
    data.every((r) => r.user_id === USER_A);
  return {
    ok,
    detail: `status=${status} error=${errMsg(error)} rows=${JSON.stringify(data)}`,
  };
});

check(
  "A2: backend JWT for user A can insert + then delete its own row",
  async () => {
    const jwt = await mintBackendJwt({ sub: USER_A });
    const sb = clientFor(jwt);
    const ins = await sb
      .from("notes")
      .insert({ user_id: USER_A, body: "A: inserted via Data API" })
      .select("id")
      .single();
    if (ins.error || !ins.data?.id) {
      return {
        ok: false,
        detail: `insert status=${ins.status} error=${errMsg(ins.error)}`,
      };
    }
    const del = await sb.from("notes").delete().eq("id", ins.data.id);
    const ok = !del.error;
    return {
      ok,
      detail: `insert=${ins.status} delete=${del.status} error=${errMsg(del.error)}`,
    };
  },
);

check(
  "A3: backend JWT for user A CANNOT insert a row for user B (RLS WITH CHECK)",
  async () => {
    const jwt = await mintBackendJwt({ sub: USER_A });
    const sb = clientFor(jwt);
    const { data, error, status } = await sb
      .from("notes")
      .insert({ user_id: USER_B, body: "A trying to write as B" });
    const ok = !!error;
    return {
      ok,
      detail: `status=${status} error=${errMsg(error)} data=${JSON.stringify(data)}`,
    };
  },
);

// ---------------------------------------------------------------- B
check(
  "B1: anon (publishable-key only) cannot read api.notes (no USAGE on schema)",
  async () => {
    const sb = clientFor(null);
    const { data, error, status } = await sb.from("notes").select("*");
    const leaked = Array.isArray(data) && data.length > 0;
    const ok =
      !leaked && (!!error || (Array.isArray(data) && data.length === 0));
    return {
      ok,
      detail: `status=${status} error=${errMsg(error)} data=${JSON.stringify(data)}`,
    };
  },
);

check(
  "B2: anon cannot call locked-down RPC public.backend_only_ping",
  async () => {
    const sb = clientFor(null, { schema: "public" });
    const { data, error, status } = await sb.rpc("backend_only_ping");
    const ok = !!error; // EXECUTE was revoked
    return {
      ok,
      detail: `status=${status} error=${errMsg(error)} data=${JSON.stringify(data)}`,
    };
  },
);

// Mint a "normal Supabase user" JWT (role: authenticated) using the same
// signing key. This is what a real session JWT from Supabase Auth looks
// like — and it should NOT be able to read api.notes either.
check("B3: normal authenticated user JWT cannot read api.notes", async () => {
  const jwt = await mintBackendJwt({ sub: USER_A, role: "authenticated" });
  const sb = clientFor(jwt);
  const { data, error, status } = await sb.from("notes").select("*");
  const leaked = Array.isArray(data) && data.length > 0;
  const ok = !leaked && (!!error || (Array.isArray(data) && data.length === 0));
  return {
    ok,
    detail: `status=${status} error=${errMsg(error)} data=${JSON.stringify(data)}`,
  };
});

check(
  "B4: normal authenticated user JWT cannot call backend_only_ping",
  async () => {
    const jwt = await mintBackendJwt({ sub: USER_A, role: "authenticated" });
    const sb = clientFor(jwt, { schema: "public" });
    const { data, error, status } = await sb.rpc("backend_only_ping");
    const ok = !!error;
    return {
      ok,
      detail: `status=${status} error=${errMsg(error)} data=${JSON.stringify(data)}`,
    };
  },
);

// ---------------------------------------------------------------- C
check("C1: switching JWT sub from A to B changes visible rows", async () => {
  const jwt = await mintBackendJwt({ sub: USER_B });
  const sb = clientFor(jwt);
  const { data, error, status } = await sb
    .from("notes")
    .select("id,user_id,body")
    .order("body");
  const ok =
    !error &&
    Array.isArray(data) &&
    data.length === 2 &&
    data.every((r) => r.user_id === USER_B);
  return {
    ok,
    detail: `status=${status} error=${errMsg(error)} rows=${JSON.stringify(data)}`,
  };
});

check("C2: orphan row is invisible to both A and B", async () => {
  const sbA = clientFor(await mintBackendJwt({ sub: USER_A }));
  const sbB = clientFor(await mintBackendJwt({ sub: USER_B }));
  const a = await sbA.from("notes").select("*").eq("user_id", USER_ORPHAN);
  const b = await sbB.from("notes").select("*").eq("user_id", USER_ORPHAN);
  const ok =
    !a.error &&
    !b.error &&
    Array.isArray(a.data) &&
    a.data.length === 0 &&
    Array.isArray(b.data) &&
    b.data.length === 0;
  const summary = (r) => ({
    status: r.status,
    data: r.data,
    error: errMsg(r.error),
  });
  return {
    ok,
    detail: `A=${JSON.stringify(summary(a))} B=${JSON.stringify(summary(b))}`,
  };
});

// Run -------------------------------------------------------------

let failed = 0;
console.log(`Supabase URL: ${SUPABASE_URL}\n`);
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

console.log(
  `\n${failed === 0 ? "All checks passed." : `${failed} check(s) failed.`}`,
);
process.exit(failed === 0 ? 0 : 1);
