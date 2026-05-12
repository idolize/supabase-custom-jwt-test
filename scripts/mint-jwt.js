// Mint a short-lived RS256 JWT for the `nodejs_backend` Postgres role.
//
// Reads the JWK from supabase/signing_keys.json — the same key material the
// CLI hands to GoTrue, so the JWT verifies through Supabase Auth's JWKS and
// PostgREST trusts it.
//
// Usage:
//   node scripts/mint-jwt.js <sub-uuid> [role] [ttl-seconds]
//   pnpm mint <sub-uuid>
//
// Defaults: role=nodejs_backend, ttl=300s.

import fs from "node:fs/promises";
import path from "node:path";
import "dotenv/config";
import { SignJWT, importJWK } from "jose";

const KEYS_PATH =
  process.env.SUPABASE_SIGNING_KEYS_PATH ?? "./supabase/signing_keys.json";
const ISS = process.env.SUPABASE_JWT_ISS ?? "http://127.0.0.1:54321/auth/v1";

async function loadActivePrivateKey() {
  const raw = await fs.readFile(path.resolve(KEYS_PATH), "utf8");
  const keys = JSON.parse(raw);
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error(`${KEYS_PATH} must be a non-empty JSON array of JWKs`);
  }
  // The CLI emits a single key with both sign+verify ops. Prefer one
  // tagged as in_use if present (matches Supabase's hosted format).
  const jwk = keys.find((k) => k.status === "in_use")?.key ?? keys[0];
  if (jwk.alg !== "RS256") {
    throw new Error(
      `Expected RS256 JWK, got alg=${jwk.alg}. Regenerate with --algorithm RS256.`,
    );
  }
  const privateKey = await importJWK(jwk, "RS256");
  return { jwk, privateKey };
}

export async function mintBackendJwt({
  sub,
  role = "nodejs_backend",
  ttlSeconds = 300,
}) {
  if (!sub) throw new Error("sub (user UUID) is required");
  const { jwk, privateKey } = await loadActivePrivateKey();
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({ role })
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: jwk.kid })
    .setIssuer(ISS)
    .setAudience("authenticated")
    .setSubject(sub)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(privateKey);
}

// CLI entry point
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const [, , sub, role, ttl] = process.argv;
  if (!sub) {
    console.error(
      "Usage: node scripts/mint-jwt.js <sub-uuid> [role] [ttl-seconds]",
    );
    process.exit(1);
  }
  const token = await mintBackendJwt({
    sub,
    role: role || "nodejs_backend",
    ttlSeconds: ttl ? Number(ttl) : 300,
  });
  process.stdout.write(token + "\n");
}
