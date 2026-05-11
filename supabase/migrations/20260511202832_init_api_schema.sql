-- Custom-role + private-schema + RLS PoC
--
-- This migration sets up:
--   1. A `nodejs_backend` Postgres role that PostgREST can switch into when
--      a JWT has `"role": "nodejs_backend"`.
--   2. A private `api` schema that ONLY `nodejs_backend` can read/write.
--      `anon` and `authenticated` get no grants here, so even with the
--      `api` schema exposed in `config.toml -> [api].schemas`, the Data
--      API returns 401/empty for those roles.
--   3. RLS on `api.notes` that filters rows by `auth.uid()`, which resolves
--      to the JWT `sub` claim. This is the primary thing we're proving.
--   4. A locked-down RPC in `public` to demonstrate that
--      `.rpc()`-style execution can be denied to anon/authenticated.

-- 1) Custom backend role -------------------------------------------------

create role nodejs_backend nologin noinherit;

-- PostgREST connects as `authenticator` and `SET LOCAL ROLE <jwt.role>`.
-- For that to succeed, `authenticator` must be a member of nodejs_backend.
grant nodejs_backend to authenticator;

-- nodejs_backend needs to call auth.uid() / auth.jwt() inside RLS.
grant usage on schema auth to nodejs_backend;
grant execute on function auth.uid()  to nodejs_backend;
grant execute on function auth.jwt()  to nodejs_backend;
grant execute on function auth.role() to nodejs_backend;

-- 2) Private api schema --------------------------------------------------

create schema api;

-- Lock the schema down: only nodejs_backend gets USAGE.
revoke all on schema api from public;
grant usage on schema api to nodejs_backend;

-- Make sure future objects in `api` also default to nodejs_backend only.
alter default privileges in schema api
  revoke all on tables    from public;
alter default privileges in schema api
  revoke all on sequences from public;
alter default privileges in schema api
  revoke all on functions from public;

-- 3) api.notes + RLS using auth.uid() -----------------------------------

create table api.notes (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,
  body       text not null,
  created_at timestamptz not null default now()
);

-- Enable + FORCE row-level security. FORCE means the table owner is also
-- subject to RLS, so we don't accidentally bypass it during testing.
alter table api.notes enable  row level security;
alter table api.notes force   row level security;

-- A row is only visible if its user_id matches the JWT subject.
create policy notes_owner_select on api.notes
  for select to nodejs_backend
  using (user_id = auth.uid());

create policy notes_owner_insert on api.notes
  for insert to nodejs_backend
  with check (user_id = auth.uid());

create policy notes_owner_update on api.notes
  for update to nodejs_backend
  using      (user_id = auth.uid())
  with check (user_id = auth.uid());

create policy notes_owner_delete on api.notes
  for delete to nodejs_backend
  using (user_id = auth.uid());

-- Grant table-level privileges. RLS still filters rows on top of this.
grant select, insert, update, delete on api.notes to nodejs_backend;

-- 4) Locked-down public RPC --------------------------------------------
-- Public schema is reachable by anon/authenticated through PostgREST.
-- We expose a function but only grant EXECUTE to nodejs_backend, proving
-- that .rpc() from a normal user/anon JWT is denied.

create function public.backend_only_ping()
returns text
language sql
stable
as $$ select 'pong from nodejs_backend'::text $$;

revoke all on function public.backend_only_ping() from public;
revoke all on function public.backend_only_ping() from anon, authenticated;
grant execute on function public.backend_only_ping() to nodejs_backend;
