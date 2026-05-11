-- Fixture data for the RLS PoC.
--
-- Two synthetic users (A, B) with notes each, plus one "orphan" note whose
-- user_id matches neither — it should be invisible to both JWTs.
--
-- We do NOT insert into auth.users; nothing here exercises Supabase Auth
-- itself. The RLS policy only compares api.notes.user_id to auth.uid()
-- (= JWT.sub), so any UUID works as a fixture subject.

insert into api.notes (id, user_id, body) values
  ('11111111-1111-1111-1111-111111111111',
   '00000000-0000-0000-0000-0000000000aa',
   'A: top-secret note for user A'),
  ('22222222-2222-2222-2222-222222222222',
   '00000000-0000-0000-0000-0000000000aa',
   'A: another note for user A'),
  ('33333333-3333-3333-3333-333333333333',
   '00000000-0000-0000-0000-0000000000bb',
   'B: top-secret note for user B'),
  ('44444444-4444-4444-4444-444444444444',
   '00000000-0000-0000-0000-0000000000bb',
   'B: another note for user B'),
  ('99999999-9999-9999-9999-999999999999',
   '00000000-0000-0000-0000-0000000000cc',
   'ORPHAN: nobody should ever see this');
