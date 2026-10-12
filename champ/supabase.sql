-- =====================================================================
--  챔피언반 역할 지원 · Supabase 설정
--  Supabase 대시보드 → SQL Editor → 이 파일 내용을 전부 붙여넣고 Run.
--  여러 번 실행해도 안전해요. (학생·지원서·배정 기록은 지워지지 않아요)
--  탐험대(tm_ 표)와 같은 프로젝트를 쓰지만 표는 ch_ 로 따로 있어요.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- 학생 명단
create table if not exists public.ch_students (
  id         uuid primary key default gen_random_uuid(),
  name       text not null unique check (char_length(name) between 1 and 20),
  active     boolean not null default true,
  sort       int not null default 0,
  created_at timestamptz not null default now()
);

-- 회차(달). status: ready 준비 중 / open 지원 받는 중 / closed 마감·배정 중 / published 결과 공개
-- config: {"depts": {"edu": {"pay":70, "bad":70, "cap":6}, ...}, "unit": "챔"}
create table if not exists public.ch_rounds (
  id         uuid primary key default gen_random_uuid(),
  title      text not null check (char_length(title) between 1 and 30),
  status     text not null default 'ready' check (status in ('ready', 'open', 'closed', 'published')),
  config     jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- 지원서 (회차마다 학생 1장)
create table if not exists public.ch_apps (
  round_id     uuid not null references public.ch_rounds(id) on delete cascade,
  student_id   uuid not null references public.ch_students(id) on delete cascade,
  prev_dept    text,
  c1 text not null, why1 text not null, vow1 text not null, eff1 int not null check (eff1 between 1 and 5),
  c2 text not null, why2 text not null, vow2 text, eff2 int not null check (eff2 between 1 and 5),
  submitted_at timestamptz not null default now(),
  primary key (round_id, student_id)
);

-- 배정 결과 + 역할 수행 체크 + 월급 조정
create table if not exists public.ch_assign (
  round_id   uuid not null references public.ch_rounds(id) on delete cascade,
  student_id uuid not null references public.ch_students(id) on delete cascade,
  dept       text not null,
  perf       text not null default 'ok' check (perf in ('ok', 'bad')),
  bonus      int not null default 0,
  memo       text not null default '',
  primary key (round_id, student_id)
);

-- 부서 소개(하는 일) 같은 공통 설정
create table if not exists public.ch_settings (
  key        text primary key,
  value      jsonb,
  updated_at timestamptz not null default now()
);

-- 선생님 비밀번호 (암호화 저장) + 연속 실패 잠금
create table if not exists public.ch_secret (
  id           int primary key default 1 check (id = 1),
  pw_hash      text not null,
  fail_count   int not null default 0,
  locked_until timestamptz
);
insert into public.ch_secret (id, pw_hash)
values (1, extensions.crypt('1018', extensions.gen_salt('bf')))
on conflict (id) do nothing;

-- 표는 바깥에서 직접 못 만지게 막고, 아래 함수로만 다룹니다.
alter table public.ch_students enable row level security;
alter table public.ch_rounds   enable row level security;
alter table public.ch_apps     enable row level security;
alter table public.ch_assign   enable row level security;
alter table public.ch_settings enable row level security;
alter table public.ch_secret   enable row level security;
revoke all on table public.ch_students, public.ch_rounds, public.ch_apps, public.ch_assign,
  public.ch_settings, public.ch_secret from anon, authenticated;

-- ---------------------------------------------------------------------
-- 내부용
-- ---------------------------------------------------------------------
create or replace function public.ch_check_pw(p_pw text)
returns text language plpgsql security definer
set search_path = public, extensions as $$
declare s public.ch_secret;
begin
  select * into s from public.ch_secret where id = 1 for update;
  if s.locked_until is not null and s.locked_until > now() then return 'locked'; end if;
  if extensions.crypt(coalesce(p_pw, ''), s.pw_hash) = s.pw_hash then
    update public.ch_secret set fail_count = 0, locked_until = null where id = 1;
    return 'ok';
  end if;
  if s.fail_count + 1 >= 10 then
    update public.ch_secret set fail_count = 0, locked_until = now() + interval '10 minutes' where id = 1;
  else
    update public.ch_secret set fail_count = fail_count + 1 where id = 1;
  end if;
  return 'bad';
end $$;

create or replace function public.ch_dept_ok(p text)
returns boolean language sql immutable as $$
  select p = any (array['edu', 'env', 'cul', 'fin', 'saf']);
$$;

-- ---------------------------------------------------------------------
-- 학생용 (비밀번호 없음): 이름 목록, 이번 회차, 월급표, 공개된 결과만
-- 지원서 내용은 여기서 절대 나오지 않아요.
-- ---------------------------------------------------------------------
create or replace function public.ch_public()
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare cur public.ch_rounds;
begin
  select * into cur from public.ch_rounds order by created_at desc limit 1;
  return jsonb_build_object(
    'depts', (select value from public.ch_settings where key = 'depts'),
    'round', case when cur.id is null then null else
      jsonb_build_object('id', cur.id, 'title', cur.title, 'status', cur.status, 'config', cur.config) end,
    'students', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', s.id, 'name', s.name,
        'last_dept', (select a.dept from public.ch_assign a join public.ch_rounds r on r.id = a.round_id
                       where a.student_id = s.id and r.status = 'published' and r.id is distinct from cur.id
                       order by r.created_at desc limit 1)
      ) order by s.sort, s.name)
      from public.ch_students s where s.active), '[]'::jsonb),
    'submitted', coalesce((select jsonb_agg(student_id) from public.ch_apps where round_id = cur.id), '[]'::jsonb),
    'results', case when cur.status = 'published' then coalesce((
      select jsonb_agg(jsonb_build_object('student_id', a.student_id, 'dept', a.dept, 'memo', a.memo,
                                          'perf', a.perf, 'bonus', a.bonus))
      from public.ch_assign a where a.round_id = cur.id), '[]'::jsonb) else '[]'::jsonb end
  );
end $$;

-- 학생용: 지원서 내기 (지원 받는 중일 때만, 다시 내면 새로 덮어씀)
create or replace function public.ch_submit(p_round uuid, p_student uuid, p_data jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.ch_rounds; v_prev text; v_c1 text; v_c2 text; v_e1 int; v_e2 int;
        v_why1 text; v_vow1 text; v_why2 text; v_vow2 text;
begin
  select * into r from public.ch_rounds where id = p_round;
  if r.id is null or r.status <> 'open' then return jsonb_build_object('ok', false, 'error', 'closed'); end if;
  if not exists (select 1 from public.ch_students where id = p_student and active) then
    return jsonb_build_object('ok', false, 'error', 'student');
  end if;
  v_prev := nullif(p_data->>'prev_dept', '');
  v_c1 := p_data->>'c1'; v_c2 := p_data->>'c2';
  v_why1 := btrim(coalesce(p_data->>'why1', '')); v_vow1 := btrim(coalesce(p_data->>'vow1', ''));
  v_why2 := btrim(coalesce(p_data->>'why2', '')); v_vow2 := btrim(coalesce(p_data->>'vow2', ''));
  begin
    v_e1 := (p_data->>'eff1')::int; v_e2 := (p_data->>'eff2')::int;
  exception when others then return jsonb_build_object('ok', false, 'error', 'invalid');
  end;
  if v_prev is not null and v_prev <> 'none' and not public.ch_dept_ok(v_prev) then
    return jsonb_build_object('ok', false, 'error', 'invalid');
  end if;
  if not public.ch_dept_ok(v_c1) or not public.ch_dept_ok(v_c2) or v_c1 = v_c2 then
    return jsonb_build_object('ok', false, 'error', 'dept');
  end if;
  if v_why1 = '' or v_vow1 = '' or v_why2 = '' or v_e1 not between 1 and 5 or v_e2 not between 1 and 5 then
    return jsonb_build_object('ok', false, 'error', 'empty');
  end if;
  if greatest(char_length(v_why1), char_length(v_vow1), char_length(v_why2), char_length(v_vow2)) > 600 then
    return jsonb_build_object('ok', false, 'error', 'long');
  end if;
  insert into public.ch_apps (round_id, student_id, prev_dept, c1, why1, vow1, eff1, c2, why2, vow2, eff2, submitted_at)
  values (p_round, p_student, v_prev, v_c1, v_why1, v_vow1, v_e1, v_c2, v_why2, nullif(v_vow2, ''), v_e2, now())
  on conflict (round_id, student_id) do update set
    prev_dept = excluded.prev_dept, c1 = excluded.c1, why1 = excluded.why1, vow1 = excluded.vow1, eff1 = excluded.eff1,
    c2 = excluded.c2, why2 = excluded.why2, vow2 = excluded.vow2, eff2 = excluded.eff2, submitted_at = now();
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 선생님용 (모두 비밀번호 필요)
-- ---------------------------------------------------------------------
create or replace function public.ch_load(p_pw text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  return jsonb_build_object(
    'ok', true,
    'students', coalesce((select jsonb_agg(to_jsonb(s) order by s.sort, s.name) from public.ch_students s), '[]'::jsonb),
    'rounds',   coalesce((select jsonb_agg(to_jsonb(x) order by x.created_at) from public.ch_rounds x), '[]'::jsonb),
    'apps',     coalesce((select jsonb_agg(to_jsonb(a)) from public.ch_apps a), '[]'::jsonb),
    'assign',   coalesce((select jsonb_agg(to_jsonb(a)) from public.ch_assign a), '[]'::jsonb),
    'settings', coalesce((select jsonb_object_agg(key, value) from public.ch_settings), '{}'::jsonb)
  );
end $$;

-- 학생 추가/수정. p_data: {id?, name, active, sort}
create or replace function public.ch_save_student(p_pw text, p_data jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text; v_id uuid; v_name text;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  v_id := nullif(p_data->>'id', '')::uuid;
  v_name := regexp_replace(coalesce(p_data->>'name', ''), '\s', '', 'g');
  if v_name = '' or char_length(v_name) > 20 then return jsonb_build_object('ok', false, 'error', 'name'); end if;
  begin
    if v_id is null then
      insert into public.ch_students (name, sort)
      values (v_name, coalesce((p_data->>'sort')::int, (select coalesce(max(sort), 0) + 1 from public.ch_students)))
      returning id into v_id;
    else
      update public.ch_students set name = v_name,
        active = coalesce((p_data->>'active')::boolean, active),
        sort = coalesce((p_data->>'sort')::int, sort)
      where id = v_id;
    end if;
  exception when unique_violation then return jsonb_build_object('ok', false, 'error', 'dup');
  end;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

create or replace function public.ch_delete_student(p_pw text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  delete from public.ch_students where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

-- 회차 만들기/고치기. p_data: {id?, title, status, config}
create or replace function public.ch_save_round(p_pw text, p_data jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text; v_id uuid;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  v_id := nullif(p_data->>'id', '')::uuid;
  begin
    if v_id is null then
      insert into public.ch_rounds (title, status, config)
      values (btrim(p_data->>'title'), coalesce(p_data->>'status', 'ready'), coalesce(p_data->'config', '{}'::jsonb))
      returning id into v_id;
    else
      update public.ch_rounds set
        title  = coalesce(nullif(btrim(p_data->>'title'), ''), title),
        status = coalesce(p_data->>'status', status),
        config = coalesce(p_data->'config', config)
      where id = v_id;
    end if;
  exception when check_violation or not_null_violation then return jsonb_build_object('ok', false, 'error', 'invalid');
  end;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

create or replace function public.ch_delete_round(p_pw text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  delete from public.ch_rounds where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

-- 배정 저장. p_rows: [{student_id, dept(null이면 배정 취소), perf, bonus, memo}]
create or replace function public.ch_set_assign(p_pw text, p_round uuid, p_rows jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text; x jsonb;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  for x in select * from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) loop
    if coalesce(x->>'dept', '') = '' then
      delete from public.ch_assign where round_id = p_round and student_id = (x->>'student_id')::uuid;
    elsif public.ch_dept_ok(x->>'dept') then
      insert into public.ch_assign (round_id, student_id, dept, perf, bonus, memo)
      values (p_round, (x->>'student_id')::uuid, x->>'dept',
              case when x->>'perf' = 'bad' then 'bad' else 'ok' end,
              coalesce((x->>'bonus')::int, 0), left(coalesce(x->>'memo', ''), 60))
      on conflict (round_id, student_id) do update set
        dept = excluded.dept, perf = excluded.perf, bonus = excluded.bonus, memo = excluded.memo;
    end if;
  end loop;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ch_delete_app(p_pw text, p_round uuid, p_student uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  delete from public.ch_apps where round_id = p_round and student_id = p_student;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ch_set_setting(p_pw text, p_key text, p_value jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  insert into public.ch_settings (key, value, updated_at) values (p_key, p_value, now())
  on conflict (key) do update set value = excluded.value, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ch_change_pw(p_pw text, p_new text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r text;
begin
  r := public.ch_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  if coalesce(char_length(p_new), 0) < 4 then return jsonb_build_object('ok', false, 'error', 'short'); end if;
  update public.ch_secret set pw_hash = extensions.crypt(p_new, extensions.gen_salt('bf')) where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- 함수 실행 권한: 내부 함수는 막고, 나머지만 열어 둡니다.
revoke execute on function public.ch_check_pw(text) from public, anon, authenticated;
revoke execute on function public.ch_public(), public.ch_submit(uuid, uuid, jsonb),
  public.ch_load(text), public.ch_save_student(text, jsonb), public.ch_delete_student(text, uuid),
  public.ch_save_round(text, jsonb), public.ch_delete_round(text, uuid),
  public.ch_set_assign(text, uuid, jsonb), public.ch_delete_app(text, uuid, uuid),
  public.ch_set_setting(text, text, jsonb), public.ch_change_pw(text, text) from public;
grant execute on function public.ch_public(), public.ch_submit(uuid, uuid, jsonb),
  public.ch_load(text), public.ch_save_student(text, jsonb), public.ch_delete_student(text, uuid),
  public.ch_save_round(text, jsonb), public.ch_delete_round(text, uuid),
  public.ch_set_assign(text, uuid, jsonb), public.ch_delete_app(text, uuid, uuid),
  public.ch_set_setting(text, text, jsonb), public.ch_change_pw(text, text) to anon, authenticated;
