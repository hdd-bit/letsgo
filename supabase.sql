-- =====================================================================
--  탐험대 조 편성 · Supabase 설정
--  Supabase 대시보드 → SQL Editor → 이 파일 내용을 전부 붙여넣고 Run.
--  여러 번 실행해도 안전해요. (기존 학생 데이터는 지워지지 않아요)
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- 학생 명단 + 테스트 결과 + 희망 친구
create table if not exists public.tm_students (
  id           uuid primary key default gen_random_uuid(),
  name         text not null check (char_length(name) between 1 and 20),
  gender       text not null check (gender in ('남', '여')),
  type         text check (type in ('A', 'B', 'C', 'D')),
  answers      jsonb,
  wishes       uuid[] not null default '{}',
  submitted_at timestamptz,
  created_at   timestamptz not null default now(),
  unique (gender, name)
);

-- 조 인원, 친구 조건, 편성 결과 저장
create table if not exists public.tm_settings (
  key        text primary key,
  value      jsonb,
  updated_at timestamptz not null default now()
);

-- 선생님 비밀번호 (암호화 저장) + 연속 실패 잠금
create table if not exists public.tm_secret (
  id           int primary key default 1 check (id = 1),
  pw_hash      text not null,
  fail_count   int not null default 0,
  locked_until timestamptz
);

insert into public.tm_secret (id, pw_hash)
values (1, extensions.crypt('1018', extensions.gen_salt('bf')))
on conflict (id) do nothing;

-- 테이블에는 바깥에서 직접 접근할 수 없게 막고, 아래 함수로만 다룹니다.
alter table public.tm_students   enable row level security;
alter table public.tm_settings   enable row level security;
alter table public.tm_secret enable row level security;
revoke all on table public.tm_students, public.tm_settings, public.tm_secret from anon, authenticated;

-- ---------------------------------------------------------------------
-- 내부용: 비밀번호 확인 (10번 연속 틀리면 10분 잠금)
-- ---------------------------------------------------------------------
create or replace function public.tm_check_pw(p_pw text)
returns text language plpgsql security definer
set search_path = public, extensions as $$
declare s public.tm_secret;
begin
  select * into s from public.tm_secret where id = 1 for update;
  if s.locked_until is not null and s.locked_until > now() then
    return 'locked';
  end if;
  if extensions.crypt(coalesce(p_pw, ''), s.pw_hash) = s.pw_hash then
    update public.tm_secret set fail_count = 0, locked_until = null where id = 1;
    return 'ok';
  end if;
  if s.fail_count + 1 >= 10 then
    update public.tm_secret set fail_count = 0, locked_until = now() + interval '10 minutes' where id = 1;
  else
    update public.tm_secret set fail_count = fail_count + 1 where id = 1;
  end if;
  return 'bad';
end $$;

-- ---------------------------------------------------------------------
-- 학생용: 이름 목록 (이름·성별·제출 여부만, 결과와 희망 친구는 안 보임)
-- ---------------------------------------------------------------------
create or replace function public.tm_roster()
returns table (id uuid, name text, gender text, submitted boolean)
language sql stable security definer set search_path = public as $$
  select s.id, s.name, s.gender, s.submitted_at is not null
  from public.tm_students s
  order by s.gender, s.name;
$$;

-- 학생용: 결과 제출 (한 번만 가능, 다시 하려면 선생님이 '응답 초기화')
create or replace function public.tm_submit(p_id uuid, p_type text, p_answers jsonb, p_wishes uuid[])
returns jsonb language plpgsql security definer set search_path = public as $$
declare me public.tm_students; w uuid[]; ok_count int;
begin
  select * into me from public.tm_students where id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'error', 'notfound'); end if;
  if me.submitted_at is not null then return jsonb_build_object('ok', false, 'error', 'already'); end if;
  if p_type is null or p_type not in ('A', 'B', 'C', 'D') then
    return jsonb_build_object('ok', false, 'error', 'type');
  end if;
  select coalesce(array_agg(distinct x), '{}') into w
  from unnest(coalesce(p_wishes, '{}')) x where x <> p_id;
  if cardinality(w) > 3 then return jsonb_build_object('ok', false, 'error', 'wishes'); end if;
  select count(*) into ok_count from public.tm_students where id = any(w) and gender = me.gender;
  if ok_count <> cardinality(w) then return jsonb_build_object('ok', false, 'error', 'wishes'); end if;
  update public.tm_students
     set type = p_type, answers = p_answers, wishes = w, submitted_at = now()
   where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 선생님용 (모두 비밀번호 필요)
-- ---------------------------------------------------------------------
create or replace function public.tm_load(p_pw text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text;
begin
  r := public.tm_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  return jsonb_build_object(
    'ok', true,
    'students', coalesce((select jsonb_agg(to_jsonb(s) order by s.gender, s.name) from public.tm_students s), '[]'::jsonb),
    'settings', coalesce((select jsonb_object_agg(key, value) from public.tm_settings), '{}'::jsonb)
  );
end $$;

-- 학생 추가/수정. p_data: {id?, name, gender, type, wishes[], reset}
create or replace function public.tm_save_student(p_pw text, p_data jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text; v_id uuid; v_name text; v_gender text; v_type text; v_wishes uuid[];
begin
  r := public.tm_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  v_id     := nullif(p_data->>'id', '')::uuid;
  v_name   := btrim(p_data->>'name');
  v_gender := p_data->>'gender';
  v_type   := nullif(p_data->>'type', '');
  v_wishes := coalesce((select array_agg(distinct (x)::uuid) from jsonb_array_elements_text(coalesce(p_data->'wishes', '[]'::jsonb)) x), '{}');
  if v_name is null or v_name = '' then return jsonb_build_object('ok', false, 'error', 'name'); end if;
  begin
    if v_id is null then
      insert into public.tm_students (name, gender, type) values (v_name, v_gender, v_type) returning id into v_id;
    elsif coalesce((p_data->>'reset')::boolean, false) then
      update public.tm_students
         set name = v_name, gender = v_gender, type = null, answers = null, wishes = '{}', submitted_at = null
       where id = v_id;
    else
      update public.tm_students
         set name = v_name, gender = v_gender, type = v_type,
             wishes = (select coalesce(array_agg(x), '{}') from unnest(v_wishes) x where x <> v_id)
       where id = v_id;
    end if;
  exception
    when unique_violation then return jsonb_build_object('ok', false, 'error', 'dup');
    when check_violation  then return jsonb_build_object('ok', false, 'error', 'invalid');
  end;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

-- 여러 명 한꺼번에 추가. p_rows: [{name, gender}, ...] (이미 있는 이름은 건너뜀)
create or replace function public.tm_add_many(p_pw text, p_rows jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text; n int;
begin
  r := public.tm_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  with ins as (
    insert into public.tm_students (name, gender)
    select btrim(x->>'name'), x->>'gender'
    from jsonb_array_elements(p_rows) x
    where coalesce(btrim(x->>'name'), '') <> '' and x->>'gender' in ('남', '여')
    on conflict (gender, name) do nothing
    returning 1
  ) select count(*) into n from ins;
  return jsonb_build_object('ok', true, 'added', n);
end $$;

create or replace function public.tm_delete_student(p_pw text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text;
begin
  r := public.tm_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  delete from public.tm_students where id = p_id;
  update public.tm_students set wishes = array_remove(wishes, p_id) where p_id = any(wishes);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tm_set_setting(p_pw text, p_key text, p_value jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r text;
begin
  r := public.tm_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  insert into public.tm_settings (key, value, updated_at) values (p_key, p_value, now())
  on conflict (key) do update set value = excluded.value, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tm_change_pw(p_pw text, p_new text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r text;
begin
  r := public.tm_check_pw(p_pw);
  if r <> 'ok' then return jsonb_build_object('ok', false, 'error', r); end if;
  if coalesce(char_length(p_new), 0) < 4 then return jsonb_build_object('ok', false, 'error', 'short'); end if;
  update public.tm_secret set pw_hash = extensions.crypt(p_new, extensions.gen_salt('bf')) where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- 함수 실행 권한: 내부 함수는 막고, 나머지만 열어 둡니다.
revoke execute on function public.tm_check_pw(text) from public, anon, authenticated;
revoke execute on function public.tm_roster(), public.tm_submit(uuid, text, jsonb, uuid[]),
  public.tm_load(text), public.tm_save_student(text, jsonb), public.tm_add_many(text, jsonb),
  public.tm_delete_student(text, uuid), public.tm_set_setting(text, text, jsonb),
  public.tm_change_pw(text, text) from public;
grant execute on function public.tm_roster(), public.tm_submit(uuid, text, jsonb, uuid[]),
  public.tm_load(text), public.tm_save_student(text, jsonb), public.tm_add_many(text, jsonb),
  public.tm_delete_student(text, uuid), public.tm_set_setting(text, text, jsonb),
  public.tm_change_pw(text, text) to anon, authenticated;
