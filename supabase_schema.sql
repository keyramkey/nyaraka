-- Run this SQL once in your Supabase Dashboard -> SQL Editor

create table if not exists public.users (
  id bigint generated always as identity primary key,
  full_name text not null,
  email text not null unique,
  phone text not null default '',
  password_hash text not null,
  coins integer not null default 0 check (coins >= 0),
  unlimited_until bigint not null default 0,
  free_bonus_granted boolean not null default false,
  created_at bigint not null
);

create table if not exists public.device_claims (
  id bigint generated always as identity primary key,
  device_id text,
  cookie_token text,
  user_id bigint not null references public.users(id) on delete cascade,
  created_at bigint not null
);

create index if not exists idx_device_claims_device on public.device_claims(device_id);
create index if not exists idx_device_claims_cookie on public.device_claims(cookie_token);

create table if not exists public.payments (
  id bigint generated always as identity primary key,
  reference text not null unique,
  user_id bigint not null references public.users(id) on delete cascade,
  package_id text not null,
  package_label text not null,
  amount_tzs integer not null,
  coins_awarded integer not null default 0,
  unlimited_days integer not null default 0,
  phone_number text not null,
  status text not null default 'pending',
  provider_ref text not null default '',
  created_at bigint not null,
  completed_at bigint
);

create index if not exists idx_payments_user_created on public.payments(user_id, created_at desc);

create table if not exists public.generations (
  id bigint generated always as identity primary key,
  user_id bigint not null references public.users(id) on delete cascade,
  doc_type text not null,
  doc_label text not null,
  coins_spent integer not null,
  created_at bigint not null
);

create index if not exists idx_generations_user_created on public.generations(user_id, created_at desc);

-- Enable Row Level Security (only server-side service_role accesses tables)
alter table public.users enable row level security;
alter table public.device_claims enable row level security;
alter table public.payments enable row level security;
alter table public.generations enable row level security;

-- Atomic coin deduction for TIN / Business License generation
create or replace function public.deduct_generation_coins(
  p_user_id bigint,
  p_doc_type text,
  p_doc_label text,
  p_cost integer,
  p_now_ms bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user public.users%rowtype;
  v_is_unlimited boolean;
  v_spent integer;
begin
  select * into v_user from public.users where id = p_user_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'status_code', 404, 'error', 'Akaunti haipatikani.');
  end if;

  v_is_unlimited := coalesce(v_user.unlimited_until, 0) > p_now_ms;

  if not v_is_unlimited and coalesce(v_user.coins, 0) < p_cost then
    return jsonb_build_object(
      'ok', false,
      'status_code', 402,
      'error', format('Salio lako ni coin %s. Unahitaji coin %s kutengeneza hati. Tafadhali nunua coin kupitia Dalipay.', v_user.coins, p_cost),
      'current_coins', v_user.coins
    );
  end if;

  v_spent := case when v_is_unlimited then 0 else p_cost end;

  if v_spent > 0 then
    update public.users
       set coins = coins - v_spent
     where id = p_user_id
    returning * into v_user;
  end if;

  insert into public.generations (user_id, doc_type, doc_label, coins_spent, created_at)
  values (p_user_id, p_doc_type, p_doc_label, v_spent, p_now_ms);

  return jsonb_build_object(
    'ok', true,
    'status_code', 200,
    'coins_spent', v_spent,
    'is_unlimited', v_is_unlimited,
    'user', to_jsonb(v_user) - 'password_hash'
  );
end;
$$;

-- Atomic Dalipay payment settlement (idempotent for webhook retries)
create or replace function public.settle_dalipay_payment(
  p_reference text,
  p_provider_ref text,
  p_now_ms bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_payment public.payments%rowtype;
  v_user public.users%rowtype;
  v_base_ts bigint;
  v_next_until bigint;
begin
  select * into v_payment from public.payments where reference = p_reference for update;
  if not found then
    return jsonb_build_object('ok', false, 'status_code', 404, 'error', 'Payment reference not found.');
  end if;

  if v_payment.status = 'completed' then
    return jsonb_build_object('ok', true, 'status', 'completed');
  end if;

  select * into v_user from public.users where id = v_payment.user_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'status_code', 404, 'error', 'User not found.');
  end if;

  if coalesce(v_payment.coins_awarded, 0) > 0 then
    update public.users
       set coins = coins + v_payment.coins_awarded
     where id = v_user.id;
  end if;

  if coalesce(v_payment.unlimited_days, 0) > 0 then
    v_base_ts := case when coalesce(v_user.unlimited_until, 0) > p_now_ms then v_user.unlimited_until else p_now_ms end;
    v_next_until := v_base_ts + (v_payment.unlimited_days::bigint * 86400000);
    update public.users
       set unlimited_until = v_next_until
     where id = v_user.id;
  end if;

  update public.payments
     set status = 'completed',
         provider_ref = coalesce(nullif(p_provider_ref, ''), provider_ref),
         completed_at = p_now_ms
   where reference = p_reference;

  return jsonb_build_object('ok', true, 'status', 'completed');
end;
$$;

grant usage on schema public to service_role;
grant select, insert, update, delete on table public.users, public.device_claims, public.payments, public.generations to service_role;
grant usage, select on all sequences in schema public to service_role;

revoke all on function public.deduct_generation_coins(bigint, text, text, integer, bigint) from public, anon, authenticated;
revoke all on function public.settle_dalipay_payment(text, text, bigint) from public, anon, authenticated;
grant execute on function public.deduct_generation_coins(bigint, text, text, integer, bigint) to service_role;
grant execute on function public.settle_dalipay_payment(text, text, bigint) to service_role;
