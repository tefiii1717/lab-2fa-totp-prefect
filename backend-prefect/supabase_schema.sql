-- Ejecutar en Supabase > SQL Editor si se usa DB_BACKEND=supabase.
-- El backend usa la service_role key (solo del lado del servidor), por eso RLS queda activado sin políticas públicas.

create table if not exists public.users (
    id bigint generated always as identity primary key,
    username text unique not null,
    password_hash text not null,
    twofa_status text not null default 'DISABLED'
        check (twofa_status in ('DISABLED', 'PENDING_VERIFICATION', 'ACTIVE')),
    totp_secret text,
    created_at timestamptz not null default now()
);

create table if not exists public.backup_codes (
    id bigint generated always as identity primary key,
    user_id bigint not null references public.users(id) on delete cascade,
    code_hash text not null,
    used_at timestamptz
);

create index if not exists backup_codes_user_idx on public.backup_codes (user_id);

alter table public.users enable row level security;
alter table public.backup_codes enable row level security;
