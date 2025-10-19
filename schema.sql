-- extensions (helpful)
create extension if not exists "uuid-ossp";
create extension if not exists pgcrypto;

-- users
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

-- NEW: add columns if they don't exist yet
do $$
begin
  if not exists (
    select 1 from information_schema.columns
    where table_name='users' and column_name='name'
  ) then
    alter table users add column name text;
  end if;

  if not exists (
    select 1 from information_schema.columns
    where table_name='users' and column_name='username'
  ) then
    alter table users add column username text;
  end if;
end $$;

-- make username unique (case-insensitive); duplicate-safe create
create unique index if not exists users_username_unique_idx
  on users (lower(username));

-- OPTIONAL but recommended: make email unique case-insensitively too
drop index if exists users_email_unique; -- if you had a case-sensitive one
create unique index if not exists users_email_unique_ci
  on users (lower(email));

-- friendships (unchanged)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'friendship_status') THEN
    CREATE TYPE friendship_status AS ENUM ('pending','accepted','blocked');
  END IF;
END $$ LANGUAGE plpgsql;

create table if not exists friendships (
  id uuid primary key default gen_random_uuid(),
  requester uuid not null references users(id) on delete cascade,
  addressee uuid not null references users(id) on delete cascade,
  status friendship_status not null default 'pending',
  created_at timestamptz not null default now(),
  accepted_at timestamptz
);

create unique index if not exists uniq_pair
on friendships (least(requester, addressee), greatest(requester, addressee));

-- photos (unchanged)
create table if not exists photos (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references users(id) on delete cascade,
  storage_key text not null,
  mime text not null,
  bytes int not null check (bytes > 0),
  caption text,
  taken_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists photos_owner_idx on photos(owner);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'friendship_status') THEN
    CREATE TYPE friendship_status AS ENUM ('pending','accepted','blocked');
  END IF;
END $$ LANGUAGE plpgsql;

ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_key text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='users' AND column_name='avatar_key'
  ) THEN
    ALTER TABLE users ADD COLUMN avatar_key text;
  END IF;
END $$ LANGUAGE plpgsql;