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

-- friendships (undirected once accepted)
create type friendship_status as enum ('pending','accepted','blocked');

create table if not exists friendships (
  id uuid primary key default gen_random_uuid(),
  requester uuid not null references users(id) on delete cascade,
  addressee uuid not null references users(id) on delete cascade,
  status friendship_status not null default 'pending',
  created_at timestamptz not null default now(),
  accepted_at timestamptz
);

-- one active edge per unordered pair (pending or accepted)
create unique index if not exists uniq_pair
on friendships (least(requester, addressee), greatest(requester, addressee));

-- photos metadata; image file goes to S3/R2, not DB
create table if not exists photos (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references users(id) on delete cascade,
  storage_key text not null,        -- e.g., uploads/{owner}/{uuid}.webp
  mime text not null,
  bytes int not null check (bytes > 0),
  caption text,
  taken_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists photos_owner_idx on photos(owner);
