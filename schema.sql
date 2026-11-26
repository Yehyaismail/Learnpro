-- شغّل هذا الملف كاملاً في Supabase: SQL Editor > New query > Run
create table profiles(
  id uuid primary key references auth.users on delete cascade,
  name text not null default '', email text, about text default '',
  is_admin bool not null default false, banned bool not null default false,
  last_seen timestamptz default now(), created_at timestamptz default now());
create table chats(
  id uuid primary key default gen_random_uuid(),
  is_group bool not null default false, title text,
  created_by uuid references profiles(id), created_at timestamptz default now());
create table chat_members(
  chat_id uuid references chats on delete cascade,
  user_id uuid references profiles on delete cascade,
  pinned bool not null default false, muted bool not null default false,
  last_read_at timestamptz default now(), primary key(chat_id,user_id));
create table messages(
  id uuid primary key default gen_random_uuid(),
  chat_id uuid not null references chats on delete cascade,
  sender_id uuid not null references profiles,
  body text not null check(length(body)<=4000),
  reply_to uuid references messages(id) on delete set null,
  deleted bool not null default false, created_at timestamptz default now());
create index on messages(chat_id,created_at);

create function is_admin() returns bool language sql security definer stable set search_path=public
as $$ select coalesce((select is_admin from profiles where id=auth.uid()),false) $$;
create function is_banned() returns bool language sql security definer stable set search_path=public
as $$ select coalesce((select banned from profiles where id=auth.uid()),false) $$;
create function is_member(c uuid) returns bool language sql security definer stable set search_path=public
as $$ select exists(select 1 from chat_members where chat_id=c and user_id=auth.uid()) $$;

-- أول حساب يسجّل يصبح أدمن تلقائياً
create function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin
  insert into profiles(id,email,name,is_admin)
  values(new.id,new.email,coalesce(new.raw_user_meta_data->>'name',''),not exists(select 1 from profiles));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function handle_new_user();

create function create_chat(p_title text,p_group bool,p_members uuid[]) returns uuid
language plpgsql security definer set search_path=public as $$
declare cid uuid;
begin
  if is_banned() then raise exception 'banned'; end if;
  if not p_group then
    select m1.chat_id into cid from chat_members m1
      join chat_members m2 on m1.chat_id=m2.chat_id join chats c on c.id=m1.chat_id
      where not c.is_group and m1.user_id=auth.uid() and m2.user_id=p_members[1] limit 1;
    if cid is not null then return cid; end if;
  end if;
  insert into chats(is_group,title,created_by) values(p_group,p_title,auth.uid()) returning id into cid;
  insert into chat_members(chat_id,user_id) select cid,auth.uid()
    union select cid,x from unnest(p_members) x;
  return cid;
end $$;

create function admin_users() returns table(id uuid,name text,email text,created_at timestamptz,
  last_seen timestamptz,banned bool,is_admin bool,msg_count bigint)
language plpgsql security definer set search_path=public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  return query select p.id,p.name,p.email,p.created_at,p.last_seen,p.banned,p.is_admin,
    (select count(*) from messages m where m.sender_id=p.id) from profiles p order by p.created_at;
end $$;

alter table profiles enable row level security;
alter table chats enable row level security;
alter table chat_members enable row level security;
alter table messages enable row level security;

create policy p_sel on profiles for select using (auth.uid() is not null);
create policy p_upd on profiles for update using (id=auth.uid())
  with check (id=auth.uid() and is_admin=public.is_admin() and banned=public.is_banned());
create policy p_adm on profiles for update using (public.is_admin()) with check (true);
create policy c_sel on chats for select using (is_member(id));
create policy cm_sel on chat_members for select using (is_member(chat_id));
create policy cm_upd on chat_members for update using (user_id=auth.uid()) with check (user_id=auth.uid());
create policy m_sel on messages for select using (is_member(chat_id));
create policy m_ins on messages for insert
  with check (sender_id=auth.uid() and is_member(chat_id) and not is_banned());
create policy m_upd on messages for update using (sender_id=auth.uid()) with check (sender_id=auth.uid());

alter publication supabase_realtime add table messages, chat_members;