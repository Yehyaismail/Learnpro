-- شغّله مرة واحدة في Supabase > SQL Editor (بعد schema.sql)
-- إذا فشل أي سطر فكل شيء يتراجع تلقائياً ولا يبقى تعديل ناقص
begin;
grant select,insert,update,delete on profiles,chats,chat_members,messages to authenticated;
create table profile_private(id uuid primary key references profiles on delete cascade, email text);
insert into profile_private select id,email from profiles;
alter table profile_private enable row level security;
revoke all on profile_private from anon, authenticated;
alter table profiles drop column email;

-- كل مستخدم جديد تُنشأ له محادثة تلقائية مع الأدمن
create or replace function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare aid uuid; cid uuid; first_user bool;
begin
  first_user := not exists(select 1 from profiles);
  insert into profiles(id,name,is_admin)
  values(new.id,coalesce(new.raw_user_meta_data->>'name',''),first_user);
  insert into profile_private(id,email) values(new.id,new.email);
  if not first_user then
    select id into aid from profiles where is_admin order by created_at limit 1;
    if aid is not null then
      insert into chats(is_group,created_by) values(false,aid) returning id into cid;
      insert into chat_members(chat_id,user_id) values(cid,aid),(cid,new.id);
    end if;
  end if;
  return new;
end $$;

-- إنشاء محادثة جديدة أو مجموعة: للأدمن فقط
create or replace function create_chat(p_title text,p_group bool,p_members uuid[]) returns uuid
language plpgsql security definer set search_path=public as $$
declare cid uuid;
begin
  if not is_admin() then raise exception 'admin only'; end if;
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

drop function admin_users();
create function admin_users() returns table(id uuid,name text,email text,created_at timestamptz,
  last_seen timestamptz,banned bool,is_admin bool,msg_count bigint)
language plpgsql security definer set search_path=public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  return query select p.id,p.name,pp.email,p.created_at,p.last_seen,p.banned,p.is_admin,
    (select count(*) from messages m where m.sender_id=p.id)
    from profiles p join profile_private pp on pp.id=p.id order by p.created_at;
end $$;

-- المستخدم يرى نفسه ومن يشاركه محادثة، والأدمن يرى الجميع
create function shares_chat(u uuid) returns bool language sql security definer stable set search_path=public
as $$ select exists(select 1 from chat_members a join chat_members b on a.chat_id=b.chat_id
  where a.user_id=auth.uid() and b.user_id=u) $$;
drop policy p_sel on profiles;
create policy p_sel on profiles for select using (id=auth.uid() or is_admin() or shares_chat(id));

-- للحسابات المسجلة سابقاً: أنشئ لكل واحد محادثة مع الأدمن إن لم تكن موجودة
do $$
declare aid uuid; u record; cid uuid;
begin
  select id into aid from profiles where is_admin order by created_at limit 1;
  if aid is null then return; end if;
  for u in select p.id from profiles p where p.id<>aid and not exists(
      select 1 from chat_members a join chat_members b on a.chat_id=b.chat_id join chats c on c.id=a.chat_id
      where not c.is_group and a.user_id=aid and b.user_id=p.id) loop
    insert into chats(is_group,created_by) values(false,aid) returning id into cid;
    insert into chat_members(chat_id,user_id) values(cid,aid),(cid,u.id);
  end loop;
end $$;
commit;