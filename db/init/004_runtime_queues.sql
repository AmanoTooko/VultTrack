create table if not exists vulnerability_detail_snapshot_queue (
  vulnerability_id uuid primary key,
  queued_at timestamptz not null default now()
);

create index if not exists ix_detail_snapshot_queue_queued_at
  on vulnerability_detail_snapshot_queue(queued_at, vulnerability_id);

create table if not exists duckdb_affected_component_queue (
  vulnerability_id uuid primary key,
  queued_at timestamptz not null default now()
);

create index if not exists ix_duckdb_affected_component_queue_queued_at
  on duckdb_affected_component_queue(queued_at, vulnerability_id);

create or replace function queue_vulnerability_detail_snapshot_id()
returns trigger
language plpgsql
as $$
declare
  target_id uuid;
begin
  if current_setting('vultrack.defer_snapshot_queue', true) = 'on' then
    return coalesce(new, old);
  end if;

  target_id := case when tg_op = 'DELETE' then old.id else new.id end;
  if target_id is not null then
    insert into vulnerability_detail_snapshot_queue(vulnerability_id, queued_at)
    values (target_id, now())
    on conflict (vulnerability_id) do update set queued_at = excluded.queued_at;
  end if;
  return coalesce(new, old);
end;
$$;

create or replace function queue_vulnerability_detail_snapshot_vulnerability_id()
returns trigger
language plpgsql
as $$
declare
  target_id uuid;
begin
  target_id := case when tg_op = 'DELETE' then old.vulnerability_id else new.vulnerability_id end;
  if target_id is not null then
    insert into vulnerability_detail_snapshot_queue(vulnerability_id, queued_at)
    values (target_id, now())
    on conflict (vulnerability_id) do update set queued_at = excluded.queued_at;
  end if;
  return coalesce(new, old);
end;
$$;

create or replace function queue_vulnerability_detail_snapshot_canonical_id()
returns trigger
language plpgsql
as $$
declare
  target_id uuid;
begin
  target_id := case when tg_op = 'DELETE' then old.canonical_vulnerability_id else new.canonical_vulnerability_id end;
  if target_id is not null then
    insert into vulnerability_detail_snapshot_queue(vulnerability_id, queued_at)
    values (target_id, now())
    on conflict (vulnerability_id) do update set queued_at = excluded.queued_at;
  end if;
  return coalesce(new, old);
end;
$$;

drop trigger if exists trg_detail_snapshot_queue on vulnerabilities;
drop trigger if exists trg_detail_snapshot_queue_vulnerabilities on vulnerabilities;
create trigger trg_detail_snapshot_queue_vulnerabilities
after insert or update or delete on vulnerabilities
for each row execute function queue_vulnerability_detail_snapshot_id();

do $$
declare
  table_name text;
begin
  foreach table_name in array array[
    'vulnerability_records',
    'vulnerability_affected_components',
    'vulnerability_affected_facts',
    'vulnerability_descriptions',
    'vulnerability_weaknesses',
    'vulnerability_exploits',
    'vulnerability_references',
    'vulnerability_severity_scores'
  ] loop
    execute format('drop trigger if exists trg_detail_snapshot_queue on %I', table_name);
    execute format('drop trigger if exists trg_detail_snapshot_queue_%s on %I', table_name, table_name);
    execute format(
      'create trigger trg_detail_snapshot_queue_%s after insert or update or delete on %I for each row execute function queue_vulnerability_detail_snapshot_vulnerability_id()',
      table_name,
      table_name
    );
  end loop;
end;
$$;

drop trigger if exists trg_detail_snapshot_queue_vulnerability_identifier_index
  on vulnerability_identifier_index;
create trigger trg_detail_snapshot_queue_vulnerability_identifier_index
after insert or update or delete on vulnerability_identifier_index
for each row execute function queue_vulnerability_detail_snapshot_canonical_id();
