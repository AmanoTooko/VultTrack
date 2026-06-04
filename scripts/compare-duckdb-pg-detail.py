#!/usr/bin/env python3
import argparse
import json
import os
import time
import urllib.parse
import urllib.request

try:
    import duckdb
    import psycopg
except ModuleNotFoundError as exc:
    raise SystemExit(
        f"Missing Python dependency {exc.name!r}. Install with: "
        "python3 -m pip install --user duckdb psycopg[binary]"
    ) from exc


DEFAULT_SAMPLES = [
    "CVE-2021-44228",
    "CVE-2023-4863",
    "CVE-2017-5753",
    "CGA-V7V4-9R6P-X7FC",
]


def main():
    parser = argparse.ArgumentParser(
        description="Compare PostgreSQL and DuckDB vulnerability detail JSON aggregation."
    )
    parser.add_argument(
        "--samples",
        default=",".join(DEFAULT_SAMPLES),
        help="Comma-separated vulnerability identifiers to compare.",
    )
    parser.add_argument("--limit", type=int, default=250)
    parser.add_argument(
        "--database-url",
        default=os.environ.get(
            "DATABASE_URL", "postgres://vultrack:vultrack@127.0.0.1:5432/vultrack"
        ),
    )
    parser.add_argument(
        "--duckdb-path",
        default=os.environ.get(
            "VULTRACK_DUCKDB_PATH", "data/duckdb/vultrack-evidence.duckdb"
        ),
    )
    parser.add_argument(
        "--api-base-url",
        default=os.environ.get("API_BASE_URL", "http://localhost:5099"),
    )
    parser.add_argument("--skip-api", action="store_true")
    args = parser.parse_args()

    samples = [item.strip() for item in args.samples.split(",") if item.strip()]
    started = time.perf_counter()
    with psycopg.connect(args.database_url) as pg_conn:
        with duckdb.connect(args.duckdb_path, read_only=True) as duck_conn:
            results = [
                compare_sample(pg_conn, duck_conn, args.api_base_url, sample, args.limit, args.skip_api)
                for sample in samples
            ]

    print(json.dumps({
        "generatedAt": utc_now(),
        "elapsedMs": round((time.perf_counter() - started) * 1000),
        "limit": args.limit,
        "duckdbPath": os.path.abspath(args.duckdb_path),
        "samples": results,
        "summary": summarize(results),
    }, ensure_ascii=False, indent=2))


def compare_sample(pg_conn, duck_conn, api_base_url, key, limit, skip_api):
    resolved = resolve_pg_vulnerability(pg_conn, key)
    pg_affected = pg_json_aggregate(pg_conn, "affected", resolved, limit) if resolved else empty_metric()
    pg_references = pg_json_aggregate(pg_conn, "references", resolved, limit) if resolved else empty_metric()
    pg_severities = pg_json_aggregate(pg_conn, "severities", resolved, limit) if resolved else empty_metric()

    duck_affected = duck_json_aggregate(duck_conn, "affected", key, limit)
    duck_references = duck_json_aggregate(duck_conn, "references", key, limit)
    duck_severities = duck_json_aggregate(duck_conn, "severities", key, limit)

    result = {
        "requestedKey": key,
        "pgVulnerability": resolved,
        "affected": compare_rows(pg_affected, duck_affected, affected_fingerprint),
        "references": compare_rows(pg_references, duck_references, reference_fingerprint),
        "severities": compare_rows(pg_severities, duck_severities, severity_fingerprint),
    }
    if not skip_api and resolved:
        result["api"] = {
            "pgsql": api_detail(api_base_url, resolved["id"], "pgsql"),
            "duckdb": api_detail(api_base_url, resolved["id"], "duckdb"),
        }
    return result


def resolve_pg_vulnerability(conn, key):
    rows = conn.execute(
        """
        select id::text, primary_identifier
        from vulnerabilities
        where upper(primary_identifier) = upper(%s)
           or exists (
             select 1
             from unnest(coalesce(identifiers, '{}'::text[]) || coalesce(aliases, '{}'::text[])) item
             where upper(item) = upper(%s)
           )
        order by case when upper(primary_identifier) = upper(%s) then 0 else 1 end,
                 coalesce(source_count, 0) desc,
                 updated_at desc
        limit 1
        """,
        (key, key, key),
    ).fetchall()
    if not rows:
        return None
    return {"id": rows[0][0], "primaryIdentifier": rows[0][1]}


def pg_json_aggregate(conn, kind, resolved, limit):
    started = time.perf_counter()
    row = conn.execute(pg_sql(kind), (resolved["id"], limit)).fetchone()
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    return {
        "elapsedMs": elapsed,
        "rawRows": int(row[0]),
        "jsonRows": json.loads(row[1] or "[]"),
        "sourceCounts": row[2] or {},
    }


def duck_json_aggregate(conn, kind, key, limit):
    started = time.perf_counter()
    row = conn.execute(duck_sql(kind), [key, limit]).fetchone()
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    return {
        "elapsedMs": elapsed,
        "rawRows": int(row[0] or 0),
        "jsonRows": json.loads(row[1] or "[]"),
        "sourceCounts": json.loads(row[2] or "{}"),
    }


def compare_rows(pg_metric, duck_metric, fingerprint):
    pg_set = {fingerprint(row) for row in pg_metric["jsonRows"]}
    duck_set = {fingerprint(row) for row in duck_metric["jsonRows"]}
    intersection = pg_set & duck_set
    union = pg_set | duck_set
    return {
        "pg": metric_summary(pg_metric),
        "duckdb": metric_summary(duck_metric),
        "intersectionRows": len(intersection),
        "onlyPgRows": len(pg_set - duck_set),
        "onlyDuckDbRows": len(duck_set - pg_set),
        "jaccard": round(len(intersection) / len(union), 4) if union else 1.0,
        "sampleOnlyPg": sorted(pg_set - duck_set)[:5],
        "sampleOnlyDuckDb": sorted(duck_set - pg_set)[:5],
    }


def metric_summary(metric):
    rows = metric["jsonRows"]
    return {
        "elapsedMs": metric["elapsedMs"],
        "rawRows": metric["rawRows"],
        "jsonRows": len(rows),
        "sourceCounts": metric["sourceCounts"],
    }


def empty_metric():
    return {"elapsedMs": 0, "rawRows": 0, "jsonRows": [], "sourceCounts": {}}


def pg_sql(kind):
    if kind == "affected":
        return """
        with raw as (
          select s.code source_code, f.fact_type, f.ecosystem, f.package_name, f.purl,
                 f.cpe23_uri, f.version_range_raw, f.range_type, f.vulnerable
          from vulnerability_affected_facts f
          left join sources s on s.id = f.source_id
          where f.vulnerability_id = %s
        ), limited as (
          select distinct *
          from raw
          order by source_code nulls last, package_name nulls last, purl nulls last,
                   cpe23_uri nulls last, version_range_raw nulls last
          limit %s
        )
        select (select count(*) from raw)::bigint,
               coalesce(jsonb_agg(to_jsonb(limited) order by source_code, package_name, purl, cpe23_uri, version_range_raw)::text, '[]'),
               coalesce((select jsonb_object_agg(source_code, rows)::jsonb from (
                 select coalesce(source_code, 'unknown') source_code, count(*) rows
                 from raw group by coalesce(source_code, 'unknown')
               ) source_rows), '{}'::jsonb)
        from limited
        """
    if kind == "references":
        return """
        with raw as (
          select s.code source_code, r.url, r.ref_type
          from vulnerability_references r
          left join sources s on s.id = r.source_id
          where r.vulnerability_id = %s
        ), limited as (
          select distinct *
          from raw
          order by source_code nulls last, url
          limit %s
        )
        select (select count(*) from raw)::bigint,
               coalesce(jsonb_agg(to_jsonb(limited) order by source_code, url)::text, '[]'),
               coalesce((select jsonb_object_agg(source_code, rows)::jsonb from (
                 select coalesce(source_code, 'unknown') source_code, count(*) rows
                 from raw group by coalesce(source_code, 'unknown')
               ) source_rows), '{}'::jsonb)
        from limited
        """
    return """
    with raw as (
      select s.code source_code, scoring_system, scoring_version, score_type,
             vector_string, score, severity_label
      from vulnerability_severity_scores vss
      left join sources s on s.id = vss.source_id
      where vss.vulnerability_id = %s
    ), limited as (
      select distinct *
      from raw
      order by score desc nulls last, source_code nulls last
      limit %s
    )
    select (select count(*) from raw)::bigint,
           coalesce(jsonb_agg(to_jsonb(limited) order by score desc nulls last, source_code)::text, '[]'),
           coalesce((select jsonb_object_agg(source_code, rows)::jsonb from (
             select coalesce(source_code, 'unknown') source_code, count(*) rows
             from raw group by coalesce(source_code, 'unknown')
           ) source_rows), '{}'::jsonb)
    from limited
    """


def duck_sql(kind):
    if kind == "affected":
        return """
        with raw as (
          select source_code, fact_type, ecosystem, package_name, purl, cpe23_uri,
                 version_range_raw, range_type, vulnerable
          from affected_facts
          where upper(vulnerability_key) = upper(?)
        ), limited as (
          select distinct *
          from raw
          order by source_code nulls last, package_name nulls last, purl nulls last,
                   cpe23_uri nulls last, version_range_raw nulls last
          limit ?
        )
        select (select count(*) from raw),
               coalesce(to_json(list({
                 source_code: source_code,
                 fact_type: fact_type,
                 ecosystem: ecosystem,
                 package_name: package_name,
                 purl: purl,
                 cpe23_uri: cpe23_uri,
                 version_range_raw: version_range_raw,
                 range_type: range_type,
                 vulnerable: vulnerable
               })), '[]'),
               coalesce((select to_json(map(list(coalesce(source_code, 'unknown')), list(row_count))) from (
                 select source_code, count(*) row_count from raw group by source_code
               ) source_rows), '{}')
        from limited
        """
    if kind == "references":
        return """
        with raw as (
          select source_code, url, ref_type
          from evidence_references
          where upper(vulnerability_key) = upper(?)
        ), limited as (
          select distinct *
          from raw
          order by source_code nulls last, url
          limit ?
        )
        select (select count(*) from raw),
               coalesce(to_json(list({
                 source_code: source_code,
                 url: url,
                 ref_type: ref_type
               })), '[]'),
               coalesce((select to_json(map(list(coalesce(source_code, 'unknown')), list(row_count))) from (
                 select source_code, count(*) row_count from raw group by source_code
               ) source_rows), '{}')
        from limited
        """
    return """
    with raw as (
      select source_code, scoring_system, scoring_version, score_type,
             vector_string, score, severity_label
      from severity_scores
      where upper(vulnerability_key) = upper(?)
    ), limited as (
      select distinct *
      from raw
      order by score desc nulls last, source_code nulls last
      limit ?
    )
    select (select count(*) from raw),
           coalesce(to_json(list({
             source_code: source_code,
             scoring_system: scoring_system,
             scoring_version: scoring_version,
             score_type: score_type,
             vector_string: vector_string,
             score: score,
             severity_label: severity_label
           })), '[]'),
           coalesce((select to_json(map(list(coalesce(source_code, 'unknown')), list(row_count))) from (
             select source_code, count(*) row_count from raw group by source_code
           ) source_rows), '{}')
    from limited
    """


def affected_fingerprint(row):
    return "|".join(normalize(row.get(key)) for key in [
        "source_code",
        "fact_type",
        "ecosystem",
        "package_name",
        "purl",
        "cpe23_uri",
        "version_range_raw",
        "range_type",
        "vulnerable",
    ])


def reference_fingerprint(row):
    return "|".join(normalize(row.get(key)) for key in ["source_code", "url", "ref_type"])


def severity_fingerprint(row):
    return "|".join(normalize(row.get(key)) for key in [
        "source_code",
        "scoring_system",
        "scoring_version",
        "score_type",
        "vector_string",
        "score",
        "severity_label",
    ])


def normalize(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip().lower()


def api_detail(api_base_url, vulnerability_id, source):
    url = urllib.parse.urljoin(api_base_url, "/api/v1/vulnerability.detail")
    query = urllib.parse.urlencode({"id": vulnerability_id, "source": source})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(f"{url}?{query}", timeout=60) as response:
            body = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    data = body.get("data") or {}
    return {
        "ok": bool(body.get("ok")),
        "elapsedMs": elapsed,
        "affectedExpressions": len(data.get("affectedExpressions") or []),
        "references": len(data.get("references") or []),
        "severities": len(data.get("severities") or []),
    }


def summarize(results):
    sections = ["affected", "references", "severities"]
    summary = {}
    for section in sections:
        comparable = [item[section] for item in results]
        summary[section] = {
            "avgPgElapsedMs": average(x["pg"]["elapsedMs"] for x in comparable),
            "avgDuckDbElapsedMs": average(x["duckdb"]["elapsedMs"] for x in comparable),
            "avgJaccard": average(x["jaccard"] for x in comparable),
            "zeroDuckDbSamples": [
                item["requestedKey"]
                for item in results
                if item[section]["duckdb"]["rawRows"] == 0
            ],
        }
    return summary


def average(values):
    materialized = list(values)
    return round(sum(materialized) / len(materialized), 3) if materialized else 0


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


if __name__ == "__main__":
    main()
