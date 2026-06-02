using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed class ThreatIntelRawNormalizer(IVulnerabilityCanonicalizer canonicalizer) : ISourceScopedRawNormalizer
{
    public string SourceCode => "threat-intel";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "cisa-kev",
        "first-epss"
    };

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        var processed = 0;
        var failed = 0;
        foreach (var sourceCode in SupportedSourceCodes)
        {
            var remaining = Math.Max(0, limit - processed);
            if (remaining == 0) break;
            var result = await ProcessSourcePendingAsync(connection, sourceCode, remaining, ct);
            processed += result.Processed;
            failed += result.Failed;
        }

        return new NormalizeBatchResult(SourceCode, processed, failed);
    }

    public async Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
    {
        if (string.Equals(sourceCode, "first-epss", StringComparison.OrdinalIgnoreCase))
        {
            return await ProcessEpssPendingAsync(connection, limit, ct);
        }

        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.provider, s.identifier, s.epss_score, s.epss_percentile,
                   s.observed_at, s.payload, r.source_id
            from stg_threat_intel_records s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status in ('pending', 'failed') and src.code = $1
            order by s.observed_at nulls last, s.identifier
            limit $2
            """, connection);
        select.Parameters.AddWithValue(sourceCode);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<Row>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new Row(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetDecimal(3),
                    reader.IsDBNull(4) ? null : reader.GetDecimal(4),
                    reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5),
                    reader.GetString(6),
                    reader.GetGuid(7)));
            }
        }

        var processed = 0;
        var failed = 0;
        var succeededIds = new List<Guid>();
        foreach (var row in rows)
        {
            try
            {
                var payload = JsonNode.Parse(row.Payload);
                var title = payload?["shortDescription"]?.GetValue<string>() ?? payload?["vulnerabilityName"]?.GetValue<string>() ?? row.Identifier;
                var vulnerabilityId = await canonicalizer.UpsertCanonicalAsync(
                    connection,
                    new VulnerabilityCanonicalDraft(row.Identifier, null, null, "active", null, null, [row.Identifier], row.SourceId, row.RawIndexId),
                    ct);
                await UpsertRecordAsync(connection, vulnerabilityId, row, title, ct);
                await UpdateThreatProjectionAsync(connection, vulnerabilityId, row, payload, ct);
                succeededIds.Add(row.RawIndexId);
                processed++;
            }
            catch
            {
                failed++;
            }
        }

        await MarkNormalizedBatchAsync(connection, succeededIds, ct);

        return new NormalizeBatchResult(SourceCode, processed, failed);
    }

    private static async Task<NormalizeBatchResult> ProcessEpssPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        var batchLimit = Math.Clamp(limit * 5, 1, 25_000);
        await using var cmd = new NpgsqlCommand("""
            with batch as (
              select r.id as raw_index_id,
                     t.identifier,
                     t.epss_score,
                     t.epss_percentile
              from stg_threat_intel_records t
              join source_raw_index r on r.id = t.raw_index_id
              join sources s on s.id = r.source_id
              where s.code = 'first-epss'
                and r.normalize_status in ('pending', 'failed')
              order by t.observed_at desc nulls last, t.identifier
              limit $1
            ),
            updated as (
              update vulnerabilities v
              set epss_score = batch.epss_score,
                  epss_percentile = batch.epss_percentile,
                  updated_at = now()
              from batch
              where v.primary_identifier = batch.identifier
                and (batch.epss_score is not null or batch.epss_percentile is not null)
              returning batch.raw_index_id
            ),
            marked as (
              update source_raw_index r
              set normalize_status = 'succeeded',
                  updated_at = now()
              from batch
              where r.id = batch.raw_index_id
              returning r.id
            )
            select count(*)::integer from marked
            """, connection);
        cmd.CommandTimeout = 300;
        cmd.Parameters.AddWithValue(batchLimit);
        var processed = (int)(await cmd.ExecuteScalarAsync(ct) ?? 0);
        return new NormalizeBatchResult("first-epss", processed, 0);
    }

    private static async Task UpsertRecordAsync(NpgsqlConnection connection, Guid vulnerabilityId, Row row, string title, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            insert into vulnerability_records
              (vulnerability_id, source_id, raw_index_id, source_record_id, title, description, status)
            values ($1,$2,$3,$4,$5,$5,'active')
            on conflict (source_id, source_record_id, raw_index_id) do update set
              vulnerability_id = excluded.vulnerability_id,
              updated_at = now()
            """, connection);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue(row.SourceId);
        cmd.Parameters.AddWithValue(row.RawIndexId);
        cmd.Parameters.AddWithValue($"{row.Provider}:{row.Identifier}");
        cmd.Parameters.AddWithValue(title);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task UpdateThreatProjectionAsync(NpgsqlConnection connection, Guid vulnerabilityId, Row row, JsonNode? payload, CancellationToken ct)
    {
        var dateAdded = DateOnly.TryParse(payload?["dateAdded"]?.GetValue<string>(), out var parsedDate) ? parsedDate : (DateOnly?)null;
        var ransomware = bool.TryParse(payload?["knownRansomwareCampaignUse"]?.GetValue<string>(), out var parsedBool) ? parsedBool : (bool?)null;
        await using var cmd = new NpgsqlCommand("""
            update vulnerabilities
            set epss_score = coalesce($2, epss_score),
                epss_percentile = coalesce($3, epss_percentile),
                kev_date_added = coalesce($4, kev_date_added),
                known_ransomware = coalesce($5, known_ransomware),
                updated_at = now()
            where id = $1
            """, connection);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue((object?)row.EpssScore ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.EpssPercentile ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)dateAdded ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)ransomware ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task MarkNormalizedBatchAsync(NpgsqlConnection connection, IReadOnlyList<Guid> rawIndexIds, CancellationToken ct)
    {
        if (rawIndexIds.Count == 0) return;
        await using var cmd = new NpgsqlCommand("update source_raw_index set normalize_status = 'succeeded', updated_at = now() where id = any($1)", connection);
        cmd.Parameters.AddWithValue(rawIndexIds.ToArray());
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private sealed record Row(Guid RawIndexId, string Provider, string Identifier, decimal? EpssScore, decimal? EpssPercentile, DateTimeOffset? ObservedAt, string Payload, Guid SourceId);
}
