using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
    public async Task<DuckDbAiImportResult> ImportAiAnalysesAsync(string path, long? expectedRows, CancellationToken ct)
    {
        if (expectedRows is <= 0)
            throw new ArgumentOutOfRangeException(nameof(expectedRows), "Expected rows must be positive when supplied.");
        var importRoot = Path.GetFullPath(Path.Combine(Options.RepoRoot ?? Directory.GetCurrentDirectory(), "import"));
        var fullPath = Path.GetFullPath(path);
        if (!string.Equals(Path.GetDirectoryName(fullPath), importRoot, StringComparison.Ordinal))
            throw new UnauthorizedAccessException($"AI analysis imports must be regular files directly under {importRoot}.");
        var importFile = new FileInfo(fullPath);
        if (!importFile.Exists) throw new FileNotFoundException("AI analysis import file not found.", fullPath);
        if (importFile.LinkTarget is not null)
            throw new UnauthorizedAccessException("Symbolic AI analysis import files are not allowed.");
        if (!fullPath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase)
            && !fullPath.EndsWith(".csv.gz", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("AI analysis import file must end in .csv or .csv.gz.");
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                Execute(connection, "drop table if exists temp_ai_import");
                Execute(connection, $"create temp table temp_ai_import as select * from read_csv_auto({SqlValue(fullPath)}, header=true, all_varchar=true)");
                var inputRows = Count(connection, "temp_ai_import");
                if (inputRows == 0)
                    throw new InvalidDataException("AI analysis import contains no data rows.");
                if (expectedRows is not null && inputRows != expectedRows.Value)
                    throw new InvalidDataException($"AI analysis import row count mismatch: expected={expectedRows.Value}, actual={inputRows}.");
                using var matchedCommand = connection.CreateCommand();
                matchedCommand.CommandText = """
                    select count(*)
                    from temp_ai_import i
                    join vulnerabilities v on v.primary_identifier = upper(trim(i.primary_identifier))
                    """;
                var matchedRows = Convert.ToInt64(matchedCommand.ExecuteScalar());
                Execute(connection, "delete from ai_vulnerability_analyses");
                Execute(connection, """
                    insert into ai_vulnerability_analyses
                    select
                      coalesce(v.id, md5('ai-unmatched:' || upper(trim(i.primary_identifier)))) as vulnerability_id,
                      upper(trim(i.primary_identifier)) as primary_identifier,
                      i.model,
                      i.prompt_version,
                      i.evidence_hash,
                      i.analysis_json,
                      i.input_json,
                      try_cast(i.input_chars as integer),
                      try_cast(i.output_chars as integer),
                      i.source_url,
                      i.created_at,
                      i.updated_at,
                      i.usage_json,
                      try_cast(i.prompt_tokens as bigint),
                      try_cast(i.completion_tokens as bigint),
                      try_cast(i.total_tokens as bigint),
                      try_cast(i.cached_tokens as bigint)
                    from temp_ai_import i
                    left join vulnerabilities v on v.primary_identifier = upper(trim(i.primary_identifier))
                    where nullif(trim(i.primary_identifier), '') is not null
                    """);
                var storedRows = Count(connection, "ai_vulnerability_analyses");
                if (storedRows != inputRows)
                    throw new InvalidDataException($"AI analysis import did not preserve every row: input={inputRows}, stored={storedRows}.");
                Execute(connection, "drop table temp_ai_import");
                Execute(connection, "commit");
                return new DuckDbAiImportResult(inputRows, matchedRows, inputRows - matchedRows, storedRows);
            }
            catch
            {
                Execute(connection, "rollback");
                throw;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<object?> GetAiAnalysisAsync(Guid id, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = """
            select vulnerability_id, model, prompt_version, evidence_hash, analysis_json,
                   input_chars, output_chars, source_url, updated_at,
                   prompt_tokens, completion_tokens, total_tokens, cached_tokens
            from ai_vulnerability_analyses
            where vulnerability_id = $1
            order by updated_at desc nulls last
            limit 1
            """;
        command.Parameters.Add(new DuckDBParameter(id.ToString("D")));
        using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        var analysis = reader.IsDBNull(4) ? null : System.Text.Json.Nodes.JsonNode.Parse(reader.GetString(4));
        return new
        {
            status = "analyzed",
            analyzed = true,
            vulnerabilityId = id,
            model = reader.GetString(1),
            promptVersion = reader.GetString(2),
            evidenceHash = reader.GetString(3),
            analysis,
            summary = analysis,
            cached = true,
            configured = false,
            inputChars = reader.IsDBNull(5) ? 0 : reader.GetInt32(5),
            outputChars = reader.IsDBNull(6) ? 0 : reader.GetInt32(6),
            sourceUrl = reader.IsDBNull(7) ? null : reader.GetString(7),
            updatedAt = reader.IsDBNull(8) ? null : reader.GetString(8),
            usage = new
            {
                promptTokens = reader.IsDBNull(9) ? 0 : reader.GetInt64(9),
                completionTokens = reader.IsDBNull(10) ? 0 : reader.GetInt64(10),
                totalTokens = reader.IsDBNull(11) ? 0 : reader.GetInt64(11),
                cachedTokens = reader.IsDBNull(12) ? 0 : reader.GetInt64(12)
            }
        };
    }
}
