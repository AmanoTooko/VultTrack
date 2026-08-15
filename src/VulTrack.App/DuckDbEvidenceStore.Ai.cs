using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
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
