using DuckDB.NET.Data;
using System.Collections.Concurrent;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore(IConfiguration configuration, VulTrackOptions? options = null) : IDisposable
{
    private const string CatalogSelectColumns = """
        select id, primary_identifier, title, description, status, severity_label, max_cvss_score,
               affected_component_count, affected_component_names_json, identifiers_json,
               published_at, modified_at, source_count
        """;

    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private readonly SemaphoreSlim _readPoolSlots = new(2, 2);
    private readonly ConcurrentBag<DuckDBConnection> _readPool = new();
    private bool _initialized;

    public VulTrackOptions Options { get; } = options ?? VulTrackOptions.Load(configuration);

    public string DatabasePath => Options.DuckDb.DatabasePath;

    public bool Enabled => Options.DuckDb.Enabled;

    public async Task InitializeAsync(CancellationToken ct)
    {
        if (Volatile.Read(ref _initialized)) return;
        ct.ThrowIfCancellationRequested();
        await _initializeLock.WaitAsync(ct);
        try
        {
            if (_initialized) return;
            Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
            using var connection = OpenConnection();
            // Old explicit ART indexes must be removed before any startup DML. An index left
            // by a previous build can invalidate the connection on the first UPDATE/DELETE.
            foreach (var statement in LegacyArtIndexDropStatements)
                Execute(connection, statement);
            foreach (var statement in SchemaStatements)
                Execute(connection, statement);
            Volatile.Write(ref _initialized, true);
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    public Task ResetAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        _writeLock.Wait(ct);
        try
        {
            using var connection = OpenConnection();
            foreach (var statement in LegacyArtIndexDropStatements)
                Execute(connection, statement);
            foreach (var statement in SchemaStatements)
                Execute(connection, statement);
            foreach (var table in ResetTables)
                Execute(connection, $"delete from {table}");
            return Task.CompletedTask;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static string[] JsonStringArray(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return System.Text.Json.JsonSerializer.Deserialize<string[]>(json) ?? []; }
        catch { return []; }
    }

    private static async Task<IReadOnlyList<Dictionary<string, object?>>> ReadRowsAsync(DuckDBCommand command, CancellationToken ct)
    {
        var rows = new List<Dictionary<string, object?>>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++)
                dict[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(dict);
        }
        return rows;
    }

    // Connection discipline: DuckDB is single-writer per file.
    // - Reads must rent a pooled connection via RentReadConnectionAsync.
    // - Writes (including temp-table/COPY activity) must hold _writeLock and use a dedicated OpenConnection.
    private DuckDBConnection OpenConnection()
    {
        var connection = new DuckDBConnection($"Data Source={DatabasePath}");
        connection.Open();
        var memoryLimit = Options.DuckDb.MemoryLimit;
        if (!string.IsNullOrWhiteSpace(memoryLimit))
            Execute(connection, $"set memory_limit = {SqlValue(memoryLimit)}");
        if (int.TryParse(Options.DuckDb.Threads, out var threadCount) && threadCount > 0)
            Execute(connection, $"set threads = {Math.Clamp(threadCount, 1, 32)}");
        return connection;
    }

    private async Task<ReadConnectionLease> RentReadConnectionAsync(CancellationToken ct)
    {
        await _readPoolSlots.WaitAsync(ct);
        try
        {
            if (!_readPool.TryTake(out var connection)) connection = OpenConnection();
            return new ReadConnectionLease(this, connection);
        }
        catch
        {
            _readPoolSlots.Release();
            throw;
        }
    }

    public void Dispose()
    {
        while (_readPool.TryTake(out var connection)) connection.Dispose();
        _readPoolSlots.Dispose();
        _writeLock.Dispose();
        _initializeLock.Dispose();
    }

    private sealed class ReadConnectionLease(DuckDbEvidenceStore owner, DuckDBConnection connection) : IDisposable
    {
        private DuckDBConnection? _connection = connection;

        public DuckDBConnection Connection => _connection ?? throw new ObjectDisposedException(nameof(ReadConnectionLease));

        public void Dispose()
        {
            var returned = Interlocked.Exchange(ref _connection, null);
            if (returned is null) return;
            owner._readPool.Add(returned);
            owner._readPoolSlots.Release();
        }
    }

    private async Task CopyRowsAsync(DuckDBConnection connection, string tableName, string columns, IEnumerable<string> rows, CancellationToken ct)
    {
        var tempDir = Path.Combine(Path.GetDirectoryName(DatabasePath)!, "tmp");
        Directory.CreateDirectory(tempDir);
        var tempFile = Path.Combine(tempDir, $"{tableName}-{Guid.NewGuid():N}.csv");
        var count = 0;
        try
        {
            await using (var writer = new StreamWriter(tempFile))
            {
                foreach (var row in rows)
                {
                    ct.ThrowIfCancellationRequested();
                    await writer.WriteLineAsync(row);
                    count++;
                }
            }

            if (count == 0) return;
            Execute(connection, $"""
                copy {tableName} ({columns})
                from {SqlValue(tempFile)}
                (
                  auto_detect false,
                  header false,
                  delim ',',
                  quote '"',
                  escape '"',
                  new_line '\n',
                  null '\N',
                  strict_mode true,
                  max_line_size 8388608
                )
                """);
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }

    private static long Count(DuckDBConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"select count(*) from {tableName}";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private static void Execute(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static string SqlValue(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? "null"
            : $"'{value.Replace("'", "''")}'";

    private static string SqlEcosystemFilter(string column, string? ecosystem)
    {
        if (string.IsNullOrWhiteSpace(ecosystem)) return "true";

        var normalized = ecosystem.ToLowerInvariant();
        if (normalized is "cargo" or "crates.io")
            return $"{column} in ('cargo', 'crates.io')";

        return $"({column} = {SqlValue(normalized)} or " +
               $"(instr({SqlValue(normalized)}, ':') = 0 and {column} like {SqlValue(normalized + ":%")}))";
    }

    private static string SourceRecordIdentity(string sourceCode, string sourceRecordId) =>
        $"{sourceCode}\u001f{sourceRecordId}";

    private static string KeyList(IEnumerable<string> keys) =>
        string.Join(", ", keys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(key => $"'{NormalizeKey(key).Replace("'", "''")}'")
            .Distinct(StringComparer.Ordinal));

    private static string TextList(IEnumerable<string?> values)
    {
        var list = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => $"'{value!.Replace("'", "''")}'")
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return list.Length == 0 ? "null" : string.Join(", ", list);
    }

    private static string TextEqualsOrIn(string column, IEnumerable<string?> values)
    {
        var list = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => SqlValue(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return list.Length switch
        {
            0 => "false",
            1 => $"{column} = {list[0]}",
            _ => $"{column} in ({string.Join(", ", list)})"
        };
    }

    private static string NonEmptyListPredicate(string list) => list == "null" ? "false" : "true";

    private static string NormalizeKey(string key) => Identifier.Normalize(key);

    private static string CsvRow(params string?[] values) =>
        string.Join(",", values.Select(CsvValue));

    private static string CsvValue(string? value)
    {
        if (value is null) return "\\N";
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static string? NullableString(System.Data.Common.DbDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static string DeterministicRowId(Guid first, Guid second)
    {
        var bytes = System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{first:D}|{second:D}"));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string? PurlWithoutVersion(string? purl) =>
        PurlIdentity.WithoutVersionAndQualifiers(purl);

    private static string[] SplitSummary(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
}
