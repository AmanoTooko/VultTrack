using System.Text.Json;
using DuckDB.NET.Data;

const string usage = "VulTrack.AiRecovery --db <duckdb> --input <csv.gz> --expected <rows>";
var arguments = ParseArguments(args);
var databasePath = RequiredPath(arguments, "--db");
var inputPath = RequiredPath(arguments, "--input");
if (!arguments.TryGetValue("--expected", out var expectedRaw)
    || !long.TryParse(expectedRaw, out var expectedRows)
    || expectedRows <= 0)
    throw new ArgumentException($"--expected must be a positive integer. {usage}");

ValidateRegularFile(databasePath, "DuckDB database");
ValidateRegularFile(inputPath, "AI backup");
if (!inputPath.EndsWith(".csv.gz", StringComparison.OrdinalIgnoreCase)
    && !inputPath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
    throw new InvalidDataException("AI backup must end in .csv or .csv.gz.");

using var connection = new DuckDBConnection($"Data Source={databasePath}");
connection.Open();
Execute(connection, "set memory_limit = '2GB'");
Execute(connection, "set threads = 2");

var explicitIndexesBefore = ScalarLong(connection, "select count(*) from duckdb_indexes()");
if (explicitIndexesBefore != 0)
    throw new InvalidDataException($"Recovery requires zero explicit DuckDB indexes; found {explicitIndexesBefore}.");

var targetColumns = ReadStrings(connection, """
    select column_name
    from information_schema.columns
    where table_schema = 'main' and table_name = 'ai_vulnerability_analyses'
    order by ordinal_position
    """);
var expectedTargetColumns = new[]
{
    "vulnerability_id", "primary_identifier", "model", "prompt_version", "evidence_hash",
    "analysis_json", "input_json", "input_chars", "output_chars", "source_url", "created_at",
    "updated_at", "usage_json", "prompt_tokens", "completion_tokens", "total_tokens", "cached_tokens"
};
RequireColumns(targetColumns, expectedTargetColumns, "target table");

Execute(connection, "begin transaction");
try
{
    Execute(connection, $"""
        create temp table ai_input as
        select * from read_csv_auto({SqlLiteral(inputPath)}, header=true, all_varchar=true)
        """);
    var inputColumns = ReadStrings(connection, "select name from pragma_table_info('ai_input') order by cid");
    RequireColumns(inputColumns, expectedTargetColumns.Skip(1).ToArray(), "AI backup");

    var inputRows = ScalarLong(connection, "select count(*) from ai_input");
    var blankIdentifiers = ScalarLong(connection, """
        select count(*) from ai_input
        where primary_identifier is null or trim(primary_identifier) = ''
        """);
    var duplicateIdentifierRows = ScalarLong(connection, """
        select count(*) - count(distinct upper(trim(primary_identifier))) from ai_input
        """);
    if (inputRows != expectedRows || blankIdentifiers != 0)
        throw new InvalidDataException(
            $"AI input gate failed: expected={expectedRows}, input={inputRows}, blankIdentifiers={blankIdentifiers}.");

    var invalidJson = ScalarLong(connection, """
        select count(*) from ai_input
        where analysis_json is null or trim(analysis_json) = '' or not json_valid(analysis_json)
        """);
    var invalidNumbers = ScalarLong(connection, """
        select count(*) from ai_input
        where (nullif(trim(input_chars), '') is not null and try_cast(input_chars as integer) is null)
           or (nullif(trim(output_chars), '') is not null and try_cast(output_chars as integer) is null)
           or (nullif(trim(prompt_tokens), '') is not null and try_cast(prompt_tokens as bigint) is null)
           or (nullif(trim(completion_tokens), '') is not null and try_cast(completion_tokens as bigint) is null)
           or (nullif(trim(total_tokens), '') is not null and try_cast(total_tokens as bigint) is null)
           or (nullif(trim(cached_tokens), '') is not null and try_cast(cached_tokens as bigint) is null)
        """);
    if (invalidJson != 0 || invalidNumbers != 0)
        throw new InvalidDataException(
            $"AI input content gate failed: invalidJson={invalidJson}, invalidNumbers={invalidNumbers}.");

    Execute(connection, """
        create temp table ai_vulnerability_map as
        select upper(trim(primary_identifier)) as primary_identifier,
               min(id) as vulnerability_id,
               count(*) as catalog_rows,
               count(distinct id) as distinct_ids
        from vulnerabilities
        where nullif(trim(primary_identifier), '') is not null
        group by upper(trim(primary_identifier))
        """);
    var ambiguousCatalogIdentifiers = ScalarLong(connection, """
        select count(*) from ai_vulnerability_map
        where catalog_rows <> 1 or distinct_ids <> 1
        """);
    if (ambiguousCatalogIdentifiers != 0)
        throw new InvalidDataException(
            $"Catalog contains {ambiguousCatalogIdentifiers} ambiguous primary identifiers; refusing a join that could lose identity.");

    Execute(connection, """
        create temp table ai_stage as
        select
          coalesce(m.vulnerability_id, md5('ai-unmatched:' || upper(trim(i.primary_identifier)))) as vulnerability_id,
          upper(trim(i.primary_identifier)) as primary_identifier,
          i.model,
          i.prompt_version,
          i.evidence_hash,
          i.analysis_json,
          i.input_json,
          try_cast(i.input_chars as integer) as input_chars,
          try_cast(i.output_chars as integer) as output_chars,
          i.source_url,
          i.created_at,
          i.updated_at,
          i.usage_json,
          try_cast(i.prompt_tokens as bigint) as prompt_tokens,
          try_cast(i.completion_tokens as bigint) as completion_tokens,
          try_cast(i.total_tokens as bigint) as total_tokens,
          try_cast(i.cached_tokens as bigint) as cached_tokens,
          m.vulnerability_id is not null as matched
        from ai_input i
        left join ai_vulnerability_map m
          on m.primary_identifier = upper(trim(i.primary_identifier))
        """);
    var stagedRows = ScalarLong(connection, "select count(*) from ai_stage");
    var matchedRows = ScalarLong(connection, "select count(*) from ai_stage where matched");
    var unmatchedRows = stagedRows - matchedRows;
    if (stagedRows != expectedRows)
        throw new InvalidDataException($"AI staging row mismatch: expected={expectedRows}, staged={stagedRows}.");

    var previousRows = ScalarLong(connection, "select count(*) from ai_vulnerability_analyses");
    Execute(connection, "delete from ai_vulnerability_analyses");
    Execute(connection, """
        insert into ai_vulnerability_analyses (
          vulnerability_id, primary_identifier, model, prompt_version, evidence_hash,
          analysis_json, input_json, input_chars, output_chars, source_url, created_at,
          updated_at, usage_json, prompt_tokens, completion_tokens, total_tokens, cached_tokens
        )
        select vulnerability_id, primary_identifier, model, prompt_version, evidence_hash,
               analysis_json, input_json, input_chars, output_chars, source_url, created_at,
               updated_at, usage_json, prompt_tokens, completion_tokens, total_tokens, cached_tokens
        from ai_stage
        """);
    var storedRows = ScalarLong(connection, "select count(*) from ai_vulnerability_analyses");
    var rowDifferences = ScalarLong(connection, """
        select count(*) from (
          (select vulnerability_id, primary_identifier, model, prompt_version, evidence_hash,
                  analysis_json, input_json, input_chars, output_chars, source_url, created_at,
                  updated_at, usage_json, prompt_tokens, completion_tokens, total_tokens, cached_tokens
           from ai_stage
           except all
           select * from ai_vulnerability_analyses)
          union all
          (select * from ai_vulnerability_analyses
           except all
           select vulnerability_id, primary_identifier, model, prompt_version, evidence_hash,
                  analysis_json, input_json, input_chars, output_chars, source_url, created_at,
                  updated_at, usage_json, prompt_tokens, completion_tokens, total_tokens, cached_tokens
           from ai_stage)
        ) differences
        """);
    var explicitIndexesAfter = ScalarLong(connection, "select count(*) from duckdb_indexes()");
    if (storedRows != expectedRows || rowDifferences != 0 || explicitIndexesAfter != 0)
        throw new InvalidDataException(
            $"AI stored gate failed: stored={storedRows}, differences={rowDifferences}, indexes={explicitIndexesAfter}.");

    var sampleIdentifiers = ReadStrings(connection, """
        select primary_identifier from ai_stage
        order by md5(primary_identifier || coalesce(model, '') || coalesce(prompt_version, ''))
        limit 32
        """);
    Execute(connection, "commit");
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        ok = true,
        expectedRows,
        inputRows,
        stagedRows,
        storedRows,
        previousRows,
        matchedRows,
        unmatchedRows,
        duplicateIdentifierRows,
        explicitIndexesBefore,
        explicitIndexesAfter,
        sampleIdentifiers
    }));
}
catch
{
    try { Execute(connection, "rollback"); } catch { }
    throw;
}

Dictionary<string, string> ParseArguments(string[] values)
{
    if (values.Length == 0 || values.Length % 2 != 0) throw new ArgumentException(usage);
    var parsed = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var index = 0; index < values.Length; index += 2)
    {
        if (!values[index].StartsWith("--", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(values[index + 1]))
            throw new ArgumentException(usage);
        if (!parsed.TryAdd(values[index], values[index + 1]))
            throw new ArgumentException($"Duplicate argument: {values[index]}.");
    }
    return parsed;
}

string RequiredPath(IReadOnlyDictionary<string, string> arguments, string name)
{
    if (!arguments.TryGetValue(name, out var value)) throw new ArgumentException($"Missing {name}. {usage}");
    return Path.GetFullPath(value);
}

static void ValidateRegularFile(string path, string label)
{
    var file = new FileInfo(path);
    if (!file.Exists) throw new FileNotFoundException($"{label} does not exist.", path);
    if (file.LinkTarget is not null) throw new InvalidDataException($"{label} must not be a symbolic link.");
}

static void RequireColumns(IReadOnlyList<string> actual, IReadOnlyList<string> expected, string label)
{
    if (!actual.SequenceEqual(expected, StringComparer.Ordinal))
        throw new InvalidDataException(
            $"Unexpected {label} columns. Expected [{string.Join(',', expected)}], actual [{string.Join(',', actual)}].");
}

static string SqlLiteral(string value) => $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";

static void Execute(DuckDBConnection connection, string sql)
{
    using var command = connection.CreateCommand();
    command.CommandText = sql;
    command.ExecuteNonQuery();
}

static long ScalarLong(DuckDBConnection connection, string sql)
{
    using var command = connection.CreateCommand();
    command.CommandText = sql;
    return Convert.ToInt64(command.ExecuteScalar());
}

static string[] ReadStrings(DuckDBConnection connection, string sql)
{
    using var command = connection.CreateCommand();
    command.CommandText = sql;
    using var reader = command.ExecuteReader();
    var rows = new List<string>();
    while (reader.Read()) rows.Add(reader.GetString(0));
    return rows.ToArray();
}
