using DuckDB.NET.Data;
using Microsoft.Extensions.Configuration;
using VulTrack.App;

namespace VulTrack.Tests;

[Collection("DuckDbSpoolEnvironment")]
public sealed class DuckDbAiImportTests
{
    private const string Header = "primary_identifier,model,prompt_version,evidence_hash,analysis_json,input_json,input_chars,output_chars,source_url,created_at,updated_at,usage_json,prompt_tokens,completion_tokens,total_tokens,cached_tokens\n";

    [Fact]
    public async Task Import_RejectsFilesOutsideTheImportRoot()
    {
        var root = NewRoot();
        try
        {
            var outside = Path.Combine(root, "outside.csv");
            await File.WriteAllTextAsync(outside, Header);
            using var store = CreateStore(root);

            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                store.ImportAiAnalysesAsync(outside, null, CancellationToken.None));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Import_RollsBackWhenRowsWouldBeDropped()
    {
        var root = NewRoot();
        var importRoot = Path.Combine(root, "import");
        Directory.CreateDirectory(importRoot);
        var valid = Path.Combine(importRoot, "valid.csv");
        var invalid = Path.Combine(importRoot, "invalid.csv");
        await File.WriteAllTextAsync(valid, Header + CsvRow("CVE-2026-0001"));
        await File.WriteAllTextAsync(invalid, Header + CsvRow(""));

        try
        {
            using var store = CreateStore(root);
            var imported = await store.ImportAiAnalysesAsync(valid, 1, CancellationToken.None);
            Assert.Equal(1, imported.StoredRows);

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                store.ImportAiAnalysesAsync(invalid, 1, CancellationToken.None));

            using var connection = new DuckDBConnection($"Data Source={store.DatabasePath}");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "select count(*) from ai_vulnerability_analyses";
            Assert.Equal(1L, Convert.ToInt64(command.ExecuteScalar()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Import_RejectsAnUnexpectedRowCountWithoutReplacingExistingRows()
    {
        var root = NewRoot();
        var importRoot = Path.Combine(root, "import");
        Directory.CreateDirectory(importRoot);
        var input = Path.Combine(importRoot, "analyses.csv");
        await File.WriteAllTextAsync(input, Header + CsvRow("CVE-2026-0001"));

        try
        {
            using var store = CreateStore(root);
            await store.ImportAiAnalysesAsync(input, 1, CancellationToken.None);

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                store.ImportAiAnalysesAsync(input, 2, CancellationToken.None));

            using var connection = new DuckDBConnection($"Data Source={store.DatabasePath}");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "select count(*) from ai_vulnerability_analyses";
            Assert.Equal(1L, Convert.ToInt64(command.ExecuteScalar()));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-ai-import-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static DuckDbEvidenceStore CreateStore(string root)
    {
        var configuration = new ConfigurationBuilder().Build();
        var options = new VulTrackOptions(
            root,
            Path.Combine(root, "spool"),
            new DuckDbOptions(true, Path.Combine(root, "test.duckdb"), "256MB", "1", false, 0.5),
            new SchedulerOptions(false, 21600, 0, false, 1, ""),
            new AdminOptions("admin", "test"),
            new AiOptions("", "", "test", "v1", "", "", "", false, 12000, 1400, "en-US"));
        return new DuckDbEvidenceStore(configuration, options);
    }

    private static string CsvRow(string primaryIdentifier) =>
        $"{primaryIdentifier},test-model,v1,hash,{{}},{{}},1,1,https://example.test,2026-08-15T00:00:00Z,2026-08-15T00:00:00Z,{{}},1,1,2,0\n";
}
