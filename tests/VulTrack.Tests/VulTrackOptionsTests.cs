using Microsoft.Extensions.Configuration;
using VulTrack.App;

namespace VulTrack.Tests;

[Collection("DuckDbSpoolEnvironment")]
public sealed class VulTrackOptionsTests
{
    [Fact]
    public void Load_UsesSafeDuckDbDefaultsWhenValuesAreBlank()
    {
        const string memoryVariable = "VULTRACK_DUCKDB_MEMORY_LIMIT";
        const string threadsVariable = "VULTRACK_DUCKDB_THREADS";
        var previousMemory = Environment.GetEnvironmentVariable(memoryVariable);
        var previousThreads = Environment.GetEnvironmentVariable(threadsVariable);

        Environment.SetEnvironmentVariable(memoryVariable, "   ");
        Environment.SetEnvironmentVariable(threadsVariable, "\t");
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:MemoryLimit"] = " ",
                    ["VulTrack:DuckDb:Threads"] = ""
                })
                .Build();

            var options = VulTrackOptions.Load(configuration);

            Assert.Equal("3g", options.DuckDb.MemoryLimit);
            Assert.Equal("4", options.DuckDb.Threads);
        }
        finally
        {
            Environment.SetEnvironmentVariable(memoryVariable, previousMemory);
            Environment.SetEnvironmentVariable(threadsVariable, previousThreads);
        }
    }

    [Fact]
    public void Load_FallsBackFromBlankEnvironmentToTrimmedConfiguration()
    {
        const string memoryVariable = "VULTRACK_DUCKDB_MEMORY_LIMIT";
        const string threadsVariable = "VULTRACK_DUCKDB_THREADS";
        var previousMemory = Environment.GetEnvironmentVariable(memoryVariable);
        var previousThreads = Environment.GetEnvironmentVariable(threadsVariable);

        Environment.SetEnvironmentVariable(memoryVariable, "   ");
        Environment.SetEnvironmentVariable(threadsVariable, "\t");
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:MemoryLimit"] = " 2g ",
                    ["VulTrack:DuckDb:Threads"] = " 3 "
                })
                .Build();

            var options = VulTrackOptions.Load(configuration);

            Assert.Equal("2g", options.DuckDb.MemoryLimit);
            Assert.Equal("3", options.DuckDb.Threads);
        }
        finally
        {
            Environment.SetEnvironmentVariable(memoryVariable, previousMemory);
            Environment.SetEnvironmentVariable(threadsVariable, previousThreads);
        }
    }
}
