namespace VulTrack.App;

public sealed record VulTrackOptions(
    string? RepoRoot,
    string? SpoolPath,
    DuckDbOptions DuckDb,
    SchedulerOptions Scheduler,
    AdminOptions Admin,
    AiOptions Ai)
{
    public string ResolveSpoolRoot() =>
        !string.IsNullOrWhiteSpace(SpoolPath)
            ? Path.GetFullPath(SpoolPath)
            : Path.Combine(RepoRoot ?? Directory.GetCurrentDirectory(), "data", "spool");

    public string ResolveSpoolIncoming() => Path.Combine(ResolveSpoolRoot(), "incoming");

    public static VulTrackOptions Load(IConfiguration configuration)
    {
        var repoRoot = Environment.GetEnvironmentVariable("VULTRACK_REPO_ROOT");
        var spoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");

        var duckDbPath = Setting(
            "VULTRACK_DUCKDB_PATH", configuration, "VulTrack:DuckDb:Path", "");
        var databasePath = !string.IsNullOrWhiteSpace(duckDbPath)
            ? Path.GetFullPath(duckDbPath)
            : Path.GetFullPath(Path.Combine(
                repoRoot ?? Directory.GetCurrentDirectory(), "data", "duckdb", "vultrack-evidence.duckdb"));

        var duckDb = new DuckDbOptions(
            Enabled: BoolSetting(
                "VULTRACK_DUCKDB_ENABLED", configuration, "VulTrack:DuckDb:Enabled", false),
            DatabasePath: databasePath,
            // Always cap. With no limit DuckDB claims ~80% of host RAM, which overruns the
            // container budget whenever the app runs outside docker-compose.
            MemoryLimit: Setting(
                "VULTRACK_DUCKDB_MEMORY_LIMIT", configuration, "VulTrack:DuckDb:MemoryLimit", DefaultDuckDbMemoryLimit),
            Threads: Setting(
                "VULTRACK_DUCKDB_THREADS", configuration, "VulTrack:DuckDb:Threads", DefaultDuckDbThreads),
            NucleiAllowLargeSnapshotDrop: BoolFlag("NUCLEI_ALLOW_LARGE_SNAPSHOT_DROP", false),
            NucleiLargeSnapshotDropThreshold: NucleiDropThreshold());

        var scheduler = new SchedulerOptions(
            Enabled: BoolFlag("VULTRACK_SCHEDULER_ENABLED", false),
            FetchIntervalSeconds: IntSetting("DUCKDB_FETCH_INTERVAL_SECONDS", 21600, 60),
            InitialDelaySeconds: IntSetting("DUCKDB_FETCH_INITIAL_DELAY_SECONDS", 15, 0),
            AllowAutomaticInit: BoolFlag("DUCKDB_ALLOW_AUTOMATIC_INIT", false),
            OsvPendingMaxBatchesPerCycle: Math.Clamp(IntSetting("OSV_PENDING_MAX_BATCHES_PER_CYCLE", 3, 1), 1, 12),
            FetchSources: FirstNonBlank(
                Environment.GetEnvironmentVariable("DUCKDB_FETCH_SOURCES"), SchedulerOptions.DefaultFetchSources));

        var admin = new AdminOptions(
            Username: FirstNonBlank(Environment.GetEnvironmentVariable("VULTRACK_ADMIN_USERNAME"), "admin"),
            Password: FirstNonBlank(Environment.GetEnvironmentVariable("VULTRACK_ADMIN_PASSWORD"), "change-me"));

        var ai = AiOptions.Load(configuration);

        return new VulTrackOptions(repoRoot, spoolPath, duckDb, scheduler, admin, ai);
    }

    // Matches the docker-compose defaults so in-container and out-of-container runs agree.
    internal const string DefaultDuckDbMemoryLimit = "3g";
    internal const string DefaultDuckDbThreads = "4";

    internal static bool IsTrue(string? value) =>
        string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);

    internal static bool BoolFlag(string name, bool fallback) =>
        bool.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? value : fallback;

    internal static bool BoolSetting(
        string envName,
        IConfiguration configuration,
        string configKey,
        bool fallback) =>
        bool.TryParse(Setting(envName, configuration, configKey, fallback.ToString()), out var value)
            ? value
            : fallback;

    internal static int IntSetting(string name, int fallback, int minimum) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? Math.Max(minimum, value) : fallback;

    // Treats blank as absent so an empty env var falls through to config and then the fallback,
    // instead of silently disabling the setting it belongs to.
    internal static string Setting(string envName, IConfiguration configuration, string configKey, string fallback) =>
        FirstNonBlank(Environment.GetEnvironmentVariable(envName), configuration[configKey], fallback);

    internal static string FirstNonBlank(params string?[] values)
    {
        foreach (var value in values)
            if (!string.IsNullOrWhiteSpace(value)) return value.Trim();
        return "";
    }

    internal static int IntSetting(string envName, IConfiguration configuration, string configKey, int fallback) =>
        int.TryParse(Setting(envName, configuration, configKey, ""), out var value) && value > 0 ? value : fallback;

    private static double NucleiDropThreshold()
    {
        var raw = Environment.GetEnvironmentVariable("NUCLEI_LARGE_SNAPSHOT_DROP_THRESHOLD");
        if (double.TryParse(raw, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var configured))
            return Math.Clamp(configured, 0.0, 1.0);
        return 0.5;
    }
}

public sealed record DuckDbOptions(
    bool Enabled,
    string DatabasePath,
    string? MemoryLimit,
    string? Threads,
    bool NucleiAllowLargeSnapshotDrop,
    double NucleiLargeSnapshotDropThreshold);

public sealed record SchedulerOptions(
    bool Enabled,
    int FetchIntervalSeconds,
    int InitialDelaySeconds,
    bool AllowAutomaticInit,
    int OsvPendingMaxBatchesPerCycle,
    string FetchSources)
{
    public const string DefaultFetchSources =
        "nvd-cve,osv,ghsa,google-osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory";

    public string[] SourceCodes() =>
        FetchSources
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
}

public sealed record AdminOptions(string Username, string Password);

public sealed record AiOptions(
    string BaseUrl,
    string ApiKey,
    string Model,
    string PromptVersion,
    string SystemPromptPath,
    string PromptCacheKey,
    string PromptCacheRetention,
    bool Enabled,
    int MaxInputChars,
    int MaxOutputTokens,
    string Language)
{
    private const string DefaultPromptVersion = "vultrack-ai-analysis-automotive-v4";

    public bool Configured =>
        Enabled
        && !string.IsNullOrWhiteSpace(BaseUrl)
        && !string.IsNullOrWhiteSpace(ApiKey)
        && !string.IsNullOrWhiteSpace(Model);

    public static AiOptions Load(IConfiguration configuration)
    {
        var apiKey = VulTrackOptions.Setting("VULTRACK_AI_API_KEY", configuration, "VulTrack:AI:ApiKey", "");
        return new AiOptions(
            BaseUrl: VulTrackOptions.Setting("VULTRACK_AI_BASE_URL", configuration, "VulTrack:AI:BaseUrl", ""),
            ApiKey: apiKey,
            Model: VulTrackOptions.Setting("VULTRACK_AI_MODEL", configuration, "VulTrack:AI:Model", "openai/gpt-5.5"),
            PromptVersion: VulTrackOptions.Setting(
                "VULTRACK_AI_ANALYSIS_PROMPT_VERSION", configuration, "VulTrack:AI:AnalysisPromptVersion",
                VulTrackOptions.Setting("VULTRACK_AI_PROMPT_VERSION", configuration, "VulTrack:AI:PromptVersion", DefaultPromptVersion)),
            SystemPromptPath: VulTrackOptions.Setting(
                "VULTRACK_AI_ANALYSIS_SYSTEM_PROMPT_PATH", configuration, "VulTrack:AI:AnalysisSystemPromptPath",
                VulTrackOptions.Setting("VULTRACK_AI_SYSTEM_PROMPT_PATH", configuration, "VulTrack:AI:SystemPromptPath", "prompts/vulnerability-analysis-batch.system.md")),
            PromptCacheKey: VulTrackOptions.Setting("VULTRACK_AI_PROMPT_CACHE_KEY", configuration, "VulTrack:AI:PromptCacheKey", ""),
            PromptCacheRetention: VulTrackOptions.Setting("VULTRACK_AI_PROMPT_CACHE_RETENTION", configuration, "VulTrack:AI:PromptCacheRetention", ""),
            Enabled: VulTrackOptions.IsTrue(VulTrackOptions.Setting("VULTRACK_AI_ENABLED", configuration, "VulTrack:AI:Enabled", ""))
                || !string.IsNullOrWhiteSpace(apiKey),
            MaxInputChars: VulTrackOptions.IntSetting("VULTRACK_AI_MAX_INPUT_CHARS", configuration, "VulTrack:AI:MaxInputChars", 12000),
            MaxOutputTokens: VulTrackOptions.IntSetting("VULTRACK_AI_MAX_OUTPUT_TOKENS", configuration, "VulTrack:AI:MaxOutputTokens", 1400),
            Language: VulTrackOptions.Setting("VULTRACK_AI_LANGUAGE", configuration, "VulTrack:AI:Language", "en-US"));
    }
}
