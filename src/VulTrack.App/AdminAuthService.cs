using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace VulTrack.App;

public sealed class AdminAuthService
{
    public const string CookieName = "vultrack_admin";
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(12);
    private readonly ConcurrentDictionary<string, Session> sessions = new(StringComparer.Ordinal);
    private readonly string username;
    private readonly string password;

    public AdminAuthService(VulTrackOptions options)
    {
        username = options.Admin.Username;
        password = options.Admin.Password;
    }

    public string Username => username;

    public bool ValidateCredentials(string? candidateUsername, string? candidatePassword) =>
        FixedEquals(username, candidateUsername) && FixedEquals(password, candidatePassword);

    public string CreateSession()
    {
        PurgeExpired();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        sessions[token] = new Session(DateTimeOffset.UtcNow.Add(SessionLifetime));
        return token;
    }

    public bool IsAuthenticated(HttpContext context)
    {
        if (!context.Request.Cookies.TryGetValue(CookieName, out var token)) return false;
        if (!sessions.TryGetValue(token, out var session)) return false;
        if (session.ExpiresAt > DateTimeOffset.UtcNow) return true;
        sessions.TryRemove(token, out _);
        return false;
    }

    public void Revoke(HttpContext context)
    {
        if (context.Request.Cookies.TryGetValue(CookieName, out var token))
            sessions.TryRemove(token, out _);
    }

    public static CookieOptions CookieOptions(HttpContext context) => new()
    {
        HttpOnly = true,
        IsEssential = true,
        SameSite = SameSiteMode.Strict,
        Secure = context.Request.IsHttps,
        MaxAge = SessionLifetime,
        Path = "/"
    };

    private void PurgeExpired()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (token, session) in sessions)
            if (session.ExpiresAt <= now) sessions.TryRemove(token, out _);
    }

    private static bool FixedEquals(string expected, string? actual)
    {
        if (actual is null) return false;
        return CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(expected)),
            SHA256.HashData(Encoding.UTF8.GetBytes(actual)));
    }

    private sealed record Session(DateTimeOffset ExpiresAt);
}
