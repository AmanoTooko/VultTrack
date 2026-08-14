namespace VulTrack.App;

public static class AuthEndpoints
{
    public static WebApplication MapAuthEndpoints(this WebApplication app)
    {
        app.MapGet("/api/v1/auth.session", (HttpContext context, AdminAuthService auth) =>
            ApiResult.Ok(new { authenticated = auth.IsAuthenticated(context), username = auth.IsAuthenticated(context) ? auth.Username : null }));

        app.MapPost("/api/v1/auth.login", (HttpContext context, AdminAuthService auth, AdminLoginRequest request) =>
        {
            if (!auth.ValidateCredentials(request.Username, request.Password))
                return ApiResult.Unauthorized("Invalid username or password.");
            context.Response.Cookies.Append(AdminAuthService.CookieName, auth.CreateSession(), AdminAuthService.CookieOptions(context));
            return ApiResult.Ok(new { authenticated = true, username = auth.Username });
        });

        app.MapPost("/api/v1/auth.logout", (HttpContext context, AdminAuthService auth) =>
        {
            auth.Revoke(context);
            context.Response.Cookies.Delete(AdminAuthService.CookieName, AdminAuthService.CookieOptions(context));
            return ApiResult.Ok(new { authenticated = false });
        });

        return app;
    }
}
