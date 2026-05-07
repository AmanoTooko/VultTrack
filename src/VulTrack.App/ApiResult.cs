namespace VulTrack.App;

public static class ApiResult
{
    public static IResult Ok(object? data) => Results.Json(new
    {
        ok = true,
        data,
        requestId = Guid.NewGuid().ToString("n")
    });

    public static IResult NotFound(string code, string message) => Results.Json(new
    {
        ok = false,
        error = new { code, message, details = new { } },
        requestId = Guid.NewGuid().ToString("n")
    }, statusCode: StatusCodes.Status404NotFound);
}
