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
        error = new { code, message },
        requestId = Guid.NewGuid().ToString("N")[..8]
    }, statusCode: StatusCodes.Status404NotFound);

    public static IResult Error(string code, string message) => Results.Json(new
    {
        ok = false,
        error = new { code, message },
        requestId = Guid.NewGuid().ToString("N")[..8]
    }, statusCode: StatusCodes.Status400BadRequest);
}
