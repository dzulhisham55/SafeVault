namespace SafeVault.Web.Security;

/// <summary>
/// Adds the headers that make an output-encoding mistake much harder to exploit: a CSP with
/// no <c>unsafe-inline</c> and no <c>unsafe-eval</c> means an injected <c>&lt;script&gt;</c>
/// element cannot execute, <c>nosniff</c> stops content being re-interpreted as HTML, and
/// <c>frame-ancestors 'none'</c> blocks clickjacking.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    private const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'";

    private readonly RequestDelegate _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        headers["Content-Security-Policy"] = ContentSecurityPolicy;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";

        if (context.Request.IsHttps)
        {
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        }

        // Pages carry a signed-in user's data; never let a shared cache keep them.
        if (!Path.HasExtension(context.Request.Path.Value))
        {
            headers["Cache-Control"] = "no-store";
        }

        await _next(context);
    }
}

public static class SecurityHeadersExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) =>
        app.UseMiddleware<SecurityHeadersMiddleware>();
}
