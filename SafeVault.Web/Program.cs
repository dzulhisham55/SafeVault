using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault.Web.Api;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages(options =>
{
    // Deny-by-default for the two authenticated areas: a page added to these folders is
    // protected without anyone having to remember an attribute.
    options.Conventions.AuthorizeFolder("/Vault");

    // Authenticated only: the Admin *role* requirement lives on the page model. Passing a
    // role name as the second argument here would be read as a policy name, and an unknown
    // policy fails every request to the folder with a 500.
    options.Conventions.AuthorizeFolder("/Admin");
});

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<Database>();
builder.Services.AddScoped<UserRepository>();
builder.Services.AddScoped<VaultItemRepository>();
builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton<LoginThrottle>();
builder.Services.AddScoped<SignInService>();
builder.Services.AddAntiforgery();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/Denied";
        options.Cookie.Name = "SafeVault.Auth";
        options.Cookie.HttpOnly = true;                        // not readable from JavaScript
        options.Cookie.SameSite = SameSiteMode.Lax;             // blocks cross-site POSTs
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;

        options.Events.OnRedirectToLogin = context =>
            RespondToUnauthenticatedRequest(context, StatusCodes.Status401Unauthorized);
        options.Events.OnRedirectToAccessDenied = context =>
            RespondToUnauthenticatedRequest(context, StatusCodes.Status403Forbidden);
    });

builder.Services.AddAuthorization();

builder.Services.ConfigureHttpJsonOptions(options =>
{
    // Escape HTML-sensitive characters inside JSON as well. The content type and nosniff
    // already prevent interpretation, but a payload should not survive verbatim into any
    // consumer that embeds this response in a page.
    options.SerializerOptions.Encoder = JavaScriptEncoder.Default;
});

var app = builder.Build();

// Schema and seed data must exist before the first request is served.
app.Services.GetRequiredService<Database>().Initialize();
DatabaseSeeder.EnsureAdministrator(
    app.Services,
    app.Configuration,
    app.Environment,
    app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SafeVault.Startup"));

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

if (app.Configuration.GetValue("SafeVault:HttpsRedirection", true))
{
    app.UseHttpsRedirection();
}

app.UseSecurityHeaders();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapRazorPages();
app.MapVaultApi();

app.Run();

static Task RespondToUnauthenticatedRequest(RedirectContext<CookieAuthenticationOptions> context, int statusCode)
{
    // A JSON client should get a status code, not a 302 to an HTML page: redirecting hides
    // whether the caller was anonymous (401) or merely not allowed (403).
    if (context.Request.Path.StartsWithSegments("/api"))
    {
        context.Response.StatusCode = statusCode;
        return Task.CompletedTask;
    }

    context.Response.Redirect(context.RedirectUri);
    return Task.CompletedTask;
}

public partial class Program
{
}
