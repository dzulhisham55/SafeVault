using System.Net;
using System.Text.RegularExpressions;

namespace SafeVault.Tests;

/// <summary>
/// Drives the app the way a browser does: fetch the page, take its antiforgery token, post
/// the form. No test bypasses a filter or calls a handler directly.
/// </summary>
internal static class TestHttp
{
    private static readonly Regex TokenPattern = new(
        "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"",
        RegexOptions.Compiled | RegexOptions.Singleline);

    public static async Task<string> GetTokenAsync(HttpClient client, string path)
    {
        using var response = await client.GetAsync(path);
        response.EnsureSuccessStatusCode();

        var html = await response.Content.ReadAsStringAsync();
        var match = TokenPattern.Match(html);

        if (!match.Success)
        {
            throw new InvalidOperationException($"No antiforgery token was rendered on {path}.");
        }

        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    public static async Task<HttpResponseMessage> PostFormAsync(
        HttpClient client,
        string path,
        IReadOnlyDictionary<string, string?> fields,
        string tokenPath,
        bool includeAntiforgeryToken = true)
    {
        var payload = new Dictionary<string, string>(StringComparer.Ordinal);

        if (includeAntiforgeryToken)
        {
            payload["__RequestVerificationToken"] = await GetTokenAsync(client, tokenPath);
        }

        foreach (var (key, value) in fields)
        {
            if (value is not null)
            {
                payload[key] = value;
            }
        }

        return await client.PostAsync(path, new FormUrlEncodedContent(payload));
    }

    public static Task<HttpResponseMessage> LoginAsync(
        HttpClient client,
        string username,
        string password,
        string? returnUrl = null) =>
        PostFormAsync(
            client,
            "/Account/Login",
            new Dictionary<string, string?>
            {
                ["Input.Username"] = username,
                ["Input.Password"] = password,
                ["ReturnUrl"] = returnUrl,
            },
            tokenPath: "/Account/Login");

    public static Task<HttpResponseMessage> RegisterAsync(
        HttpClient client,
        string username,
        string password,
        string? confirmPassword = null) =>
        PostFormAsync(
            client,
            "/Account/Register",
            new Dictionary<string, string?>
            {
                ["Input.Username"] = username,
                ["Input.Password"] = password,
                ["Input.ConfirmPassword"] = confirmPassword ?? password,
            },
            tokenPath: "/Account/Register");

    public static Task<HttpResponseMessage> CreateItemAsync(HttpClient client, string title, string body) =>
        PostFormAsync(
            client,
            "/Vault?handler=Create",
            new Dictionary<string, string?>
            {
                ["Title"] = title,
                ["Body"] = body,
            },
            tokenPath: "/Vault");

    public static Task<HttpResponseMessage> DeleteItemAsync(HttpClient client, long id) =>
        PostFormAsync(
            client,
            $"/Vault?handler=Delete&id={id}",
            new Dictionary<string, string?>(),
            tokenPath: "/Vault");

    public static Task<HttpResponseMessage> SetRoleAsync(HttpClient client, long userId, string role) =>
        PostFormAsync(
            client,
            $"/Admin?handler=SetRole&id={userId}&role={Uri.EscapeDataString(role)}",
            new Dictionary<string, string?>(),
            tokenPath: "/Vault");
}
