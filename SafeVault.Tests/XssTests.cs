using System.Net;
using SafeVault.Web.Security;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Cross-site scripting coverage. The payload is stored exactly as typed (validation does not
/// strip it) and must appear encoded everywhere it is written back out.
/// </summary>
public sealed class XssTests(SafeVaultFactory factory) : IClassFixture<SafeVaultFactory>
{
    private const string Password = "Str0ng!Passphrase#1";
    private const string ScriptPayload = "<script>alert('xss')</script>";
    private const string ImagePayload = "<img src=x onerror=alert(1)>";

    private async Task<(HttpClient Client, long ItemId)> CreateItemAsync(string username, string title, string body)
    {
        factory.SeedUser(username, Password);
        var user = factory.RequireCredentials(username);

        var client = factory.CreateApiClient();
        var login = await TestHttp.LoginAsync(client, username, Password);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);

        var create = await TestHttp.CreateItemAsync(client, title, body);
        Assert.Equal(HttpStatusCode.Redirect, create.StatusCode);

        var item = factory.ItemsFor(user.Id).Single();
        return (client, item.Id);
    }

    [Fact]
    public async Task StoredScriptPayload_IsEncodedOnTheDetailPage()
    {
        var (client, itemId) = await CreateItemAsync("xss_detail", "Stored script", ScriptPayload);
        using var http = client;

        var response = await http.GetAsync($"/Vault/Detail?id={itemId}");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("&lt;script&gt;", html);
        Assert.DoesNotContain("<script", html);
        Assert.DoesNotContain(ScriptPayload, html);
    }

    [Fact]
    public async Task StoredImagePayload_IsEncodedOnTheDetailPage()
    {
        var (client, itemId) = await CreateItemAsync("xss_image", "Stored image", ImagePayload);
        using var http = client;

        var html = await http.GetStringAsync($"/Vault/Detail?id={itemId}");

        Assert.Contains("&lt;img", html);
        Assert.DoesNotContain("<img", html);
    }

    [Fact]
    public async Task StoredScriptPayload_IsEncodedInTheListPage()
    {
        var (client, _) = await CreateItemAsync("xss_list", "List payload", ScriptPayload);
        using var http = client;

        var html = await http.GetStringAsync("/Vault");

        Assert.Contains("List payload", html);
        Assert.DoesNotContain("<script", html);
    }

    [Fact]
    public async Task SearchHighlight_EncodesTheMatchItWraps()
    {
        var (client, _) = await CreateItemAsync("xss_search", ImagePayload, "body text");
        using var http = client;

        var html = await http.GetStringAsync("/Vault?q=img");

        // The match is marked, but only after the text was encoded.
        Assert.Contains("<mark>img</mark>", html);
        Assert.Contains("&lt;img", html);
        Assert.DoesNotContain("<img", html);
    }

    [Fact]
    public async Task JsonApi_ReturnsJson_NotHtml()
    {
        var (client, itemId) = await CreateItemAsync("xss_json", "Json payload", ScriptPayload);
        using var http = client;

        var response = await http.GetAsync($"/api/items/{itemId}");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        Assert.DoesNotContain("<script", body);
        Assert.Contains("\\u003Cscript", body);
    }

    [Fact]
    public async Task RawContentEndpoint_IsPlainTextAndNotSniffed()
    {
        var (client, itemId) = await CreateItemAsync("xss_raw", "Raw payload", ScriptPayload);
        using var http = client;

        var response = await http.GetAsync($"/api/items/{itemId}/content");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/plain", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal(ScriptPayload, body);

        // nosniff stops a browser from deciding this plain-text body is really HTML.
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task SecurityHeaders_ArePresentWithARestrictiveContentSecurityPolicy()
    {
        using var client = factory.CreateApiClient();

        var response = await client.GetAsync("/Account/Login");
        var csp = response.Headers.GetValues("Content-Security-Policy").Single();

        Assert.Contains("script-src 'self'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
        Assert.DoesNotContain("unsafe-eval", csp);
        Assert.Contains("frame-ancestors 'none'", csp);

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("no-store", response.Headers.GetValues("Cache-Control").Single());
    }

    [Fact]
    public void Highlight_EncodesBeforeItAddsMarkup()
    {
        var html = HtmlOutput.Highlight(ScriptPayload, "script").ToString();

        // The match is marked inside already-encoded text: "&lt;" stays an entity.
        Assert.Contains("&lt;<mark>script</mark>&gt;", html);
        Assert.DoesNotContain("<script", html);
    }
}
