using System.Net;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Web.Data;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// SQL injection coverage. The classic payloads are sent through the real forms and through
/// the repository API; none of them changes the meaning of a statement.
/// </summary>
public sealed class SqlInjectionTests(SafeVaultFactory factory) : IClassFixture<SafeVaultFactory>
{
    private const string Tautology = "' OR '1'='1";
    private const string CommentPayload = "admin' --";
    private const string StrongPassword = "Str0ng!Passphrase#1";

    [Theory]
    [InlineData("' OR '1'='1")]
    [InlineData("admin' --")]
    [InlineData("' OR 1=1 --")]
    [InlineData("'; DROP TABLE Users; --")]
    [InlineData("\" OR \"\"=\"")]
    public void Repository_TreatsPayloadAsLiteralUsername(string payload)
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserRepository>();

        Assert.Null(users.FindCredentialsByUsername(payload));

        // Proof the schema is intact and the real row is still findable.
        Assert.NotNull(users.FindCredentialsByUsername(SafeVaultFactory.AdminUsername));
    }

    [Fact]
    public async Task Login_WithTautologyPayload_DoesNotAuthenticate()
    {
        using var client = factory.CreateApiClient();

        var response = await TestHttp.LoginAsync(client, Tautology, Tautology + " --");

        // The page comes back with an error; no authentication cookie is issued.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Username or password is incorrect", await response.Content.ReadAsStringAsync());

        var vault = await client.GetAsync("/Vault");
        Assert.Equal(HttpStatusCode.Redirect, vault.StatusCode);
        Assert.Contains("/Account/Login", vault.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Login_WithCommentPayload_DoesNotLogInAsAdmin()
    {
        using var client = factory.CreateApiClient();

        await TestHttp.LoginAsync(client, CommentPayload, "anything");

        var vault = await client.GetAsync("/Vault");
        Assert.Equal(HttpStatusCode.Redirect, vault.StatusCode);
    }

    [Fact]
    public async Task Search_WithTautologyPayload_ReturnsOnlyTheSignedInUsersItems()
    {
        factory.SeedUser("sqli_alpha", StrongPassword);
        factory.SeedUser("sqli_bravo", StrongPassword);

        var alpha = factory.RequireCredentials("sqli_alpha");
        var bravo = factory.RequireCredentials("sqli_bravo");

        factory.SeedItem(alpha.Id, "Alpha inventory note", "Only alpha may see this.");
        factory.SeedItem(bravo.Id, "Bravo secret note", "Only bravo may see this.");

        using var client = factory.CreateApiClient();
        await TestHttp.LoginAsync(client, "sqli_alpha", StrongPassword);

        var response = await client.GetAsync("/Vault?q=" + Uri.EscapeDataString(Tautology));
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("Bravo secret note", html);

        // The payload is a search term, not syntax: it matches nothing at all rather than
        // widening the statement to every row.
        Assert.Contains("No items match that search", html);
    }

    [Fact]
    public async Task Search_PercentSign_IsMatchedLiterallyInsteadOfMatchingEverything()
    {
        var owner = factory.RequireCredentials(SafeVaultFactory.AdminUsername);
        factory.SeedItem(owner.Id, "Sqli wildcard probe item", "No percent sign in this row.");

        using var client = factory.CreateApiClient();
        await TestHttp.LoginAsync(client, SafeVaultFactory.AdminUsername, SafeVaultFactory.AdminPassword);

        var response = await client.GetAsync("/Vault?q=" + Uri.EscapeDataString("%"));
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Escaped wildcard: "%" searches for a literal percent sign, so nothing matches.
        Assert.DoesNotContain("Sqli wildcard probe item", html);
    }

    [Fact]
    public async Task Search_Underscore_IsMatchedLiterally()
    {
        var owner = factory.RequireCredentials(SafeVaultFactory.AdminUsername);
        factory.SeedItem(owner.Id, "Underscore probe row", "Single-word titles must not match the wildcard.");

        using var client = factory.CreateApiClient();
        await TestHttp.LoginAsync(client, SafeVaultFactory.AdminUsername, SafeVaultFactory.AdminPassword);

        var response = await client.GetAsync("/Vault?q=" + Uri.EscapeDataString("_"));
        var html = await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain("Underscore probe row", html);
    }

    [Theory]
    [InlineData("100%", "100\\%")]
    [InlineData("a_b", "a\\_b")]
    [InlineData("back\\slash", "back\\\\slash")]
    public void EscapeLike_NeutralisesWildcards(string input, string expected)
    {
        Assert.Equal(expected, VaultItemRepository.EscapeLike(input));
    }

    [Fact]
    public async Task Registration_WithSqlMetacharactersInUsername_IsRejectedBeforeItReachesSql()
    {
        using var client = factory.CreateApiClient();

        var response = await TestHttp.RegisterAsync(client, "'; DROP TABLE Users; --", StrongPassword);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("letters, digits and underscores", html);

        // The table still answers, so nothing was dropped.
        Assert.NotNull(factory.RequireCredentials(SafeVaultFactory.AdminUsername));
    }
}
