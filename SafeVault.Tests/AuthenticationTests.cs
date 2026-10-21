using System.Net;
using SafeVault.Web.Security;
using Xunit;

namespace SafeVault.Tests;

public sealed class AuthenticationTests(SafeVaultFactory factory) : IClassFixture<SafeVaultFactory>
{
    private const string Password = "Str0ng!Passphrase#1";

    [Fact]
    public async Task AnonymousRequest_ToVault_IsRedirectedToLogin()
    {
        using var client = factory.CreateApiClient();

        var response = await client.GetAsync("/Vault");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/Account/Login", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task ValidCredentials_AreAccepted_AndTheCookieIsHttpOnly()
    {
        factory.SeedUser("auth_valid", Password);
        using var client = factory.CreateApiClient();

        var response = await TestHttp.LoginAsync(client, "auth_valid", Password);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Vault", response.Headers.Location!.ToString());

        var setCookie = response.Headers.GetValues("Set-Cookie").Single();
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", setCookie, StringComparison.OrdinalIgnoreCase);

        var vault = await client.GetAsync("/Vault");
        Assert.Equal(HttpStatusCode.OK, vault.StatusCode);
    }

    [Fact]
    public async Task WrongPassword_IsRejected_WithAGenericMessage()
    {
        factory.SeedUser("auth_wrong", Password);
        using var client = factory.CreateApiClient();

        var response = await TestHttp.LoginAsync(client, "auth_wrong", "Definitely!Wrong#2026");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Username or password is incorrect", html);

        // The password itself is never echoed back into the form.
        Assert.DoesNotContain("Definitely!Wrong#2026", html);

        var vault = await client.GetAsync("/Vault");
        Assert.Equal(HttpStatusCode.Redirect, vault.StatusCode);
    }

    [Fact]
    public async Task UnknownUsername_ProducesTheSameMessageAsAWrongPassword()
    {
        factory.SeedUser("auth_known", Password);
        using var wrongPasswordClient = factory.CreateApiClient();
        using var unknownUserClient = factory.CreateApiClient();

        var wrongPassword = await TestHttp.LoginAsync(wrongPasswordClient, "auth_known", "Definitely!Wrong#2026");
        var unknownUser = await TestHttp.LoginAsync(unknownUserClient, "auth_absent", Password);

        var wrongPasswordHtml = await wrongPassword.Content.ReadAsStringAsync();
        var unknownUserHtml = await unknownUser.Content.ReadAsStringAsync();

        // The same sentence for both cases, so the response never confirms that a username
        // does or does not exist.
        const string genericMessage = "Username or password is incorrect";
        Assert.Contains(genericMessage, wrongPasswordHtml);
        Assert.Contains(genericMessage, unknownUserHtml);

        foreach (var hint in new[] { "does not exist", "no such user", "unknown user", "not registered" })
        {
            Assert.DoesNotContain(hint, unknownUserHtml, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(hint, wrongPasswordHtml, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task ReturnUrl_PointingOffSite_IsIgnored()
    {
        factory.SeedUser("auth_redirect", Password);
        using var client = factory.CreateApiClient();

        var response = await TestHttp.LoginAsync(
            client,
            "auth_redirect",
            Password,
            returnUrl: "https://evil.example/collect");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Vault", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task ReturnUrl_PointingInsideTheApp_IsHonoured()
    {
        factory.SeedUser("auth_local", Password);
        using var client = factory.CreateApiClient();

        var response = await TestHttp.LoginAsync(
            client,
            "auth_local",
            Password,
            returnUrl: "/Vault?q=notes");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Vault?q=notes", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task PostWithoutAnAntiforgeryToken_IsRejected()
    {
        using var client = factory.CreateApiClient();

        var response = await TestHttp.PostFormAsync(
            client,
            "/Account/Login",
            new Dictionary<string, string?>
            {
                ["Input.Username"] = SafeVaultFactory.AdminUsername,
                ["Input.Password"] = SafeVaultFactory.AdminPassword,
            },
            tokenPath: "/Account/Login",
            includeAntiforgeryToken: false);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task FiveFailedAttempts_LockTheAccountOut_EvenWithTheCorrectPassword()
    {
        factory.SeedUser("auth_lock", Password);
        using var client = factory.CreateApiClient();

        for (var attempt = 0; attempt < LoginThrottle.MaxFailures; attempt++)
        {
            var failed = await TestHttp.LoginAsync(client, "auth_lock", "Definitely!Wrong#2026");
            Assert.Equal(HttpStatusCode.OK, failed.StatusCode);
        }

        var locked = await TestHttp.LoginAsync(client, "auth_lock", Password);
        var html = await locked.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, locked.StatusCode);
        Assert.Contains("Too many failed attempts", html);

        var vault = await client.GetAsync("/Vault");
        Assert.Equal(HttpStatusCode.Redirect, vault.StatusCode);
    }

    [Fact]
    public async Task SignOut_ClearsTheAuthenticationCookie()
    {
        factory.SeedUser("auth_signout", Password);
        using var client = factory.CreateApiClient();
        await TestHttp.LoginAsync(client, "auth_signout", Password);

        var token = await TestHttp.GetTokenAsync(client, "/Vault");
        var signOut = await client.PostAsync(
            "/Account/Logout",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = token,
            }));

        Assert.Equal(HttpStatusCode.Redirect, signOut.StatusCode);

        var vault = await client.GetAsync("/Vault");
        Assert.Equal(HttpStatusCode.Redirect, vault.StatusCode);
    }

    [Fact]
    public async Task SignedInUser_VisitingTheLoginPage_IsSentToTheVault()
    {
        factory.SeedUser("auth_again", Password);
        using var client = factory.CreateApiClient();
        await TestHttp.LoginAsync(client, "auth_again", Password);

        var response = await client.GetAsync("/Account/Login");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Vault", response.Headers.Location!.ToString());
    }
}
