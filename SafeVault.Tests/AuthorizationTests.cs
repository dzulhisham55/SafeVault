using System.Net;
using SafeVault.Web.Security;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Role-based access to the administration area, plus ownership checks on individual items
/// (the horizontal-privilege half of authorization, which a role check alone does not cover).
/// </summary>
public sealed class AuthorizationTests(SafeVaultFactory factory) : IClassFixture<SafeVaultFactory>
{
    private const string Password = "Str0ng!Passphrase#1";

    private async Task<HttpClient> SignInAsync(string username, string password)
    {
        var client = factory.CreateApiClient();
        var response = await TestHttp.LoginAsync(client, username, password);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return client;
    }

    [Fact]
    public async Task Anonymous_ApiRequest_Returns401InsteadOfARedirect()
    {
        using var client = factory.CreateApiClient();

        var response = await client.GetAsync("/api/items");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_AdminPage_RedirectsToLogin()
    {
        using var client = factory.CreateApiClient();

        var response = await client.GetAsync("/Admin");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/Account/Login", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task OrdinaryUser_CannotOpenTheAdminPage()
    {
        factory.SeedUser("authz_user", Password, Roles.User);
        using var client = await SignInAsync("authz_user", Password);

        var response = await client.GetAsync("/Admin");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/Account/Denied", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Administrator_CanOpenTheAdminPage()
    {
        using var client = await SignInAsync(SafeVaultFactory.AdminUsername, SafeVaultFactory.AdminPassword);

        var response = await client.GetAsync("/Admin");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Administration", html);
        Assert.Contains(SafeVaultFactory.AdminUsername, html);
    }

    [Fact]
    public async Task OrdinaryUser_ChangingSomeonesRole_IsBlocked()
    {
        factory.SeedUser("authz_climber", Password, Roles.User);
        factory.SeedUser("authz_victim", Password, Roles.User);

        var climber = factory.RequireCredentials("authz_climber");
        var victim = factory.RequireCredentials("authz_victim");

        using var client = await SignInAsync("authz_climber", Password);
        var response = await TestHttp.SetRoleAsync(client, victim.Id, Roles.Admin);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/Account/Denied", response.Headers.Location!.ToString());

        // Self-promotion through the handler is refused and the role is unchanged.
        var stored = factory.RequireCredentials("authz_victim");
        Assert.Equal(Roles.User, stored.Role);
        Assert.NotEqual(Roles.Admin, factory.RequireCredentials("authz_climber").Role);
        Assert.NotEqual(0, climber.Id);
    }

    [Fact]
    public async Task Administrator_CanPromoteAnotherUser()
    {
        factory.SeedUser("authz_promote", Password, Roles.User);
        var target = factory.RequireCredentials("authz_promote");

        using var client = await SignInAsync(SafeVaultFactory.AdminUsername, SafeVaultFactory.AdminPassword);
        var response = await TestHttp.SetRoleAsync(client, target.Id, Roles.Admin);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(Roles.Admin, factory.RequireCredentials("authz_promote").Role);
    }

    [Fact]
    public async Task Administrator_CannotRemoveTheirOwnRole()
    {
        var admin = factory.RequireCredentials(SafeVaultFactory.AdminUsername);

        using var client = await SignInAsync(SafeVaultFactory.AdminUsername, SafeVaultFactory.AdminPassword);
        await TestHttp.SetRoleAsync(client, admin.Id, Roles.User);

        // A one-click self-lockout is refused, so administration stays reachable.
        Assert.Equal(Roles.Admin, factory.RequireCredentials(SafeVaultFactory.AdminUsername).Role);
    }

    [Fact]
    public async Task OrdinaryUser_CannotOpenAnotherUsersItemPage()
    {
        factory.SeedUser("authz_owner", Password, Roles.User);
        factory.SeedUser("authz_other", Password, Roles.User);

        var owner = factory.RequireCredentials("authz_owner");
        var item = factory.SeedItem(owner.Id, "Owner only note", "Private.");

        using var client = await SignInAsync("authz_other", Password);
        var response = await client.GetAsync($"/Vault/Detail?id={item.Id}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task OrdinaryUser_CannotReadAnotherUsersItemThroughTheApi()
    {
        factory.SeedUser("authz_owner_api", Password, Roles.User);
        factory.SeedUser("authz_other_api", Password, Roles.User);

        var owner = factory.RequireCredentials("authz_owner_api");
        var item = factory.SeedItem(owner.Id, "Owner only api note", "Private.");

        using var client = await SignInAsync("authz_other_api", Password);

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/api/items/{item.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/api/items/{item.Id}/content")).StatusCode);
    }

    [Fact]
    public async Task ApiList_OnlyReturnsTheSignedInUsersItems()
    {
        factory.SeedUser("authz_list_a", Password, Roles.User);
        factory.SeedUser("authz_list_b", Password, Roles.User);

        var a = factory.RequireCredentials("authz_list_a");
        var b = factory.RequireCredentials("authz_list_b");
        factory.SeedItem(a.Id, "Alpha list marker", "a");
        factory.SeedItem(b.Id, "Bravo list marker", "b");

        using var client = await SignInAsync("authz_list_a", Password);
        var json = await client.GetStringAsync("/api/items");

        Assert.Contains("Alpha list marker", json);
        Assert.DoesNotContain("Bravo list marker", json);
    }

    [Fact]
    public async Task Administrator_CanReadAnyItem()
    {
        factory.SeedUser("authz_admin_view", Password, Roles.User);
        var owner = factory.RequireCredentials("authz_admin_view");
        var item = factory.SeedItem(owner.Id, "Admin review note", "Reviewed.");

        using var client = await SignInAsync(SafeVaultFactory.AdminUsername, SafeVaultFactory.AdminPassword);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/Vault/Detail?id={item.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/api/items/{item.Id}")).StatusCode);
    }

    [Fact]
    public async Task OrdinaryUser_CannotDeleteAnotherUsersItem()
    {
        factory.SeedUser("authz_delete_owner", Password, Roles.User);
        factory.SeedUser("authz_delete_other", Password, Roles.User);

        var owner = factory.RequireCredentials("authz_delete_owner");
        var item = factory.SeedItem(owner.Id, "Delete protection note", "Keep me.");

        using var client = await SignInAsync("authz_delete_other", Password);
        var response = await TestHttp.DeleteItemAsync(client, item.Id);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(factory.RequireItem(item.Id));
    }
}
