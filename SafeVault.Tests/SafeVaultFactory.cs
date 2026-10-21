using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

namespace SafeVault.Tests;

/// <summary>
/// Boots the real application (real pipeline, real SQLite, real authentication) against a
/// throwaway database file, so tests exercise the same code paths a browser would hit.
/// </summary>
public sealed class SafeVaultFactory : WebApplicationFactory<Program>
{
    public const string AdminUsername = "admin";
    public const string AdminPassword = "Vault!Keeper#2026";

    private readonly string _databasePath =
        Path.Combine(Path.GetTempPath(), $"safevault-tests-{Guid.NewGuid():N}.db");

    public string DatabasePath => _databasePath;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SafeVault:DatabasePath"] = _databasePath,
                ["SafeVault:SeedAdminUsername"] = AdminUsername,
                ["SafeVault:SeedAdminPassword"] = AdminPassword,
                ["SafeVault:HttpsRedirection"] = "false",
            });
        });
    }

    public HttpClient CreateApiClient() => CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        HandleCookies = true,
        BaseAddress = new Uri("https://localhost"),
    });

    public void SeedUser(string username, string password, string role = Roles.User)
    {
        using var scope = Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserRepository>();
        var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher>();
        users.Create(username, hasher.Hash(password), role);
    }

    public VaultItem SeedItem(long ownerId, string title, string content)
    {
        using var scope = Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<VaultItemRepository>().Create(ownerId, title, content);
    }

    public UserCredentials RequireCredentials(string username)
    {
        using var scope = Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserRepository>();
        return users.FindCredentialsByUsername(username)
            ?? throw new InvalidOperationException($"No user named '{username}'.");
    }

    public IReadOnlyList<VaultItem> ItemsFor(long ownerId)
    {
        using var scope = Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<VaultItemRepository>().ListForOwner(ownerId, null);
    }

    public VaultItem RequireItem(long id)
    {
        using var scope = Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<VaultItemRepository>().GetById(id)
            ?? throw new InvalidOperationException($"No item with id {id}.");
    }

    public int CountItems()
    {
        using var scope = Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<VaultItemRepository>().CountAll();
    }

    public string ReadStoredPasswordHash(string username)
    {
        using var connection = new SqliteConnection($"Data Source={_databasePath}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT PasswordHash FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", username);
        return (string)command.ExecuteScalar()!;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { string.Empty, "-shm", "-wal" })
        {
            try
            {
                File.Delete(_databasePath + suffix);
            }
            catch (IOException)
            {
                // A leftover temp file is harmless; never fail a test run over cleanup.
            }
        }
    }
}
