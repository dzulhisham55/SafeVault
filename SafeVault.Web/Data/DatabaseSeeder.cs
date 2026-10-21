using SafeVault.Web.Security;

namespace SafeVault.Web.Data;

/// <summary>
/// Creates the first administrator. Outside Development the password must be supplied by
/// configuration (normally <c>SafeVault__SeedAdminPassword</c>); there is no built-in
/// production credential.
/// </summary>
public static class DatabaseSeeder
{
    public const string DefaultAdminUsername = "admin";
    public const string DevelopmentDefaultPassword = "ChangeMe!2026#Root";

    public static void EnsureAdministrator(
        IServiceProvider services,
        IConfiguration configuration,
        IHostEnvironment environment,
        ILogger logger)
    {
        using var scope = services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserRepository>();

        if (users.Count() > 0)
        {
            return;
        }

        var hasher = scope.ServiceProvider.GetRequiredService<PasswordHasher>();

        var username = configuration["SafeVault:SeedAdminUsername"];
        if (string.IsNullOrWhiteSpace(username))
        {
            username = DefaultAdminUsername;
        }

        var usernameCheck = InputValidator.ValidateUsername(username);
        if (!usernameCheck.IsValid)
        {
            throw new InvalidOperationException(
                $"SafeVault:SeedAdminUsername '{username}' is not a valid username: {string.Join(" ", usernameCheck.Errors)}");
        }

        var password = configuration["SafeVault:SeedAdminPassword"];
        var usingDevelopmentDefault = false;

        if (string.IsNullOrWhiteSpace(password))
        {
            if (!environment.IsDevelopment())
            {
                throw new InvalidOperationException(
                    "SafeVault:SeedAdminPassword must be configured before the first non-development start.");
            }

            password = DevelopmentDefaultPassword;
            usingDevelopmentDefault = true;
        }

        var passwordCheck = InputValidator.ValidatePassword(password, username);
        if (!passwordCheck.IsValid && !usingDevelopmentDefault)
        {
            throw new InvalidOperationException(
                "SafeVault:SeedAdminPassword does not meet the password policy: " + string.Join(" ", passwordCheck.Errors));
        }

        users.Create(username.Trim(), hasher.Hash(password), Roles.Admin);
        logger.LogWarning(
            "Seeded the initial administrator '{Username}'. {Detail}",
            username,
            usingDevelopmentDefault
                ? "The development default password is in use; set SafeVault__SeedAdminPassword to override it."
                : "The password came from configuration.");
    }
}
