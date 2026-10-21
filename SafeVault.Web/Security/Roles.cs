namespace SafeVault.Web.Security;

public static class Roles
{
    public const string Admin = "Admin";
    public const string User = "User";

    public static readonly string[] All = [Admin, User];

    public static bool IsKnown(string? role) => role is not null && All.Contains(role, StringComparer.Ordinal);
}
