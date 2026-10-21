using System.Globalization;
using System.Security.Claims;

namespace SafeVault.Web.Security;

public static class ClaimsPrincipalExtensions
{
    public static long? GetUserId(this ClaimsPrincipal principal) =>
        long.TryParse(
            principal.FindFirstValue(ClaimTypes.NameIdentifier),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var id)
            ? id
            : null;

    public static string? GetUsername(this ClaimsPrincipal principal) =>
        principal.FindFirstValue(ClaimTypes.Name);

    public static string? GetRole(this ClaimsPrincipal principal) =>
        principal.FindFirstValue(ClaimTypes.Role);

    public static bool IsAdmin(this ClaimsPrincipal principal) =>
        principal.IsInRole(Roles.Admin);

    public static bool CanAccess(this ClaimsPrincipal principal, long ownerId) =>
        principal.GetUserId() == ownerId || principal.IsAdmin();
}
