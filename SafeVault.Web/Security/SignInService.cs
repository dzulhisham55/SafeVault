using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace SafeVault.Web.Security;

/// <summary>
/// Builds the claims principal and issues the cookie. The role claim is what the authorization
/// layer reads, so it is written only from the stored user record, never from request data.
/// </summary>
public sealed class SignInService
{
    public async Task SignInAsync(HttpContext context, long userId, string username, string role)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString(CultureInfo.InvariantCulture)),
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Role, role),
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = false,
                AllowRefresh = true,
            });
    }

    public Task SignOutAsync(HttpContext context) =>
        context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
}
