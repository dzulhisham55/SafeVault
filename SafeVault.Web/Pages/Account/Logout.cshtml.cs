using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Web.Security;

namespace SafeVault.Web.Pages.Account;

[Authorize]
public sealed class LogoutModel(SignInService authentication) : PageModel
{
    public IActionResult OnGet() => RedirectToPage("/Vault/Index");

    // POST only, with the antiforgery token Razor Pages requires by default, so a cross-site
    // image or link cannot sign the user out.
    public async Task<IActionResult> OnPostAsync()
    {
        await authentication.SignOutAsync(HttpContext);
        return RedirectToPage("/Account/Login");
    }
}
