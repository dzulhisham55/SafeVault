using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SafeVault.Web.Pages;

public sealed class IndexModel : PageModel
{
    public IActionResult OnGet() => User.Identity?.IsAuthenticated == true
        ? RedirectToPage("/Vault/Index")
        : RedirectToPage("/Account/Login");
}
