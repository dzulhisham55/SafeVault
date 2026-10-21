using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SafeVault.Web.Pages.Account;

[AllowAnonymous]
public sealed class DeniedModel : PageModel
{
    public void OnGet()
    {
    }
}
