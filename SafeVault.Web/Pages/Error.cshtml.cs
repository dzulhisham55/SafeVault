using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SafeVault.Web.Pages;

[AllowAnonymous]
public sealed class ErrorModel : PageModel
{
    public void OnGet()
    {
    }
}
