using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

namespace SafeVault.Web.Pages.Vault;

[Authorize]
public sealed class DetailModel(VaultItemRepository items) : PageModel
{
    public VaultItem Item { get; private set; } = null!;

    public IActionResult OnGet(long id)
    {
        if (User.GetUserId() is null)
        {
            return Challenge();
        }

        var item = items.GetById(id);

        // Another user's item answers 404 rather than 403: "forbidden" would confirm the id
        // exists, which is exactly what an enumeration attempt is asking for.
        if (item is null || !User.CanAccess(item.OwnerId))
        {
            return NotFound();
        }

        Item = item;
        return Page();
    }
}
