using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

namespace SafeVault.Web.Pages.Admin;

[Authorize(Roles = Roles.Admin)]
public sealed class IndexModel(UserRepository users, VaultItemRepository items) : PageModel
{
    public IReadOnlyList<User> Users { get; private set; } = Array.Empty<User>();

    public int ItemCount { get; private set; }

    public long? CurrentUserId => User.GetUserId();

    public IActionResult OnGet()
    {
        Load();
        return Page();
    }

    public IActionResult OnPostSetRole(long id, string? role)
    {
        if (!Roles.IsKnown(role))
        {
            return BadRequest("Unknown role.");
        }

        // Refuse to remove the last administrator's own access: a one-click lockout is a bug,
        // not a privilege change.
        if (User.GetUserId() == id)
        {
            TempData["Error"] = "You cannot change your own role. Ask another administrator.";
            return RedirectToPage();
        }

        var updated = users.UpdateRole(id, role!);
        TempData[updated ? "Message" : "Error"] = updated
            ? $"Role updated for user {id}."
            : $"No user with id {id} exists.";

        return RedirectToPage();
    }

    private void Load()
    {
        Users = users.ListAll();
        ItemCount = items.CountAll();
    }
}
