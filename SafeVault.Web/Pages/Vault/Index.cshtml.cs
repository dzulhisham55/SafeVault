using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

namespace SafeVault.Web.Pages.Vault;

[Authorize]
public sealed class IndexModel(VaultItemRepository items) : PageModel
{
    public IReadOnlyList<VaultItem> Items { get; private set; } = Array.Empty<VaultItem>();

    [BindProperty]
    public string? Title { get; set; }

    [BindProperty]
    public string? Body { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Q { get; set; }

    public string? SearchError { get; private set; }

    public IActionResult OnGet()
    {
        if (User.GetUserId() is not long userId)
        {
            return Challenge();
        }

        var search = InputValidator.ValidateSearch(Q);
        if (!search.IsValid)
        {
            SearchError = string.Join(" ", search.Errors);
            Q = null;
        }

        Load(userId, SearchError is null ? Q : null);
        return Page();
    }

    public IActionResult OnPostCreate()
    {
        if (User.GetUserId() is not long userId)
        {
            return Challenge();
        }

        var validation = InputValidator.ValidateItem(Title, Body);
        if (!validation.IsValid)
        {
            foreach (var error in validation.Errors)
            {
                ModelState.AddModelError(string.Empty, error);
            }

            Load(userId, search: null);
            return Page();
        }

        var created = items.Create(userId, Title!.Trim(), Body ?? string.Empty);
        TempData["Message"] = $"Saved \"{created.Title}\".";
        return RedirectToPage("/Vault/Index");
    }

    public IActionResult OnPostDelete(long id)
    {
        if (User.GetUserId() is not long userId)
        {
            return Challenge();
        }

        // Deleting is scoped to the owner in SQL: passing someone else's id changes nothing.
        var deleted = items.DeleteOwned(id, userId);
        TempData[deleted ? "Message" : "Error"] = deleted
            ? "Item deleted."
            : "That item does not belong to you.";

        return RedirectToPage("/Vault/Index");
    }

    /// <summary>Single-line snippet for the table, still untrusted text at this point.</summary>
    public static string Preview(string content)
    {
        var singleLine = content
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Trim();

        return singleLine.Length <= 90 ? singleLine : singleLine[..90] + "…";
    }

    private void Load(long userId, string? search) => Items = items.ListForOwner(userId, search);
}
