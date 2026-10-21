using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

namespace SafeVault.Web.Pages.Account;

[AllowAnonymous]
public sealed class RegisterModel : PageModel
{
    private readonly UserRepository _users;
    private readonly PasswordHasher _hasher;
    private readonly SignInService _authentication;
    private readonly ILogger<RegisterModel> _logger;

    public RegisterModel(
        UserRepository users,
        PasswordHasher hasher,
        SignInService authentication,
        ILogger<RegisterModel> logger)
    {
        _users = users;
        _hasher = hasher;
        _authentication = authentication;
        _logger = logger;
    }

    [BindProperty]
    public RegisterInput Input { get; set; } = new();

    public IReadOnlyList<string> Errors { get; private set; } = Array.Empty<string>();

    public IActionResult OnGet()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToPage("/Vault/Index");
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var username = Input.Username?.Trim() ?? string.Empty;

        var usernameCheck = InputValidator.ValidateUsername(username);
        var passwordCheck = InputValidator.ValidatePassword(Input.Password, username);

        var errors = new List<string>();
        errors.AddRange(usernameCheck.Errors);
        errors.AddRange(passwordCheck.Errors);

        if (!string.Equals(Input.Password, Input.ConfirmPassword, StringComparison.Ordinal))
        {
            errors.Add("The passwords do not match.");
        }

        if (errors.Count == 0 && _users.UsernameExists(username))
        {
            errors.Add("That username is already taken.");
        }

        if (errors.Count > 0)
        {
            Errors = errors;
            return Page();
        }

        User created;
        try
        {
            created = _users.Create(username, _hasher.Hash(Input.Password!), Roles.User);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            // The unique index is the real guard against two simultaneous registrations.
            Errors = ["That username is already taken."];
            return Page();
        }

        _logger.LogInformation("Registered new user {Username}", created.Username);

        // New accounts always start as ordinary users; only an administrator can grant Admin.
        await _authentication.SignInAsync(HttpContext, created.Id, created.Username, created.Role);
        return RedirectToPage("/Vault/Index");
    }
}

public sealed class RegisterInput
{
    public string? Username { get; set; }

    public string? Password { get; set; }

    public string? ConfirmPassword { get; set; }
}
