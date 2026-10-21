using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Web.Data;
using SafeVault.Web.Security;

namespace SafeVault.Web.Pages.Account;

[AllowAnonymous]
public sealed class LoginModel : PageModel
{
    private readonly UserRepository _users;
    private readonly PasswordHasher _hasher;
    private readonly LoginThrottle _throttle;
    private readonly SignInService _authentication;
    private readonly ILogger<LoginModel> _logger;

    public LoginModel(
        UserRepository users,
        PasswordHasher hasher,
        LoginThrottle throttle,
        SignInService authentication,
        ILogger<LoginModel> logger)
    {
        _users = users;
        _hasher = hasher;
        _throttle = throttle;
        _authentication = authentication;
        _logger = logger;
    }

    [BindProperty]
    public LoginInput Input { get; set; } = new();

    [BindProperty]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; private set; }

    public IActionResult OnGet(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToPage("/Vault/Index");
        }

        ReturnUrl = returnUrl;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var username = Input.Username?.Trim() ?? string.Empty;
        var throttleKey = ThrottleKey(username);

        if (_throttle.RemainingLockout(throttleKey) is TimeSpan remaining)
        {
            return Fail($"Too many failed attempts. Try again in {Math.Ceiling(remaining.TotalSeconds)} seconds.");
        }

        if (username.Length == 0 || string.IsNullOrEmpty(Input.Password))
        {
            return Fail("Enter your username and password.");
        }

        var credentials = _users.FindCredentialsByUsername(username);

        bool verified;
        if (credentials is null)
        {
            // Perform the same hashing work as the real path so that a missing account is not
            // measurably faster to reject than a wrong password.
            _hasher.Verify(Input.Password, _hasher.DummyHash);
            verified = false;
        }
        else
        {
            verified = _hasher.Verify(Input.Password, credentials.PasswordHash);
        }

        if (credentials is null || !verified)
        {
            _throttle.RegisterFailure(throttleKey);
            _logger.LogWarning(
                "Failed sign-in for {Username} from {Address}",
                username,
                HttpContext.Connection.RemoteIpAddress);

            // One message for "no such user" and "wrong password": the response must not
            // tell an attacker which usernames exist.
            return Fail("Username or password is incorrect.");
        }

        _throttle.Reset(throttleKey);
        await _authentication.SignInAsync(HttpContext, credentials.Id, credentials.Username, credentials.Role);
        _logger.LogInformation("Sign-in succeeded for {Username}", credentials.Username);

        // Only a local path is honoured; anything else falls back to the vault.
        return !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl)
            ? Redirect(ReturnUrl)
            : RedirectToPage("/Vault/Index");
    }

    private string ThrottleKey(string username) =>
        $"{username.ToLowerInvariant()}|{HttpContext.Connection.RemoteIpAddress}";

    private IActionResult Fail(string message)
    {
        ErrorMessage = message;

        // Do not echo the submitted password back into the form.
        ModelState.Remove($"{nameof(Input)}.{nameof(LoginInput.Password)}");
        Input.Password = null;

        return Page();
    }
}

public sealed class LoginInput
{
    [Required(ErrorMessage = "Enter your username.")]
    [StringLength(InputValidator.UsernameMaxLength)]
    public string? Username { get; set; }

    [Required(ErrorMessage = "Enter your password.")]
    [StringLength(InputValidator.PasswordMaxLength)]
    public string? Password { get; set; }
}
