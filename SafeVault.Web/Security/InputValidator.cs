using System.Text.RegularExpressions;

namespace SafeVault.Web.Security;

public sealed record ValidationResult(bool IsValid, IReadOnlyList<string> Errors)
{
    public static readonly ValidationResult Success = new(true, Array.Empty<string>());

    public static ValidationResult Fail(params string[] errors) => new(false, errors);

    public static ValidationResult Fail(IEnumerable<string> errors) => new(false, errors.ToArray());
}

/// <summary>
/// Server-side validation. The browser's <c>maxlength</c> and <c>required</c> attributes are
/// a convenience for the user, never a control: every rule here runs again on the server for
/// every request, including requests that did not come from the form.
///
/// Note what is deliberately *not* done here: HTML is not stripped or escaped on input.
/// Stored text stays exactly what the user typed and is encoded on output instead, which is
/// the only place the encoding can be correct for the context it is written into.
/// </summary>
public static class InputValidator
{
    public const int UsernameMinLength = 3;
    public const int UsernameMaxLength = 32;
    public const int PasswordMinLength = 12;
    public const int PasswordMaxLength = 128;
    public const int TitleMinLength = 1;
    public const int TitleMaxLength = 100;
    public const int ContentMaxLength = 10_000;
    public const int SearchMaxLength = 100;

    private static readonly Regex UsernamePattern =
        new("^[A-Za-z0-9_]+$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));

    private static readonly Regex ControlCharacterPattern =
        new(@"[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));

    public static ValidationResult ValidateUsername(string? username)
    {
        var value = username?.Trim() ?? string.Empty;
        var errors = new List<string>();

        if (value.Length is < UsernameMinLength or > UsernameMaxLength)
        {
            errors.Add($"Username must be {UsernameMinLength}-{UsernameMaxLength} characters long.");
        }

        if (value.Length > 0 && !UsernamePattern.IsMatch(value))
        {
            errors.Add("Username may only contain letters, digits and underscores.");
        }

        return errors.Count == 0 ? ValidationResult.Success : ValidationResult.Fail(errors);
    }

    public static ValidationResult ValidatePassword(string? password, string? username)
    {
        var value = password ?? string.Empty;
        var errors = new List<string>();

        if (value.Length < PasswordMinLength)
        {
            errors.Add($"Password must be at least {PasswordMinLength} characters long.");
        }

        if (value.Length > PasswordMaxLength)
        {
            errors.Add($"Password must be at most {PasswordMaxLength} characters long.");
        }

        if (!value.Any(char.IsUpper))
        {
            errors.Add("Password must include an uppercase letter.");
        }

        if (!value.Any(char.IsLower))
        {
            errors.Add("Password must include a lowercase letter.");
        }

        if (!value.Any(char.IsDigit))
        {
            errors.Add("Password must include a digit.");
        }

        if (value.Length > 0 && value.All(char.IsLetterOrDigit))
        {
            errors.Add("Password must include a symbol.");
        }

        if (ControlCharacterPattern.IsMatch(value))
        {
            errors.Add("Password must not contain control characters.");
        }

        var trimmedUsername = username?.Trim();
        if (!string.IsNullOrEmpty(trimmedUsername)
            && value.Contains(trimmedUsername, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Password must not contain the username.");
        }

        return errors.Count == 0 ? ValidationResult.Success : ValidationResult.Fail(errors);
    }

    public static ValidationResult ValidateItem(string? title, string? content)
    {
        var trimmedTitle = title?.Trim() ?? string.Empty;
        var value = content ?? string.Empty;
        var errors = new List<string>();

        if (trimmedTitle.Length is < TitleMinLength or > TitleMaxLength)
        {
            errors.Add($"Title must be {TitleMinLength}-{TitleMaxLength} characters long.");
        }

        if (value.Length > ContentMaxLength)
        {
            errors.Add($"Content must be at most {ContentMaxLength} characters long.");
        }

        if (ControlCharacterPattern.IsMatch(trimmedTitle) || ControlCharacterPattern.IsMatch(value))
        {
            errors.Add("Title and content must not contain control characters.");
        }

        return errors.Count == 0 ? ValidationResult.Success : ValidationResult.Fail(errors);
    }

    public static ValidationResult ValidateSearch(string? query)
    {
        var value = query?.Trim() ?? string.Empty;
        var errors = new List<string>();

        if (value.Length > SearchMaxLength)
        {
            errors.Add($"Search terms must be at most {SearchMaxLength} characters long.");
        }

        if (ControlCharacterPattern.IsMatch(value))
        {
            errors.Add("Search terms must not contain control characters.");
        }

        return errors.Count == 0 ? ValidationResult.Success : ValidationResult.Fail(errors);
    }
}
