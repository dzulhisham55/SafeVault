using System.Globalization;
using System.Security.Cryptography;

namespace SafeVault.Web.Security;

/// <summary>
/// PBKDF2-HMAC-SHA256 password hashing. The stored value carries its own algorithm version,
/// iteration count and salt, so the cost can be raised later without invalidating hashes.
/// Format: <c>v1$iterations$base64(salt)$base64(key)</c>.
/// </summary>
public sealed class PasswordHasher
{
    public const int DefaultIterations = 210_000;
    private const byte FormatVersion = 1;
    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int MinimumAcceptedIterations = 10_000;
    private const int MaximumAcceptedIterations = 2_000_000;

    private readonly Lazy<string> _dummyHash;

    public PasswordHasher()
    {
        _dummyHash = new Lazy<string>(() => Hash("timing-equalisation-placeholder"));
    }

    /// <summary>
    /// Verified against when no user matches, so a missing account costs roughly the same
    /// time as a wrong password and cannot be detected from response timing.
    /// </summary>
    public string DummyHash => _dummyHash.Value;

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            DefaultIterations,
            HashAlgorithmName.SHA256,
            KeySize);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"v{FormatVersion}${DefaultIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(key)}");
    }

    /// <summary>Constant-time verification. Returns false for any malformed stored value.</summary>
    public bool Verify(string password, string storedHash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        var parts = storedHash.Split('$');
        if (parts.Length != 4 || parts[0] != $"v{FormatVersion}")
        {
            return false;
        }

        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
            || iterations < MinimumAcceptedIterations
            || iterations > MaximumAcceptedIterations)
        {
            return false;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length < 8 || expected.Length == 0)
        {
            return false;
        }

        var candidate = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expected.Length);

        return CryptographicOperations.FixedTimeEquals(candidate, expected);
    }
}
