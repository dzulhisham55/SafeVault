using SafeVault.Web.Security;
using Xunit;

namespace SafeVault.Tests;

public sealed class PasswordHashingTests
{
    private const string Password = "Str0ng!Passphrase#1";
    private readonly PasswordHasher _hasher = new();

    [Fact]
    public void Hash_DoesNotContainThePassword()
    {
        var hash = _hasher.Hash(Password);

        Assert.DoesNotContain(Password, hash);
        Assert.NotEqual(Password, hash);
        Assert.StartsWith("v1$", hash);
    }

    [Fact]
    public void Hash_RecordsItsVersionIterationsAndSalt()
    {
        var parts = _hasher.Hash(Password).Split('$');

        Assert.Equal(4, parts.Length);
        Assert.Equal("v1", parts[0]);
        Assert.Equal(PasswordHasher.DefaultIterations.ToString(), parts[1]);
        Assert.True(Convert.FromBase64String(parts[2]).Length >= 16);
        Assert.True(Convert.FromBase64String(parts[3]).Length >= 32);
    }

    [Fact]
    public void Hash_UsesAFreshSaltEachTime()
    {
        Assert.NotEqual(_hasher.Hash(Password), _hasher.Hash(Password));
    }

    [Fact]
    public void Verify_AcceptsTheCorrectPassword()
    {
        Assert.True(_hasher.Verify(Password, _hasher.Hash(Password)));
    }

    [Theory]
    [InlineData("Str0ng!Passphrase#2")]
    [InlineData("str0ng!passphrase#1")]
    [InlineData("")]
    public void Verify_RejectsWrongPasswords(string candidate)
    {
        Assert.False(_hasher.Verify(candidate, _hasher.Hash(Password)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("plain-text")]
    [InlineData("v1$1000$not-base64$not-base64")]
    [InlineData("v2$210000$c2FsdA==$aGFzaA==")]
    [InlineData("v1$210000$c2FsdA==")]
    public void Verify_RejectsMalformedStoredValues(string stored)
    {
        Assert.False(_hasher.Verify(Password, stored));
    }

    [Fact]
    public void Verify_RejectsAbsurdIterationCounts()
    {
        // A stored value claiming ten billion iterations would otherwise be a denial of
        // service handed to whoever can write to the table.
        Assert.False(_hasher.Verify(Password, "v1$10000000000$c2FsdA==$aGFzaA=="));
    }

    [Fact]
    public void StoredPassword_IsHashedNotPlainText()
    {
        using var factory = new SafeVaultFactory();
        factory.SeedUser("hash_check", Password);

        var stored = factory.ReadStoredPasswordHash("hash_check");

        Assert.NotEqual(Password, stored);
        Assert.DoesNotContain(Password, stored);
        Assert.StartsWith("v1$", stored);
    }
}
