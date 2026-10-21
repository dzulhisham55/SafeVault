using System.Net;
using SafeVault.Web.Security;
using Xunit;

namespace SafeVault.Tests;

public sealed class ValidationTests(SafeVaultFactory factory) : IClassFixture<SafeVaultFactory>
{
    private const string Password = "Str0ng!Passphrase#1";

    [Theory]
    [InlineData("ab")]
    [InlineData("has space")]
    [InlineData("semi;colon")]
    [InlineData("quote'name")]
    [InlineData("dash-name")]
    public void Username_RulesRejectUnsafeValues(string username)
    {
        Assert.False(InputValidator.ValidateUsername(username).IsValid);
    }

    [Theory]
    [InlineData("valid_name")]
    [InlineData("User123")]
    [InlineData("a_b_c")]
    public void Username_RulesAcceptValidValues(string username)
    {
        Assert.True(InputValidator.ValidateUsername(username).IsValid);
    }

    [Fact]
    public void Username_IsLimitedToTheDocumentedLength()
    {
        Assert.False(InputValidator.ValidateUsername(new string('a', InputValidator.UsernameMaxLength + 1)).IsValid);
        Assert.True(InputValidator.ValidateUsername(new string('a', InputValidator.UsernameMaxLength)).IsValid);
    }

    [Theory]
    [InlineData("Short1!")]                    // under 12 characters
    [InlineData("alllowercase!123")]           // no upper case
    [InlineData("ALLUPPERCASE!123")]           // no lower case
    [InlineData("NoDigitsHere!!")]             // no digit
    [InlineData("NoSymbolsHere123")]           // no symbol
    public void Password_RulesRejectWeakValues(string password)
    {
        Assert.False(InputValidator.ValidatePassword(password, "someone").IsValid);
    }

    [Fact]
    public void Password_RulesAcceptAStrongValue()
    {
        Assert.True(InputValidator.ValidatePassword(Password, "someone").IsValid);
    }

    [Fact]
    public void Password_ContainingTheUsername_IsRejected()
    {
        var result = InputValidator.ValidatePassword("Alice!IsHere#2026", "alice");

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("username", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Item_RulesRejectOversizedContent()
    {
        var result = InputValidator.ValidateItem("Title", new string('x', InputValidator.ContentMaxLength + 1));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Item_RulesRejectControlCharacters()
    {
        Assert.False(InputValidator.ValidateItem("Title", "bell\u0007here").IsValid);
        Assert.False(InputValidator.ValidateItem("ti\u0000tle", "body").IsValid);
    }

    [Fact]
    public void Item_RulesAllowMarkup_SoThatEncodingHappensOnOutputOnly()
    {
        // Stripping HTML on input is not the fix for XSS: the text is stored as typed and
        // encoded when it is written into a page (see XssTests).
        Assert.True(InputValidator.ValidateItem("A <b>title</b>", "<script>alert(1)</script>").IsValid);
    }

    [Fact]
    public void Search_RulesRejectOversizedTerms()
    {
        Assert.False(InputValidator.ValidateSearch(new string('q', InputValidator.SearchMaxLength + 1)).IsValid);
        Assert.True(InputValidator.ValidateSearch("normal term").IsValid);
    }

    [Fact]
    public async Task Registration_WithAWeakPassword_IsRejectedAndNoAccountIsCreated()
    {
        using var client = factory.CreateApiClient();

        var response = await TestHttp.RegisterAsync(client, "weakling", "short");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("at least 12 characters", html);
        Assert.Throws<InvalidOperationException>(() => factory.RequireCredentials("weakling"));
    }

    [Fact]
    public async Task Registration_WithADuplicateUsername_IsRejectedCaseInsensitively()
    {
        using var firstClient = factory.CreateApiClient();
        var first = await TestHttp.RegisterAsync(firstClient, "Duplicate_Name", Password);
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);

        using var secondClient = factory.CreateApiClient();
        var second = await TestHttp.RegisterAsync(secondClient, "duplicate_name", Password);
        var html = await second.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Contains("already taken", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Registration_CreatesAUserRoleAccount()
    {
        using var client = factory.CreateApiClient();

        var response = await TestHttp.RegisterAsync(client, "role_default", Password);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(Roles.User, factory.RequireCredentials("role_default").Role);
    }

    [Fact]
    public async Task CreateItem_WithOversizedContent_IsRejectedAndNothingIsStored()
    {
        factory.SeedUser("valid_size", Password);
        using var client = factory.CreateApiClient();
        await TestHttp.LoginAsync(client, "valid_size", Password);

        var before = factory.CountItems();
        var response = await TestHttp.CreateItemAsync(client, "Oversized", new string('x', 10_001));
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("at most 10000 characters", html);
        Assert.Equal(before, factory.CountItems());
    }

    [Fact]
    public async Task CreateItem_WithControlCharacters_IsRejected()
    {
        factory.SeedUser("valid_control", Password);
        using var client = factory.CreateApiClient();
        await TestHttp.LoginAsync(client, "valid_control", Password);

        var before = factory.CountItems();
        var response = await TestHttp.CreateItemAsync(client, "Bell", "ring\u0007");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before, factory.CountItems());
    }

    [Fact]
    public async Task CreateItem_WithValidInput_IsStoredAndListed()
    {
        factory.SeedUser("valid_create", Password);
        using var client = factory.CreateApiClient();
        await TestHttp.LoginAsync(client, "valid_create", Password);

        var response = await TestHttp.CreateItemAsync(client, "Quarterly plan", "Numbers and dates.");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        var list = await client.GetStringAsync("/Vault");
        Assert.Contains("Quarterly plan", list);
        Assert.Contains("Numbers and dates.", list);
    }
}
