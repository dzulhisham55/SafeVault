using SafeVault.Web.Security;
using Xunit;

namespace SafeVault.Tests;

public sealed class HtmlOutputTests
{
    [Theory]
    [InlineData("<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;")]
    [InlineData("\"quoted\"", "&quot;quoted&quot;")]
    [InlineData("a & b", "a &amp; b")]
    public void Encode_NeutralisesMarkup(string input, string expected)
    {
        Assert.Equal(expected, HtmlOutput.Encode(input));
    }

    [Fact]
    public void Encode_TreatsNullAsEmpty()
    {
        Assert.Equal(string.Empty, HtmlOutput.Encode(null));
    }

    [Fact]
    public void Highlight_WithoutATerm_ReturnsEncodedText()
    {
        var html = HtmlOutput.Highlight("<b>bold</b>", null).ToString();

        Assert.Equal("&lt;b&gt;bold&lt;/b&gt;", html);
    }

    [Fact]
    public void Highlight_WrapsEveryMatch()
    {
        var html = HtmlOutput.Highlight("note note NOTE", "note").ToString();

        Assert.Equal("<mark>note</mark> <mark>note</mark> <mark>NOTE</mark>", html);
    }

    [Fact]
    public void Highlight_EncodesTheTermAsWell()
    {
        // "<scr" is encoded to "&lt;scr" before matching, so the mark wraps encoded text.
        var html = HtmlOutput.Highlight("<script>", "<scr").ToString();

        Assert.Equal("<mark>&lt;scr</mark>ipt&gt;", html);
    }
}
