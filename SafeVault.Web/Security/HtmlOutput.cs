using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;

namespace SafeVault.Web.Security;

/// <summary>
/// Output encoding. Razor encodes <c>@value</c> automatically; these helpers exist for the
/// one case that needs both encoding and markup: highlighting a search term.
/// </summary>
public static class HtmlOutput
{
    /// <summary>HTML-encodes text for an element context. Null becomes an empty string.</summary>
    public static string Encode(string? value) => HtmlEncoder.Default.Encode(value ?? string.Empty);

    /// <summary>
    /// Returns HTML with every occurrence of <paramref name="term"/> wrapped in
    /// <c>&lt;mark&gt;</c>. The text is encoded <em>first</em> and the match is then looked for
    /// in the encoded string, so no character from the input can reach the browser as markup.
    ///
    /// The result is an <see cref="IHtmlContent"/> because Razor must not encode the
    /// <c>&lt;mark&gt;</c> tags a second time. Encoding already happened above; nothing that
    /// reaches this method is written to the response raw.
    /// </summary>
    public static IHtmlContent Highlight(string? text, string? term)
    {
        var encoded = Encode(text);
        var needle = Encode(term?.Trim());

        if (needle.Length == 0)
        {
            return new HtmlString(encoded);
        }

        var builder = new StringBuilder(encoded.Length + 16);
        var index = 0;

        while (index < encoded.Length)
        {
            var found = encoded.IndexOf(needle, index, StringComparison.OrdinalIgnoreCase);
            if (found < 0)
            {
                break;
            }

            builder.Append(encoded, index, found - index)
                .Append("<mark>")
                .Append(encoded, found, needle.Length)
                .Append("</mark>");

            index = found + needle.Length;
        }

        builder.Append(encoded, index, encoded.Length - index);
        return new HtmlString(builder.ToString());
    }
}
