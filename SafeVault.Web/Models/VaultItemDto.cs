namespace SafeVault.Web.Models;

/// <summary>What the JSON API exposes. Never includes owner ids or password material.</summary>
public sealed record VaultItemDto(long Id, string Title, string Content, DateTimeOffset CreatedUtc);

public sealed record VaultItemListDto(int Count, IReadOnlyList<VaultItemDto> Items);

public sealed record UserSummaryDto(long Id, string Username, string Role, DateTimeOffset CreatedUtc);
