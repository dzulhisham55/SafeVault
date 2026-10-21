using System.Security.Claims;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Security;

namespace SafeVault.Web.Api;

/// <summary>
/// Read-only JSON API. Every route requires authentication, and every item route applies the
/// ownership rule from the claims principal rather than from a caller-supplied id.
/// </summary>
public static class VaultApi
{
    public static IEndpointRouteBuilder MapVaultApi(this IEndpointRouteBuilder endpoints)
    {
        var api = endpoints.MapGroup("/api").RequireAuthorization();

        api.MapGet("/items", (ClaimsPrincipal user, VaultItemRepository repository) =>
        {
            if (user.GetUserId() is not long userId)
            {
                return Results.Unauthorized();
            }

            var items = repository.ListForOwner(userId, search: null)
                .Select(ToDto)
                .ToList();

            return Results.Ok(new VaultItemListDto(items.Count, items));
        })
        .WithName("ListVaultItems");

        api.MapGet("/items/{id:long}", (long id, ClaimsPrincipal user, VaultItemRepository repository) =>
        {
            var item = FindAccessibleItem(id, user, repository);
            return item is null ? Results.NotFound() : Results.Ok(ToDto(item));
        })
        .WithName("GetVaultItem");

        api.MapGet("/items/{id:long}/content", (long id, ClaimsPrincipal user, VaultItemRepository repository) =>
        {
            var item = FindAccessibleItem(id, user, repository);

            // Served as text/plain with nosniff from the security headers, so a payload such
            // as <script>...</script> is displayed as characters and never parsed as HTML.
            return item is null
                ? Results.NotFound()
                : Results.Text(item.Content, "text/plain; charset=utf-8");
        })
        .WithName("GetVaultItemContent");

        return endpoints;
    }

    private static VaultItem? FindAccessibleItem(long id, ClaimsPrincipal user, VaultItemRepository repository)
    {
        if (user.GetUserId() is null)
        {
            return null;
        }

        var item = repository.GetById(id);

        // Someone else's item is reported as missing rather than forbidden, so ids cannot be
        // probed to discover which records exist.
        return item is not null && user.CanAccess(item.OwnerId) ? item : null;
    }

    private static VaultItemDto ToDto(VaultItem item) =>
        new(item.Id, item.Title, item.Content, item.CreatedUtc);
}
