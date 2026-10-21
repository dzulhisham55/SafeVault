using System.Globalization;
using Microsoft.Data.Sqlite;

namespace SafeVault.Web.Data;

public sealed record VaultItem(long Id, long OwnerId, string Title, string Content, DateTimeOffset CreatedUtc);

/// <summary>
/// Vault item access. Reads are scoped by owner inside the SQL statement itself
/// (<c>WHERE OwnerId = $ownerId</c>) so a caller cannot forget the check, and search terms
/// are parameters with LIKE wildcards escaped rather than concatenated.
/// </summary>
public sealed class VaultItemRepository(Database database)
{
    private const string ItemColumns = "Id, OwnerId, Title, Content, CreatedUtc";

    public VaultItem Create(long ownerId, string title, string content)
    {
        var createdUtc = DateTimeOffset.UtcNow;

        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO VaultItems (OwnerId, Title, Content, CreatedUtc)
            VALUES ($ownerId, $title, $content, $createdUtc);
            """;
        command.Parameters.AddWithValue("$ownerId", ownerId);
        command.Parameters.AddWithValue("$title", title);
        command.Parameters.AddWithValue("$content", content);
        command.Parameters.AddWithValue("$createdUtc", Database.ToStorage(createdUtc));
        command.ExecuteNonQuery();

        using var idCommand = connection.CreateCommand();
        idCommand.CommandText = "SELECT last_insert_rowid();";
        var id = (long)idCommand.ExecuteScalar()!;

        return new VaultItem(id, ownerId, title, content, createdUtc);
    }

    /// <summary>Unscoped lookup. Callers must apply the ownership rule themselves.</summary>
    public VaultItem? GetById(long id)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {ItemColumns} FROM VaultItems WHERE Id = $id LIMIT 1;";
        command.Parameters.AddWithValue("$id", id);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadItem(reader) : null;
    }

    public VaultItem? GetOwned(long id, long ownerId)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {ItemColumns} FROM VaultItems WHERE Id = $id AND OwnerId = $ownerId LIMIT 1;";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$ownerId", ownerId);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadItem(reader) : null;
    }

    public IReadOnlyList<VaultItem> ListForOwner(long ownerId, string? search)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();

        if (string.IsNullOrWhiteSpace(search))
        {
            command.CommandText =
                $"SELECT {ItemColumns} FROM VaultItems WHERE OwnerId = $ownerId ORDER BY CreatedUtc DESC, Id DESC;";
            command.Parameters.AddWithValue("$ownerId", ownerId);
        }
        else
        {
            // The term stays a parameter and the wildcards inside it are escaped, so a user
            // typing "%" searches for a percent sign instead of matching every row.
            command.CommandText = $"""
                SELECT {ItemColumns}
                FROM VaultItems
                WHERE OwnerId = $ownerId
                  AND (Title LIKE $pattern ESCAPE '\' OR Content LIKE $pattern ESCAPE '\')
                ORDER BY CreatedUtc DESC, Id DESC;
                """;
            command.Parameters.AddWithValue("$ownerId", ownerId);
            command.Parameters.AddWithValue("$pattern", "%" + EscapeLike(search.Trim()) + "%");
        }

        using var reader = command.ExecuteReader();
        var items = new List<VaultItem>();
        while (reader.Read())
        {
            items.Add(ReadItem(reader));
        }

        return items;
    }

    public IReadOnlyList<VaultItem> ListAll()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {ItemColumns} FROM VaultItems ORDER BY CreatedUtc DESC, Id DESC;";

        using var reader = command.ExecuteReader();
        var items = new List<VaultItem>();
        while (reader.Read())
        {
            items.Add(ReadItem(reader));
        }

        return items;
    }

    public bool DeleteOwned(long id, long ownerId)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM VaultItems WHERE Id = $id AND OwnerId = $ownerId;";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$ownerId", ownerId);
        return command.ExecuteNonQuery() > 0;
    }

    public int CountAll()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM VaultItems;";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    /// <summary>Neutralises LIKE metacharacters so the term is matched literally.</summary>
    public static string EscapeLike(string value) => value
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("%", "\\%", StringComparison.Ordinal)
        .Replace("_", "\\_", StringComparison.Ordinal);

    private static VaultItem ReadItem(SqliteDataReader reader) => new(
        reader.GetInt64(0),
        reader.GetInt64(1),
        reader.GetString(2),
        reader.GetString(3),
        Database.FromStorage(reader.GetString(4)));
}
