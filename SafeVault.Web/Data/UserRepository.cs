using System.Globalization;
using Microsoft.Data.Sqlite;

namespace SafeVault.Web.Data;

public sealed record User(long Id, string Username, string Role, DateTimeOffset CreatedUtc);

/// <summary>The only shape that carries a password hash; never bound to a view.</summary>
public sealed record UserCredentials(long Id, string Username, string PasswordHash, string Role);

/// <summary>
/// Every statement here is parameterised and every value travels as a
/// <see cref="SqliteParameter"/>. No SQL text is ever built from user input, which is what
/// makes a payload like <c>' OR '1'='1</c> a literal string instead of syntax.
/// </summary>
public sealed class UserRepository(Database database)
{
    private const string UserColumns = "Id, Username, Role, CreatedUtc";

    public UserCredentials? FindCredentialsByUsername(string username)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT Id, Username, PasswordHash, Role FROM Users WHERE Username = $username COLLATE NOCASE LIMIT 1;";
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new UserCredentials(
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3));
    }

    public User? FindById(long id)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {UserColumns} FROM Users WHERE Id = $id LIMIT 1;";
        command.Parameters.AddWithValue("$id", id);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    public bool UsernameExists(string username)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM Users WHERE Username = $username COLLATE NOCASE LIMIT 1;";
        command.Parameters.AddWithValue("$username", username);

        return command.ExecuteScalar() is not null;
    }

    public User Create(string username, string passwordHash, string role)
    {
        var createdUtc = DateTimeOffset.UtcNow;

        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, PasswordHash, Role, CreatedUtc)
            VALUES ($username, $passwordHash, $role, $createdUtc);
            """;
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$passwordHash", passwordHash);
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$createdUtc", Database.ToStorage(createdUtc));
        command.ExecuteNonQuery();

        using var idCommand = connection.CreateCommand();
        idCommand.CommandText = "SELECT last_insert_rowid();";
        var id = (long)idCommand.ExecuteScalar()!;

        return new User(id, username, role, createdUtc);
    }

    public IReadOnlyList<User> ListAll()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {UserColumns} FROM Users ORDER BY Username COLLATE NOCASE;";

        using var reader = command.ExecuteReader();
        var users = new List<User>();
        while (reader.Read())
        {
            users.Add(ReadUser(reader));
        }

        return users;
    }

    public int Count()
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM Users;";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    public bool UpdateRole(long id, string role)
    {
        using var connection = database.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Role = $role WHERE Id = $id;";
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$id", id);
        return command.ExecuteNonQuery() > 0;
    }

    private static User ReadUser(SqliteDataReader reader) => new(
        reader.GetInt64(0),
        reader.GetString(1),
        reader.GetString(2),
        Database.FromStorage(reader.GetString(3)));
}
