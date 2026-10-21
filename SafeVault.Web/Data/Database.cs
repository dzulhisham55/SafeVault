using System.Globalization;
using Microsoft.Data.Sqlite;

namespace SafeVault.Web.Data;

/// <summary>
/// Owns the SQLite connection string, file creation and schema. Every caller receives an
/// open connection with foreign keys enforced.
/// </summary>
public sealed class Database
{
    private readonly ILogger<Database> _logger;
    private readonly string _connectionString;

    public Database(IConfiguration configuration, IHostEnvironment environment, ILogger<Database> logger)
    {
        _logger = logger;

        var configured = configuration["SafeVault:DatabasePath"];
        var path = string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(environment.ContentRootPath, "App_Data", "safevault.db")
            : Path.GetFullPath(configured);

        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        DatabasePath = path;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            ForeignKeys = true,
            Pooling = true,
            DefaultTimeout = 15,
        }.ToString();
    }

    public string DatabasePath { get; }

    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys = ON;";
        pragma.ExecuteNonQuery();

        return connection;
    }

    public void Initialize()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = Schema;
        command.ExecuteNonQuery();

        _logger.LogInformation("SafeVault schema ready at {DatabasePath}", DatabasePath);
    }

    /// <summary>ISO-8601 round-trip text, so ordering in SQL and parsing in C# agree.</summary>
    internal static string ToStorage(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    internal static DateTimeOffset FromStorage(string value) =>
        DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    // Users.Username is COLLATE NOCASE UNIQUE, so "Admin" and "admin" cannot both exist.
    // Roles are constrained at the storage layer as well as in code.
    private const string Schema = """
        CREATE TABLE IF NOT EXISTS Users (
            Id            INTEGER PRIMARY KEY AUTOINCREMENT,
            Username      TEXT    NOT NULL COLLATE NOCASE UNIQUE,
            PasswordHash  TEXT    NOT NULL,
            Role          TEXT    NOT NULL CHECK (Role IN ('Admin', 'User')),
            CreatedUtc    TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS VaultItems (
            Id         INTEGER PRIMARY KEY AUTOINCREMENT,
            OwnerId    INTEGER NOT NULL REFERENCES Users (Id) ON DELETE CASCADE,
            Title      TEXT    NOT NULL,
            Content    TEXT    NOT NULL,
            CreatedUtc TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS IX_VaultItems_OwnerId ON VaultItems (OwnerId);
        """;
}
