using System.Security.Cryptography;
using System.Text;  // UTF8 for HashPassword

namespace Weep.Server.Auth;

public sealed record User(string Username, string PasswordHash, IReadOnlyList<string> Roles);

/// <summary>
/// In-memory user store.  Swap out for DB-backed implementation in production.
/// Passwords stored as SHA-256 hex of the raw password.
/// </summary>
public sealed class UserStore
{
    private readonly Dictionary<string, User> _users = new();

    public void AddUser(string username, string password,
                         params string[] roles)
    {
        _users[username] = new User(username, HashPassword(password),
                                    roles.Length > 0 ? roles : ["read"]);
    }

    public User? GetUser(string username) =>
        _users.GetValueOrDefault(username);

    public static string HashPassword(string password) =>
        Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(password))
        ).ToLowerInvariant();
}
