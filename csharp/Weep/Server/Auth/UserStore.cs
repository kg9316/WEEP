using System.Security.Cryptography;
using System.Text;  // UTF8 for HashPassword

namespace Weep.Server.Auth;

public sealed record User(
    string Username,
    string PasswordSalt,
    int PasswordIterations,
    string PasswordKey,
    IReadOnlyList<string> Roles);

/// <summary>
/// In-memory user store.  Swap out for DB-backed implementation in production.
/// Passwords stored as PBKDF2-SHA256 derived key + salt + iterations.
/// </summary>
public sealed class UserStore
{
    private const int DefaultIterations = 120_000;
    private const int KeySizeBytes = 32;

    private readonly Dictionary<string, User> _users = new();

    public void AddUser(string username, string password,
                         params string[] roles)
    {
        var (salt, iterations, key) = CreatePasswordKey(password);
        _users[username] = new User(username, salt, iterations, key,
                                    roles.Length > 0 ? roles : ["read"]);
    }

    public User? GetUser(string username) =>
        _users.GetValueOrDefault(username);

    private static (string Salt, int Iterations, string Key) CreatePasswordKey(string password)
    {
        var saltBytes = RandomNumberGenerator.GetBytes(16);
        var keyBytes = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            saltBytes,
            DefaultIterations,
            HashAlgorithmName.SHA256,
            KeySizeBytes);

        return (
            Convert.ToHexString(saltBytes).ToLowerInvariant(),
            DefaultIterations,
            Convert.ToHexString(keyBytes).ToLowerInvariant());
    }
}
