using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Weep.Protocol;

namespace Weep.Server.Auth;

public sealed record AuthResult(string Username, IReadOnlyList<string> Roles);

/// <summary>
/// Server-side auth handler.
/// Supports auth:scram-sha256 (mutual) using PBKDF2 + HMAC-SHA256.
/// </summary>
public sealed class ServerAuthHandler(
    Func<string, Task> sendJson,
    UserStore          store,
    string             serverNonce)
{
    // Pending state for auth:scram-sha256 (username -> ScramState)
    private readonly Dictionary<string, ScramState> _pendingScram      = new();

    private sealed record ScramState(string CombinedNonce, string SharedKey);

    public async Task<AuthResult?> HandleAsync(JsonObject payload, int msgno)
    {
        var mechanism = payload["mechanism"]?.GetValue<string>() ?? "";
        return mechanism switch
        {
            "auth:scram-sha256" => await ScramAsync(payload, msgno),
            _ => await RejectAsync(msgno, 400, "Unsupported mechanism; use auth:scram-sha256"),
        };
    }

    // ------------------------------------------------------------------
    // auth:scram-sha256  (mutual two-step — both sides prove identity)
    //
    // Key derivation (both sides compute identical values if pw correct):
    //   pdk         = PBKDF2-SHA256(password, salt, iterations, 32)
    //   combinedNonce = serverNonce + clientNonce
    //   sharedKey     = HMAC-SHA256(pdk, combinedNonce)
    //   serverProof   = HMAC-SHA256(sharedKey, "server:" + combinedNonce)
    //   clientProof   = HMAC-SHA256(sharedKey, "client:" + combinedNonce)
    // ------------------------------------------------------------------

    private async Task<AuthResult?> ScramAsync(JsonObject payload, int msgno)
    {
        var username    = payload["username"]?.GetValue<string>() ?? "";
        var clientNonce = payload["clientNonce"]?.GetValue<string>();
        var clientProof = payload["clientProof"]?.GetValue<string>();

        if (string.IsNullOrEmpty(username))
            return await RejectAsync(msgno, 400, "username required");

        if (clientProof is null)
        {
            // ── Step 1: receive clientNonce, send combinedNonce + serverProof ──
            if (string.IsNullOrEmpty(clientNonce))
                return await RejectAsync(msgno, 400, "clientNonce required");

            var user = store.GetUser(username);
            if (user is null)
                return await RejectAsync(msgno, 401, "Invalid credentials");

            var combinedNonce = serverNonce + clientNonce;
            var sharedKey     = ComputeHmacHex(user.PasswordKey, combinedNonce);
            var srvProof      = ComputeHmacHex(sharedKey, "server:" + combinedNonce);

            _pendingScram[username] = new ScramState(combinedNonce, sharedKey);

            await sendJson(new JsonObject
            {
                ["type"]    = MsgType.RPY.ToString(),
                ["channel"] = 0,
                ["msgno"]   = msgno,
                ["payload"] = new JsonObject
                {
                    ["combinedNonce"] = combinedNonce,
                    ["serverProof"]   = srvProof,
                    ["salt"]          = user.PasswordSalt,
                    ["iterations"]    = user.PasswordIterations,
                },
            }.ToJsonString());
            return null;
        }

        // ── Step 2: verify clientProof ──
        if (!_pendingScram.Remove(username, out var state))
            return await RejectAsync(msgno, 400, "No pending SCRAM exchange");

        var user2 = store.GetUser(username);
        if (user2 is null)
            return await RejectAsync(msgno, 401, "Invalid credentials");

        var expectedProof = ComputeHmacHex(state.SharedKey, "client:" + state.CombinedNonce);
        if (!FixedHexEquals(expectedProof, clientProof))
            return await RejectAsync(msgno, 401, "Invalid credentials");

        await SendOkAsync(msgno, user2);
        return new AuthResult(user2.Username, user2.Roles);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private async Task SendOkAsync(int msgno, User user)
    {
        var roles = new JsonArray(user.Roles.Select(r => JsonValue.Create(r)).ToArray());
        await sendJson(new JsonObject
        {
            ["type"]    = MsgType.RPY.ToString(),
            ["channel"] = 0,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["ok"]       = true,
                ["username"] = user.Username,
                ["roles"]    = roles,
            },
        }.ToJsonString());
    }

    private async Task<AuthResult?> RejectAsync(int msgno, int code, string message)
    {
        await sendJson(MessageFactory.Error(0, msgno, code, message));
        return null;
    }

    private static string ComputeHmacHex(string keyHex, string input)
    {
        var keyBytes = Convert.FromHexString(keyHex);
        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool FixedHexEquals(string leftHex, string rightHex)
    {
        try
        {
            var left = Convert.FromHexString(leftHex);
            var right = Convert.FromHexString(rightHex);
            return CryptographicOperations.FixedTimeEquals(left, right);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
