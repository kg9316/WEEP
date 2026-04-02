using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Weep.Protocol;

namespace Weep.Server.Auth;

public sealed record AuthResult(string Username, IReadOnlyList<string> Roles);

/// <summary>
/// Server-side auth handler.
/// Supports auth:challenge (legacy) and auth:scram-sha256 (mutual).
/// </summary>
public sealed class ServerAuthHandler(
    Func<string, Task> sendJson,
    UserStore          store,
    string             serverNonce)
{
    // Pending state for auth:challenge  (username → nonce)
    private readonly Dictionary<string, string>     _pendingChallenges = new();
    // Pending state for auth:scram-sha256 (username → ScramState)
    private readonly Dictionary<string, ScramState> _pendingScram      = new();

    private sealed record ScramState(string CombinedNonce, string SharedKey);

    public async Task<AuthResult?> HandleAsync(JsonObject payload, int msgno)
    {
        var mechanism = payload["mechanism"]?.GetValue<string>() ?? "";
        return mechanism switch
        {
            "auth:challenge"    => await ChallengeAsync(payload, msgno),
            "auth:scram-sha256" => await ScramAsync(payload, msgno),
            _ => await RejectAsync(msgno, 400, $"Unsupported mechanism: {mechanism}"),
        };
    }

    // ------------------------------------------------------------------
    // auth:challenge  (legacy two-step, server-issued nonce only)
    // ------------------------------------------------------------------

    private async Task<AuthResult?> ChallengeAsync(JsonObject payload, int msgno)
    {
        var username = payload["username"]?.GetValue<string>() ?? "";
        var response = payload["response"]?.GetValue<string>();

        if (string.IsNullOrEmpty(username))
            return await RejectAsync(msgno, 400, "username required");

        if (response is null)
        {
            // Step 1: issue challenge nonce
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16))
                               .ToLowerInvariant();
            _pendingChallenges[username] = nonce;
            await sendJson(new JsonObject
            {
                ["type"]    = MsgType.RPY.ToString(),
                ["channel"] = 0,
                ["msgno"]   = msgno,
                ["payload"] = new JsonObject { ["challenge"] = nonce },
            }.ToJsonString());
            return null;
        }

        // Step 2: verify
        if (!_pendingChallenges.Remove(username, out var storedNonce))
            return await RejectAsync(msgno, 400, "No pending challenge");

        var user = store.GetUser(username);
        if (user is null)
            return await RejectAsync(msgno, 401, "Invalid credentials");

        var expected = ComputeSha256($"{username}:{storedNonce}:{user.PasswordHash}");
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected),
                Encoding.UTF8.GetBytes(response)))
            return await RejectAsync(msgno, 401, "Invalid credentials");

        await SendOkAsync(msgno, user);
        return new AuthResult(user.Username, user.Roles);
    }

    // ------------------------------------------------------------------
    // auth:scram-sha256  (mutual two-step — both sides prove identity)
    //
    // Key derivation (both sides compute identical values if pw correct):
    //   combinedNonce = serverNonce + clientNonce
    //   sharedKey     = SHA256( pH + ":" + combinedNonce )
    //   serverProof   = SHA256( "server:" + sharedKey )   ← server sends, client verifies
    //   clientProof   = SHA256( "client:" + sharedKey )   ← client sends, server verifies
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
            var sharedKey     = ComputeSha256(user.PasswordHash + ":" + combinedNonce);
            var srvProof      = ComputeSha256("server:" + sharedKey);

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

        var expectedProof = ComputeSha256("client:" + state.SharedKey);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expectedProof),
                Encoding.UTF8.GetBytes(clientProof)))
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

    private static string ComputeSha256(string input) =>
        Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(input))
        ).ToLowerInvariant();
}
