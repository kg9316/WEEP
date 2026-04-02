using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Weep.Protocol;

namespace Weep.Client;

/// <summary>
/// Handles weep authentication on channel 0 before any data channels are opened.
///
/// Usage:
///   var auth = new AuthClient(client);
///   var result = await auth.LoginAsync("admin", "secret");
///   // or
///   var result = await auth.LoginWithTokenAsync("eyJ...");
/// </summary>
public sealed class AuthClient
{
    private readonly WeepClient _client;
    private          int          _msgno = 0;

    // Greeting waiter
    private readonly TaskCompletionSource<GreetingInfo> _greetingTcs =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    // Auth reply waiter: msgno → TCS<JsonObject>
    private readonly Dictionary<int, TaskCompletionSource<JsonObject>> _pending = new();

    public AuthResult? CurrentUser { get; private set; }

    public AuthClient(WeepClient client)
    {
        _client = client;
        _client.OnGreeting += HandleGreeting;
        _client.OnManagementMessage += HandleManagementMessage;
    }

    // ------------------------------------------------------------------
    // Greeting
    // ------------------------------------------------------------------

    /// <summary>Waits for the server greeting and returns advertised profiles/auth mechanisms.</summary>
    public Task<GreetingInfo> WaitForGreetingAsync(CancellationToken ct = default)
    {
        ct.Register(() => _greetingTcs.TrySetCanceled(ct));
        return _greetingTcs.Task;
    }

    private void HandleGreeting(IReadOnlyList<string> profiles)
    {
        // Full greeting (including auth mechanisms) is parsed in HandleManagementMessage.
        // This event fires from OnGreeting which only carries profiles — ignore it here.
    }

    // ------------------------------------------------------------------
    // Login
    // ------------------------------------------------------------------

    /// <summary>
    /// Challenge-response login — password never travels over the wire.
    /// Client sends username → server returns nonce → client hashes and responds.
    /// Response = SHA256( username + ":" + nonce + ":" + SHA256(password) )
    /// </summary>
    public async Task<AuthResult> LoginWithChallengeAsync(string username, string password,
                                                           CancellationToken ct = default)
    {
        // Step 1: request challenge
        var step1Msgno = Interlocked.Increment(ref _msgno);
        var nonce      = await RequestChallengeAsync(username, step1Msgno, ct);

        // Step 2: compute response and authenticate
        var passwordHash = ComputeSha256($"{password}");
        var response     = ComputeSha256($"{username}:{nonce}:{passwordHash}");

        var step2Payload = new JsonObject
        {
            ["mechanism"] = "auth:challenge",
            ["username"]  = username,
            ["response"]  = response,
        };
        return await SendAuthAsync(step2Payload, ct);
    }

    private async Task<string> RequestChallengeAsync(string username, int msgno,
                                                       CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<JsonObject>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[msgno] = tcs;

        var msg = new JsonObject
        {
            ["type"]    = MsgType.MSG.ToString(),
            ["channel"] = 0,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["mechanism"] = "auth:challenge",
                ["username"]  = username,
            },
        };

        try
        {
            await _client.SendRawAsync(msg.ToJsonString(), ct);
            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            var rpy = await tcs.Task;
            return rpy["challenge"]!.GetValue<string>();
        }
        finally { _pending.Remove(msgno); }
    }

    // ------------------------------------------------------------------
    // auth:scram-sha256  (mutual)
    // ------------------------------------------------------------------

    /// <summary>
    /// SCRAM-SHA-256 mutual authentication — both client and server prove identity.
    /// The client verifies the server's proof before sending its own.
    /// Derivation (both sides, identical if password correct):
    ///   pH           = SHA256(password)
    ///   sharedKey    = SHA256(pH + ":" + combinedNonce)
    ///   serverProof  = SHA256("server:" + sharedKey)  ← client verifies this
    ///   clientProof  = SHA256("client:" + sharedKey)  ← client sends this
    /// </summary>
    public async Task<AuthResult> LoginWithScramAsync(string username, string password,
                                                       CancellationToken ct = default)
    {
        var greeting    = await WaitForGreetingAsync(ct);
        var serverNonce = greeting.ServerNonce
            ?? throw new WeepException(400, "Server did not send serverNonce in greeting");

        // Generate client nonce
        var clientNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16))
                                 .ToLowerInvariant();

        // Step 1: send clientNonce → receive combinedNonce + serverProof
        var step1Msgno = Interlocked.Increment(ref _msgno);
        var step1Reply = await SendRpcAsync(new JsonObject
        {
            ["mechanism"]   = "auth:scram-sha256",
            ["username"]    = username,
            ["clientNonce"] = clientNonce,
        }, step1Msgno, ct);

        var combinedNonce  = step1Reply["combinedNonce"]!.GetValue<string>();
        var serverProofRcv = step1Reply["serverProof"]!.GetValue<string>();

        // Verify server proof — MUTUAL AUTH (abort if talking to impostor server)
        var pH             = ComputeSha256(password);
        var sharedKey      = ComputeSha256(pH + ":" + combinedNonce);
        var expectedServer = ComputeSha256("server:" + sharedKey);
        if (!string.Equals(expectedServer, serverProofRcv, StringComparison.Ordinal))
            throw new WeepException(401, "Server proof mismatch — possible impostor server");

        // Step 2: send clientProof
        var clientProof = ComputeSha256("client:" + sharedKey);
        return await SendAuthAsync(new JsonObject
        {
            ["mechanism"]   = "auth:scram-sha256",
            ["username"]    = username,
            ["clientProof"] = clientProof,
        }, ct);
    }

    // Generic: send MSG on channel 0 and await the RPY payload.
    private async Task<JsonObject> SendRpcAsync(JsonObject msgPayload, int msgno,
                                                 CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<JsonObject>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[msgno] = tcs;
        var msg = new JsonObject
        {
            ["type"]    = MsgType.MSG.ToString(),
            ["channel"] = 0,
            ["msgno"]   = msgno,
            ["payload"] = msgPayload,
        };
        try
        {
            await _client.SendRawAsync(msg.ToJsonString(), ct);
            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            return await tcs.Task;
        }
        finally { _pending.Remove(msgno); }
    }

    private static string ComputeSha256(string input)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    private async Task<AuthResult> SendAuthAsync(JsonObject payload,
                                                   CancellationToken ct)
    {
        var msgno = Interlocked.Increment(ref _msgno);
        var tcs   = new TaskCompletionSource<JsonObject>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[msgno] = tcs;

        var msg = new JsonObject
        {
            ["type"]    = MsgType.MSG.ToString(),
            ["channel"] = 0,
            ["msgno"]   = msgno,
            ["payload"] = payload,
        };

        try
        {
            await _client.SendRawAsync(msg.ToJsonString(), ct);
            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            var rpy = await tcs.Task;

            var result = new AuthResult(
                Username: rpy["username"]!.GetValue<string>(),
                Roles   : rpy["roles"]!.AsArray()
                               .Select(r => r!.GetValue<string>())
                               .ToList()
            );
            CurrentUser = result;
            return result;
        }
        catch (WeepException ex) when (ex.Code == 401)
        {
            throw new UnauthorizedException(ex.Message);
        }
        finally
        {
            _pending.Remove(msgno);
        }
    }

    private void HandleManagementMessage(string json)
    {
        var node    = JsonNode.Parse(json)!.AsObject();
        var typeStr = node["type"]?.GetValue<string>();
        var msgno   = node["msgno"]?.GetValue<int>() ?? -1;
        var payload = node["payload"]?.AsObject() ?? new JsonObject();

        // Extended greeting with auth mechanisms
        if (typeStr == "greeting")
        {
            var profiles = payload["profiles"]?.AsArray()
                               .Select(p => p!.GetValue<string>()).ToList()
                           ?? [];
            var auth = payload["auth"]?.AsArray()
                           .Select(a => a!.GetValue<string>()).ToList()
                       ?? [];
            var serverNonce = payload["serverNonce"]?.GetValue<string>();
            _greetingTcs.TrySetResult(new GreetingInfo(profiles, auth, serverNonce));
            return;
        }

        if (!_pending.TryGetValue(msgno, out var tcs)) return;

        if (typeStr == MsgType.RPY.ToString())
        {
            tcs.TrySetResult(payload);
        }
        else if (typeStr == MsgType.ERR.ToString())
        {
            var code    = payload["code"]?.GetValue<int>()    ?? 500;
            var message = payload["message"]?.GetValue<string>() ?? "Error";
            tcs.TrySetException(new WeepException(code, message));
        }
    }
}

public sealed record GreetingInfo(
    IReadOnlyList<string> Profiles,
    IReadOnlyList<string> AuthMechanisms,
    string?               ServerNonce = null
);

public sealed record AuthResult(
    string               Username,
    IReadOnlyList<string> Roles
)
{
    public bool HasRole(string role) =>
        Roles.Contains("admin") || Roles.Contains(role);
}

public sealed class UnauthorizedException(string message)
    : Exception(message);
