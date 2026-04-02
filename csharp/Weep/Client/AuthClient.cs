using System.Security.Cryptography;
using System.Text;
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
    /// SCRAM-SHA-256 mutual authentication — both client and server prove identity.
    /// The client verifies the server's proof before sending its own.
    /// Derivation (both sides, identical if password correct):
    ///   pdk         = PBKDF2-SHA256(password, salt, iterations, 32)
    ///   sharedKey   = HMAC-SHA256(pdk, combinedNonce)
    ///   serverProof = HMAC-SHA256(sharedKey, "server:" + combinedNonce)
    ///   clientProof = HMAC-SHA256(sharedKey, "client:" + combinedNonce)
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
        var salt           = step1Reply["salt"]!.GetValue<string>();
        var iterations     = step1Reply["iterations"]!.GetValue<int>();

        // Verify server proof — MUTUAL AUTH (abort if talking to impostor server)
        var passwordKey    = ComputePbkdf2Hex(password, salt, iterations);
        var sharedKey      = ComputeHmacHex(passwordKey, combinedNonce);
        var expectedServer = ComputeHmacHex(sharedKey, "server:" + combinedNonce);
        if (!string.Equals(expectedServer, serverProofRcv, StringComparison.Ordinal))
            throw new WeepException(401, "Server proof mismatch — possible impostor server");

        // Step 2: send clientProof
        var clientProof = ComputeHmacHex(sharedKey, "client:" + combinedNonce);
        return await SendAuthAsync(new JsonObject
        {
            ["mechanism"]   = "auth:scram-sha256",
            ["username"]    = username,
            ["clientProof"] = clientProof,
        }, ct);
    }

    /// <summary>
    /// Sends a raw authentication payload on channel 0 and returns the RPY payload.
    /// This is primarily useful for integration/regression probes.
    /// </summary>
    public Task<JsonObject> ProbeAuthAsync(JsonObject payload, CancellationToken ct = default)
    {
        var msgno = Interlocked.Increment(ref _msgno);
        return SendRpcAsync(payload, msgno, ct);
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

    private static string ComputePbkdf2Hex(string password, string saltHex, int iterations)
    {
        var saltBytes = Convert.FromHexString(saltHex);
        var key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            saltBytes,
            iterations,
            HashAlgorithmName.SHA256,
            32);
        return Convert.ToHexString(key).ToLowerInvariant();
    }

    private static string ComputeHmacHex(string keyHex, string input)
    {
        var keyBytes = Convert.FromHexString(keyHex);
        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
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
