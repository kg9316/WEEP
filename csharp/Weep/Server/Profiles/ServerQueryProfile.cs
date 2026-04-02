using System.Text.Json.Nodes;
using Weep.Protocol;

namespace Weep.Server.Profiles;

/// <summary>
/// Server-side weep:query handler.
/// Query is passed as an opaque string (for SQL/BQL-like usage).
/// Current behavior returns a fixed JSON array payload so user code can later
/// replace this with a custom backend.
/// </summary>
public sealed class ServerQueryProfile(
    int                channel,
    Func<string, Task> sendJson)
{
    private static readonly JsonArray FixedRows =
    [
        new JsonObject { ["name"] = "row1", ["value"] = 123 },
        new JsonObject { ["name"] = "row2", ["value"] = 456 },
        new JsonObject { ["name"] = "row3", ["value"] = 789 },
    ];

    public async Task HandleAsync(JsonObject payload, int msgno)
    {
        var op = payload["op"]?.GetValue<string>() ?? "query";
        if (!string.Equals(op, "query", StringComparison.OrdinalIgnoreCase))
        {
            await sendJson(MessageFactory.Error(channel, msgno, 400, $"Unknown op: {op}"));
            return;
        }

        var q = payload["q"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(q))
        {
            await sendJson(MessageFactory.Error(channel, msgno, 400, "q required"));
            return;
        }

        await sendJson(new JsonObject
        {
            ["type"]    = MsgType.RPY.ToString(),
            ["channel"] = channel,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["resultType"] = "array",
                ["query"]      = q,
                ["items"]      = FixedRows.DeepClone(),
            },
        }.ToJsonString());
    }
}
