using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Weep.Protocol;

public enum MsgType
{
    MSG, RPY, ERR, ANS, NUL,
    greeting, start, close, ok
}

public static class Profiles
{
    public const string File   = "weep:file";
    public const string Stream = "weep:stream";
    public const string Read   = "weep:read";
    public const string Write  = "weep:write";
    public const string Sub    = "weep:sub";
    public const string Pub    = "weep:pub";
    public const string Invoke = "weep:invoke";
    public const string Query  = "weep:query";
}

public sealed record Message(
    MsgType        Type,
    int            Channel,
    int            Msgno,
    JsonObject     Payload,
    string?        Profile = null,
    int?           Ansno   = null
)
{
    public static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy        = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition      = JsonIgnoreCondition.WhenWritingNull,
        Converters                  = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public string Serialize()
    {
        var node = new JsonObject
        {
            ["type"]    = Type.ToString(),
            ["channel"] = Channel,
            ["msgno"]   = Msgno,
            ["payload"] = Payload.DeepClone(),
        };
        if (Profile is not null) node["profile"] = Profile;
        if (Ansno   is not null) node["ansno"]   = Ansno;
        return node.ToJsonString();
    }

    public static Message Deserialize(string json)
    {
        var node = JsonNode.Parse(json)!.AsObject();
        return new Message(
            Type    : Enum.Parse<MsgType>(node["type"]!.GetValue<string>()),
            Channel : node["channel"]!.GetValue<int>(),
            Msgno   : node["msgno"]!.GetValue<int>(),
            Payload : node["payload"]?.AsObject() ?? new JsonObject(),
            Profile : node["profile"]?.GetValue<string>(),
            Ansno   : node["ansno"]?.GetValue<int>()
        );
    }
}

public static class MessageFactory
{
    public static string Greeting(IEnumerable<string> profiles) =>
        new JsonObject
        {
            ["type"]    = "greeting",
            ["channel"] = 0,
            ["msgno"]   = 0,
            ["payload"] = new JsonObject
            {
                ["profiles"] = new JsonArray(profiles.Select(p => JsonValue.Create(p)).ToArray()),
            },
        }.ToJsonString();

    public static string Start(int channel, int msgno, string profile,
                                int chunkSize = 65_536) =>
        new JsonObject
        {
            ["type"]    = "start",
            ["channel"] = 0,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["channel"]   = channel,
                ["profile"]   = profile,
                ["chunkSize"] = chunkSize,
            },
        }.ToJsonString();

    public static string Ok(int msgno) =>
        new JsonObject
        {
            ["type"]    = "ok",
            ["channel"] = 0,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject(),
        }.ToJsonString();

    public static string Error(int channel, int msgno, int code, string message) =>
        new JsonObject
        {
            ["type"]    = "ERR",
            ["channel"] = channel,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["code"]    = code,
                ["message"] = message,
            },
        }.ToJsonString();
}
