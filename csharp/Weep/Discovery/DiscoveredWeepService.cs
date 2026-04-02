namespace Weep.Discovery;

public sealed record DiscoveredWeepService(
    string InstanceName,
    string HostName,
    int Port,
    string Path,
    string Version,
    IReadOnlyList<string> AuthMechanisms,
    IReadOnlyList<string> Addresses
)
{
    public string BuildWebSocketUrl()
    {
        var host = PickPreferredHost(Addresses)
            ?? (HostName.EndsWith(".", StringComparison.Ordinal)
                ? HostName[..^1]
                : HostName);
        var path = Path.StartsWith("/", StringComparison.Ordinal) ? Path : "/" + Path;
        return $"ws://{host}:{Port}{path}";
    }

    private static string? PickPreferredHost(IReadOnlyList<string> addresses)
    {
        static int Rank(string value)
        {
            if (!System.Net.IPAddress.TryParse(value, out var ip)) return int.MaxValue;
            if (System.Net.IPAddress.IsLoopback(ip)) return 0;
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = ip.GetAddressBytes();
                if (b[0] == 192 && b[1] == 168) return 1;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return 2;
                if (b[0] == 10) return 3;
                if (b[0] == 169 && b[1] == 254) return 50;
                return 10;
            }

            // Prefer global/link-local IPv6 after private IPv4 for browser friendliness.
            return ip.IsIPv6LinkLocal ? 20 : 15;
        }

        return addresses
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(Rank)
            .FirstOrDefault();
    }
}
