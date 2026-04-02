using Makaretu.Dns;
using System.Collections.Concurrent;

namespace Weep.Discovery;

public static class WeepMdnsBrowser
{
    public static async Task<IReadOnlyList<DiscoveredWeepService>> DiscoverAsync(
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        timeout ??= TimeSpan.FromSeconds(3);

        using var mdns = new MulticastService();
        using var sd = new ServiceDiscovery(mdns);

        var found = new ConcurrentDictionary<string, Candidate>(StringComparer.OrdinalIgnoreCase);

        sd.ServiceInstanceDiscovered += (_, e) =>
        {
            var instanceName = e.ServiceInstanceName.ToString();
            if (!instanceName.Contains("._weep._tcp.", StringComparison.OrdinalIgnoreCase))
                return;

            var candidate = found.GetOrAdd(instanceName, _ => new Candidate(instanceName));
            UpdateFromMessage(candidate, e.Message);
        };

        mdns.AnswerReceived += (_, e) =>
        {
            foreach (var ptr in e.Message.Answers.OfType<PTRRecord>())
            {
                var instanceName = ptr.DomainName.ToString();
                if (!instanceName.Contains("._weep._tcp.", StringComparison.OrdinalIgnoreCase))
                    continue;

                var candidate = found.GetOrAdd(instanceName, _ => new Candidate(instanceName));
                UpdateFromMessage(candidate, e.Message);
            }
        };

        mdns.NetworkInterfaceDiscovered += (_, _) =>
        {
            sd.QueryServiceInstances(new DomainName("_weep._tcp"));
        };

        mdns.Start();
        sd.QueryServiceInstances(new DomainName("_weep._tcp"));

        await Task.Delay(timeout.Value, ct);

        return found.Values
            .Where(c => c.Port > 0)
            .Select(c => c.ToResult())
            .OrderBy(c => c.InstanceName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void UpdateFromMessage(Candidate candidate, Message message)
    {
        var records = message.Answers
            .Concat(message.AdditionalRecords)
            .ToList();

        var srv = records.OfType<SRVRecord>().FirstOrDefault(r =>
            string.Equals(r.Name.ToString(), candidate.InstanceName, StringComparison.OrdinalIgnoreCase));
        if (srv is not null)
        {
            candidate.HostName = srv.Target.ToString();
            candidate.Port = srv.Port;
        }

        var txt = records.OfType<TXTRecord>().FirstOrDefault(r =>
            string.Equals(r.Name.ToString(), candidate.InstanceName, StringComparison.OrdinalIgnoreCase));
        if (txt is not null)
        {
            var properties = txt.Strings
                .Select(s => s.Split('=', 2))
                .Where(parts => parts.Length == 2)
                .ToDictionary(parts => parts[0], parts => parts[1], StringComparer.OrdinalIgnoreCase);

            if (properties.TryGetValue("path", out var path))
                candidate.Path = path;
            if (properties.TryGetValue("version", out var version))
                candidate.Version = version;
            if (properties.TryGetValue("auth", out var auth))
                candidate.Auth = auth.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        }

        if (!string.IsNullOrWhiteSpace(candidate.HostName))
        {
            var host = candidate.HostName;
            var addresses = records.OfType<AddressRecord>()
                .Where(r => string.Equals(r.Name.ToString(), host, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Address.ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (addresses.Count > 0)
                candidate.Addresses = addresses;
        }
    }

    private sealed class Candidate
    {
        public Candidate(string instanceName)
        {
            InstanceName = instanceName;
        }

        public string InstanceName { get; }
        public string HostName { get; set; } = string.Empty;
        public int Port { get; set; }
        public string Path { get; set; } = "/weep";
        public string Version { get; set; } = "1.2";
        public List<string> Auth { get; set; } = ["auth:scram-sha256"];
        public List<string> Addresses { get; set; } = [];

        public DiscoveredWeepService ToResult() => new(
            InstanceName,
            HostName,
            Port,
            Path,
            Version,
            Auth,
            Addresses);
    }
}
