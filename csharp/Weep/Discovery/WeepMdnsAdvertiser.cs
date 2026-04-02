using Makaretu.Dns;

namespace Weep.Discovery;

public sealed class WeepMdnsAdvertiser : IDisposable
{
    private readonly MulticastService _mdns;
    private readonly ServiceDiscovery _discovery;
    private readonly ServiceProfile _profile;
    private bool _started;

    public WeepMdnsAdvertiser(
        string instanceName,
        int port,
        string path = "/weep",
        string version = "1.2",
        IReadOnlyList<string>? authMechanisms = null)
    {
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), "Port must be in range 1..65535.");

        _mdns = new MulticastService();
        _discovery = new ServiceDiscovery(_mdns);
        _profile = new ServiceProfile(instanceName, "_weep._tcp", (ushort)port);

        _profile.AddProperty("path", path);
        _profile.AddProperty("version", version);
        _profile.AddProperty("auth", string.Join(",", authMechanisms ?? ["auth:scram-sha256"]));
    }

    public void Start()
    {
        if (_started) return;
        _discovery.Advertise(_profile);
        _mdns.Start();
        _started = true;
    }

    public void Dispose()
    {
        if (_started)
        {
            _discovery.Unadvertise(_profile);
            _mdns.Stop();
            _started = false;
        }

        _discovery.Dispose();
        _mdns.Dispose();
    }
}
