namespace Weep.Protocol;

/// <summary>
/// Sliding-window send throttle for binary transfers.
///
/// The sender calls AcquireAsync() before transmitting each frame and is
/// suspended when the window is full (W unacknowledged frames in flight).
/// The receiver calls Acknowledge() each time an ACK binary frame arrives,
/// which releases one credit and lets the sender continue.
///
/// Window size W controls the bandwidth-delay product:
///   W = 8 frames × 64 KB/frame = 512 KB in-flight
///   At 1 Mbit/s + 500 ms RTT this fills the pipe completely.
///
/// W = 1 gives stop-and-wait (maximum backpressure, minimum throughput).
/// The default W = 8 is appropriate for reliable LAN/WiFi.
/// Raise W for high-latency WAN links; lower it for constrained receivers.
/// </summary>
internal sealed class SendWindow(int size = 8)
{
    private readonly SemaphoreSlim _credits = new(size, size);

    /// <summary>Wait until a send credit is available.</summary>
    public Task AcquireAsync(CancellationToken ct = default) =>
        _credits.WaitAsync(ct);

    /// <summary>Release one credit when an ACK arrives for <paramref name="seq"/>.</summary>
    public void Acknowledge(uint seq) => _credits.Release();
}
