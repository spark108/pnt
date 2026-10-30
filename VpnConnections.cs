using System.Collections.Concurrent;

namespace Pnt;

static class VpnConnections
{
    static readonly ConcurrentDictionary<(string Node, string Client, Guid Session), long> relays = new();
    internal sealed class Relay(string node, string client) : IDisposable
    {
        readonly Guid session = Guid.NewGuid();
        public void Touch() => relays[(node, client, session)] = Environment.TickCount64;
        public void Dispose() => relays.TryRemove((node, client, session), out _);
    }
    internal static VpnStatistics Observe(string node, string client, VpnStatistics stats, long now)
    {
        var connected = stats.Exists && stats.Handshake > 0 && stats.Handshake <= now && now - stats.Handshake <= 180;
        var relay = connected && relays.Any(p => p.Key.Node == node && p.Key.Client == client && Environment.TickCount64 - p.Value <= 180_000);
        return stats with { Connected = connected, Mode = connected ? relay ? "relay" : "direct" : null };
    }
    internal static string Describe(IEnumerable<VpnStatistics?> reports)
    {
        var samples = reports.ToArray();
        var connected = samples.Where(s => s?.Connected == true).ToArray();
        if (connected.Length > 0)
        {
            var modes = connected.Select(s => s!.Mode).Distinct().ToArray();
            var mode = modes.Contains("relay") && modes.Contains("direct") ? "прямое, транспорт" : modes.Contains("relay") ? "транспорт" : "прямое";
            return "подключён  " + mode;
        }
        return samples.Any(s => s is null || s.Connected is null) ? "неизвестно  —" : "отключён  —";
    }
}
