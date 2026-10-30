using System.Collections.Concurrent;

namespace Pnt;

static class VpnConnections
{
    sealed class Activity(string[] route)
    {
        public long Updated;
        public readonly string[] Route=route;
    }
    static readonly ConcurrentDictionary<(string Node, string Client, Guid Session), Activity> relays = new();
    internal sealed class Relay(string node, string client,string[]? route=null) : IDisposable
    {
        readonly Guid session = Guid.NewGuid();
        readonly Activity activity=new((route??[node]).ToArray());
        public void Touch()
        {
            Volatile.Write(ref activity.Updated,Environment.TickCount64);
            relays[(node,client,session)]=activity;
        }
        public void Dispose() => relays.TryRemove((node, client, session), out _);
    }
    internal static VpnStatistics Observe(string node, string client, VpnStatistics stats, long now)
    {
        var connected = stats.Exists && stats.Handshake > 0 && stats.Handshake <= now && now - stats.Handshake <= 180;
        var relay = connected ? relays.Where(p => p.Key.Node == node && p.Key.Client == client && Environment.TickCount64 - Volatile.Read(ref p.Value.Updated) <= 180_000)
            .OrderByDescending(p=>Volatile.Read(ref p.Value.Updated)).Select(p=>p.Value).FirstOrDefault() : null;
        return stats with { Connected = connected, Mode = connected ? relay is not null ? "relay" : "direct" : null,
            Route=connected?relay?.Route.ToArray()??[node]:null };
    }
    internal static (string Status,string Mode) Summary(IEnumerable<VpnStatistics?> reports)
    {
        var samples = reports.ToArray();
        var connected = samples.Where(s => s?.Connected == true).ToArray();
        if (connected.Length > 0)
        {
            var modes = connected.Select(s => s!.Mode).Distinct().ToArray();
            var mode = modes.Contains("relay") && modes.Contains("direct") ? "прямое, транспорт" : modes.Contains("relay") ? "транспорт" : "прямое";
            return ("подключён",mode);
        }
        return (samples.Any(s => s is null || s.Connected is null) ? "неизвестно" : "отключён","—");
    }
}
