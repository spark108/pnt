using System.Diagnostics;
using System.Reflection;

namespace Pnt;

static class SyncBenchmark
{
    public static async Task Main()
    {
        var directory = Path.Combine(Path.GetTempPath(), "pnt-sync-benchmark-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var cert = Certificate.Load(Path.Combine(directory, "node.pfx"));
            using var db = new Store(Path.Combine(directory, "node.db"));
            var now = App.Now;
            var nodes = Enumerable.Range(1, 10).Select(i => new Node(i.ToString("x16"), "node" + i, "192.0.2." + i, new string('A', 64), now)).ToArray();
            var pings = nodes.SelectMany(a => nodes.Where(b => a.Id != b.Id).Select(b => new PingReport(a.Id, b.Id, 10, now, true, [a.Id, b.Id]))).ToArray();
            var message = new Message("sync", Nodes: nodes, Pings: pings, Links: pings,
                Traffic: pings.Select(p => new LinkTrafficReport(p.Source, p.Target, 1000, 2000, now, 5000)).ToArray(),
                VpnServers: nodes.Select(n => new VpnServer(n.Id, n.Name, now)).ToArray(),
                VpnClients: Enumerable.Range(100, 20).Select(i => new VpnClient(i.ToString("x16"), "client" + i, new string('B', 64), nodes.Select(n => n.Id).ToArray(), now)).ToArray());
            var service = new Service(db, cert, 0);
            var merge = typeof(Service).GetMethod("Merge", BindingFlags.NonPublic | BindingFlags.Instance)!;
            async Task Apply() { if (merge.Invoke(service, [message]) is Task task) await task; }
            await Apply();
            var cpu = Process.GetCurrentProcess().TotalProcessorTime;
            var watch = Stopwatch.StartNew();
            for (var i = 0; i < 20; i++) await Apply();
            Console.WriteLine($"20 full unchanged syncs / 10 nodes: elapsed={watch.Elapsed.TotalMilliseconds:F0} ms; CPU={(Process.GetCurrentProcess().TotalProcessorTime - cpu).TotalMilliseconds:F0} ms");
        }
        finally { Directory.Delete(directory, true); }
    }
}
