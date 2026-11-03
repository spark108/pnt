using Microsoft.Data.Sqlite;

namespace Pnt;

static class StoreChecks
{
    const string A = "aaaaaaaaaaaaaaaa", B = "bbbbbbbbbbbbbbbb", C = "cccccccccccccccc";
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    static long Version(SqliteConnection c) { using var q = c.CreateCommand(); q.CommandText = "PRAGMA data_version"; return Convert.ToInt64(q.ExecuteScalar()); }
    static void Execute(Store db, string sql) { using var c = db.Open(); using var q = c.CreateCommand(); q.CommandText = sql; q.ExecuteNonQuery(); }

    public static async Task Main(string[] args)
    {
        if (args.Contains("--benchmark")) { await SyncBenchmark.Main(); return; }
        var directory = Path.Combine(Path.GetTempPath(), "pnt-store-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var db = new Store(Path.Combine(directory, "node;sync.db"));
            var now = App.Now;
            var a = new Node(A, "A", "192.0.2.1", new string('A', 64), now);
            var b = new Node(B, "B", "192.0.2.2", new string('B', 64), now);
            var rule = new Rule(C, A, 1000, null, B, 2000, now);
            var client = new VpnClient(C, "client", new string('C', 64), [A], now, ProtectedIdentity: "protected", DeviceAuthority: A);
            var ping = new PingReport(A, B, 10, now, true, [A, B]);
            var rate = new LinkTrafficReport(A, B, 1024, 2048, now, 5000);
            var message = new Message("sync", Nodes: [a, b], Rules: [rule], VpnServers: [new(A, "VPN", now)], VpnClients: [client],
                Pings: [ping], Links: [ping], Traffic: [rate]);
            using var observer = db.Open();
            var before = Version(observer);
            await db.MergeState(message);
            Assert(Version(observer) == before + 1, "A full sync was not committed as one transaction");
            Assert(db.Nodes().Count == 2 && db.Rules().Single() == rule && db.VpnServers().Count == 1 && db.VpnClients().Count == 1, "Full sync lost records");
            Assert(db.PingFrom(A, B) == 10 && db.Links().Count == 1 && db.Traffic().Single() == rate, "Sync lost telemetry");
            before = Version(observer);
            for (var i = 0; i < 10; i++) await db.MergeState(message);
            Assert(Version(observer) == before, "Unchanged gossip caused database writes");
            var newer = message with { Nodes = [a with { Name = "new", Version = now + 10 }], Pings = [ping with { Ms = 5, Updated = now + 10 }],
                Traffic = [rate with { SentBytesPerSecond = 4096, Updated = now + 10 }] };
            await Task.WhenAll(Enumerable.Range(0, 12).Select(i => Task.Run(() => db.MergeState(i % 2 == 0 ? newer : message))));
            Assert(db.Resolve(A)!.Name == "new" && db.PingFrom(A, B) == 5 && db.Traffic().Single().SentBytesPerSecond == 4096, "Concurrent stale sync overwrote fresh state");
            await db.MergeState(message with { Nodes = [a with { Cert = new string('F', 64), Version = now + 100 }],
                VpnClients = [client with { Cert = new string('F', 64), Version = now + 100 }] });
            Assert(db.Resolve(A)!.Cert == a.Cert && db.VpnClients().Single().Cert == client.Cert, "Gossip replaced an immutable certificate");
            db.MergeVpnState(new Message("vpn", VpnClients: [client with { DeviceAuthority = B, Version = now + 100 }]));
            Assert(db.VpnClients().Single().DeviceAuthority == A, "Gossip replaced the device authority");
            db.MergeVpnState(new Message("vpn", VpnClients: [client with { Name = "renamed", ProtectedIdentity = null, DeviceAuthority = null, Version = now + 1 }]));
            Assert(db.VpnClients().Single() is { Name: "renamed", ProtectedIdentity: "protected", DeviceAuthority: A }, "Legacy gossip lost protected identity/authority");
            var invalid = ping with { Updated = now + 20, Direct = false, Route = [B, A], Ms = 99 };
            await db.MergeState(new Message("sync", Pings: [invalid, ping with { Source = C, Updated = now + 20 }],
                Traffic: [rate with { SentBytesPerSecond = double.NaN, Updated = now + 20 }]));
            Assert(db.PingFrom(A, B) == 5 && db.Traffic().Single().SentBytesPerSecond == 4096, "Invalid telemetry replaced valid records");
            db.Set("self", A);
            await db.MergeState(new Message("sync", Traffic: [rate with { SentBytesPerSecond = 1, Updated = now + 30 }]));
            Assert(db.Traffic().Single().SentBytesPerSecond == 4096, "Remote gossip replaced local traffic measurements");

            Execute(db, "CREATE TRIGGER fail_sync BEFORE INSERT ON rules BEGIN SELECT RAISE(ABORT,'injected failure'); END");
            try
            {
                await db.MergeState(new Message("sync", Nodes: [a with { Name = "rollback", Version = now + 100 }], Rules: [rule with { Version = now + 100 }]));
                throw new Exception("Injected failure did not fail the batch");
            }
            catch (SqliteException) { }
            Assert(db.Resolve(A)!.Name == "new", "A failed sync left partially committed records");
            Execute(db, "DROP TRIGGER fail_sync");
            using (var cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel();
                try { await db.MergeState(new Message("sync", Nodes: [a with { Name = "cancelled", Version = now + 100 }]), cancelled.Token); throw new Exception("Cancelled sync ran"); }
                catch (OperationCanceledException) { }
            }
            await db.MergeState(new Message("sync", Nodes: [b with { Removed = true, Version = now - 1 }], Rules: [rule with { Removed = true, Version = now - 1 }],
                VpnClients: [client with { Removed = true, Version = now + 2 }]));
            await db.MergeState(message with { Nodes = [b with { Version = now + 1000 }], Rules = [rule with { Version = now + 1000 }],
                VpnClients = [client with { Version = now + 1000 }] });
            Assert(db.Nodes().Single(n => n.Id == B).Removed && db.Rules().Single().Removed && db.VpnClients().Single().Removed, "Stale resurrection defeated tombstones");
            Console.WriteLine("PASS: one-commit sync, unchanged gossip performs no writes, concurrent freshness, immutable identities, validation, rollback, cancellation, tombstones and pooled file cleanup");
        }
        finally { Directory.Delete(directory, true); }
    }
}
