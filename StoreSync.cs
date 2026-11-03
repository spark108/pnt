using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Pnt;

sealed partial class Store
{
    internal async Task MergeState(Message message, CancellationToken token = default)
    {
        await mergeGate.WaitAsync(token);
        try
        {
            using var batch = new SyncBatch(this);
            var nodes = batch.Read<Node>("nodes").ToDictionary(n => n.Id);
            foreach (var incoming in message.Nodes ?? [])
            {
                token.ThrowIfCancellationRequested();
                nodes.TryGetValue(incoming.Id, out var old);
                if (old is not null && old.Cert != incoming.Cert || incoming.Ip.Length > 64 || incoming.Name.Length > 64 ||
                    incoming.Location is {} location && !GeoLocations.Valid(location)) continue;
                var value = incoming;
                if (old?.Removed == true && !value.Removed) continue;
                if (old?.Removed == false && value.Removed && value.Version <= old.Version) value = value with { Version = old.Version + 1 };
                if (old is not null && value.Version <= old.Version) continue;
                batch.Versioned("nodes", value.Id, value.Version, value);
                nodes[value.Id] = value;
            }
            if (message.Rules is { Length: > 0 })
            {
                var rules = batch.Read<Rule>("rules").ToDictionary(r => r.Id);
                foreach (var incoming in message.Rules)
                {
                    rules.TryGetValue(incoming.Id, out var old);
                    var value = incoming;
                    if (old?.Removed == true && !value.Removed) continue;
                    if (old?.Removed == false && value.Removed && value.Version <= old.Version) value = value with { Version = old.Version + 1 };
                    if (old is not null && value.Version <= old.Version) continue;
                    batch.Versioned("rules", value.Id, value.Version, value);
                    rules[value.Id] = value;
                }
            }
            batch.Vpn(message);
            var active = nodes.Values.Where(n => !n.Removed).ToArray();
            var ids = active.Select(n => n.Id).ToHashSet();
            bool Known(string id) => ids.Contains(id) || active.Any(n => n.Name.Equals(id, StringComparison.OrdinalIgnoreCase) || n.Ip == id);
            var now = App.Now;
            var links = batch.Times("direct_links");
            void Link(PingReport report)
            {
                if (!report.Direct || !double.IsFinite(report.Ms) || report.Ms < 0 || report.Updated < now - 60_000 ||
                    report.Updated > now + 60_000 || !Known(report.Source) || !Known(report.Target)) return;
                batch.Report("direct_links", report.Source, report.Target, report.Updated, report, links);
            }
            var pings = batch.Times("peer_pings");
            foreach (var report in message.Pings ?? [])
            {
                if (report.Direct) Link(report);
                if (report.Source.Length != 16 || report.Target.Length != 16 || !double.IsFinite(report.Ms) || report.Ms < 0 ||
                    report.Updated > now + 60_000 || report.Updated < now - 60_000 || !ids.Contains(report.Source) || !ids.Contains(report.Target)) continue;
                if (report.Route is { Length: > 0 } route && (route.Length > 10 || route[0] != report.Source || route[^1] != report.Target ||
                    route.Any(n => n is null || n.Length != 16 || !n.All(Uri.IsHexDigit)))) continue;
                var key = (report.Source, report.Target);
                if (pings.TryGetValue(key, out var timestamp) && timestamp >= report.Updated) continue;
                batch.Execute("INSERT INTO peer_pings(source,target,ms,updated,direct,route) VALUES($s,$t,$ms,$u,$direct,$route) " +
                    "ON CONFLICT(source,target) DO UPDATE SET ms=excluded.ms,updated=excluded.updated,direct=excluded.direct,route=excluded.route WHERE excluded.updated>peer_pings.updated",
                    ("$s", report.Source), ("$t", report.Target), ("$ms", report.Ms), ("$u", report.Updated),
                    ("$direct", report.Direct ? 1 : 0), ("$route", JsonSerializer.Serialize(report.Route ?? [], App.Json)));
                pings[key] = report.Updated;
            }
            foreach (var report in message.Links ?? []) Link(report);
            var traffic = batch.Times("link_traffic");
            var self = batch.Scalar("SELECT v FROM meta WHERE k='self'") as string;
            foreach (var report in message.Traffic ?? [])
            {
                if (report.Source == self || report.Source == report.Target || !Known(report.Source) || !Known(report.Target) ||
                    report.Updated < now - 30_000 || report.Updated > now + 60_000 || report.IntervalMs is < 1000 or > 30_000 ||
                    !double.IsFinite(report.SentBytesPerSecond) || !double.IsFinite(report.ReceivedBytesPerSecond) ||
                    report.SentBytesPerSecond < 0 || report.ReceivedBytesPerSecond < 0) continue;
                batch.Report("link_traffic", report.Source, report.Target, report.Updated, report, traffic);
            }
            token.ThrowIfCancellationRequested();
            batch.Commit();
        }
        finally { mergeGate.Release(); }
    }

    internal void MergeVpnState(Message message)
    {
        if (message.VpnServers is not { Length: > 0 } && message.VpnClients is not { Length: > 0 }) return;
        using var batch = new SyncBatch(this);
        batch.Vpn(message);
        batch.Commit();
    }

    sealed class SyncBatch : IDisposable
    {
        readonly SqliteConnection connection;
        readonly SqliteTransaction transaction;
        readonly Dictionary<string, SqliteCommand> commands = new();

        public SyncBatch(Store store)
        {
            connection = store.Open();
            try { transaction = connection.BeginTransaction(deferred: false); }
            catch { connection.Dispose(); throw; }
        }

        SqliteCommand Command(string sql, params (string Name, object Value)[] parameters)
        {
            if (!commands.TryGetValue(sql, out var command))
            {
                command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = sql;
                commands.Add(sql, command);
                foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value);
            }
            else foreach (var parameter in parameters) command.Parameters[parameter.Name].Value = parameter.Value;
            return command;
        }

        public object? Scalar(string sql) => Command(sql).ExecuteScalar();
        public void Execute(string sql, params (string Name, object Value)[] parameters) => Command(sql, parameters).ExecuteNonQuery();
        public List<T> Read<T>(string table)
        {
            using var reader = Command($"SELECT json FROM {table}").ExecuteReader();
            var result = new List<T>();
            while (reader.Read()) result.Add(JsonSerializer.Deserialize<T>(reader.GetString(0), App.Json)!);
            return result;
        }
        public Dictionary<(string, string), long> Times(string table)
        {
            using var reader = Command($"SELECT source,target,updated FROM {table}").ExecuteReader();
            var result = new Dictionary<(string, string), long>();
            while (reader.Read()) result[(reader.GetString(0), reader.GetString(1))] = reader.GetInt64(2);
            return result;
        }
        public void Versioned<T>(string table, string id, long version, T value) => Execute(UpsertSql(table),
            ("$id", id), ("$version", version), ("$json", JsonSerializer.Serialize(value, App.Json)));
        public void Report<T>(string table, string source, string target, long updated, T value, Dictionary<(string, string), long> times)
        {
            var key = (source, target);
            if (times.TryGetValue(key, out var old) && old >= updated) return;
            Execute($"INSERT INTO {table} VALUES($s,$t,$j,$u) ON CONFLICT(source,target) DO UPDATE SET json=excluded.json,updated=excluded.updated WHERE excluded.updated>{table}.updated",
                ("$s", source), ("$t", target), ("$j", JsonSerializer.Serialize(value, App.Json)), ("$u", updated));
            times[key] = updated;
        }
        public void Vpn(Message message)
        {
            if (message.VpnServers is { Length: > 0 })
            {
                var servers = Read<VpnServer>("vpn_servers").ToDictionary(s => s.Id);
                foreach (var value in message.VpnServers)
                {
                    if (!VpnControl.Valid(value) || servers.TryGetValue(value.Id, out var old) && old.Version >= value.Version) continue;
                    Execute("INSERT INTO vpn_servers VALUES($id,$json,$version) ON CONFLICT(id) DO UPDATE SET json=excluded.json,version=excluded.version WHERE excluded.version>vpn_servers.version",
                        ("$id", value.Id), ("$json", JsonSerializer.Serialize(value, App.Json)), ("$version", value.Version));
                    servers[value.Id] = value;
                }
            }
            if (message.VpnClients is { Length: > 0 })
            {
                var clients = Read<VpnClient>("vpn_clients").ToDictionary(c => c.Id);
                foreach (var incoming in message.VpnClients)
                {
                    if (!VpnControl.Valid(incoming)) continue;
                    clients.TryGetValue(incoming.Id, out var old);
                    if (old is not null && (old.Cert != incoming.Cert || old.DeviceAuthority is not null && incoming.DeviceAuthority is not null && old.DeviceAuthority != incoming.DeviceAuthority ||
                        old.Removed && !incoming.Removed || old.Version >= incoming.Version && !(incoming.Removed && !old.Removed))) continue;
                    Execute(VpnClientSql, ("$id", incoming.Id), ("$json", JsonSerializer.Serialize(incoming, App.Json)), ("$version", incoming.Version));
                    clients[incoming.Id] = incoming with { ProtectedIdentity = incoming.ProtectedIdentity ?? old?.ProtectedIdentity, DeviceAuthority = old?.DeviceAuthority ?? incoming.DeviceAuthority };
                }
            }
        }
        public void Commit() => transaction.Commit();
        public void Dispose()
        {
            foreach (var command in commands.Values) command.Dispose();
            transaction.Dispose(); connection.Dispose();
        }
    }
}
