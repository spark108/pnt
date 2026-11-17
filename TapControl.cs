using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

record TapConfig(string Id, long Version, bool Enabled, string Subnet);
record TapPool(string Id, string Allocator, long Revision, Dictionary<string, int> Octets);
record TapLink(string Node, double Ms);
record TapStatus(string Node, string? Epoch, string? Address, string? Mac, string State, string? Error, long Updated, TapLink[] Links, int Port = 0);

static class TapControl
{
    internal const string DefaultSubnet = "37.0.0.0/24";
    internal const int DefaultPort = 44342;
    internal static bool Hex(string? value, int length) => value?.Length == length && value.All(Uri.IsHexDigit);
    internal static bool Active(Store db) => db.Get("cluster") is not null && db.Get("left") != "1" && db.Self() is { Removed: false };

    internal static bool ValidSubnet(string? subnet) => subnet?.Split('/') is [var ip, "24"] &&
        IPAddress.TryParse(ip, out var parsed) && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
        parsed.ToString() == ip && parsed.GetAddressBytes() is [> 0 and < 224 and not 127, _, _, 0];

    internal static IPAddress Address(string subnet, int octet)
        => IPAddress.Parse(subnet[..(subnet.LastIndexOf('.') + 1)] + octet);

    internal static string? Epoch(TapConfig? config, TapPool? pool)
        => config is { Enabled: true } && pool is not null ? config.Id + pool.Id : null;

    internal static TapPool Allocate(TapPool pool, IEnumerable<Node> members)
    {
        var octets = new Dictionary<string, int>(pool.Octets, StringComparer.Ordinal);
        var free = new Queue<int>(Enumerable.Range(1, 254).Except(octets.Values));
        // Keep retired numbers reserved, including when the prefix changes.
        foreach (var node in members.Where(n => !n.Removed).OrderBy(n => n.Id, StringComparer.Ordinal))
            if (!octets.ContainsKey(node.Id) && free.TryDequeue(out var octet)) octets[node.Id] = octet;
        return octets.Count == pool.Octets.Count ? pool : pool with { Revision = pool.Revision + 1, Octets = octets };
    }

    internal static async Task Command(Store db, X509Certificate2 cert, string[] args)
    {
        if (!Active(db)) throw new IOException("Узел не состоит в активном кластере.");
        var self = Certificate.Id(cert);
        if (args is ["enable"] or ["enable", "--subnet", _] or ["disable"])
        {
            var enabled = args[0] == "enable";
            if (args.Length == 3 && !ValidSubnet(args[2])) throw new ArgumentException("Укажите IPv4-подсеть /24, например 10.234.42.0/24.");
            db.ChangeTapConfig(self, enabled, args.Length == 3 ? args[2] : null);
            var result = await App.Broadcast(db, cert);
            var config = db.TapConfig()!;
            Console.WriteLine($"TAP: {(config.Enabled ? "включён" : "выключен")}. Подсеть: {config.Subnet}. Подтвердили синхронизацию: {result}.");
            return;
        }
        var target = args is ["status"] ? db.Self() : args is ["status", var node] ? db.Resolve(node) : null;
        if (target is null) throw new ArgumentException("Узел не найден.");
        var state = db.TapStatus(target.Id);
        var live = target.Id == self && state is not null && App.Now - state.Updated < 15_000;
        if (target.Id != self)
        {
            try
            {
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(6));
                using var peer = await new RouteTransport(db, cert).Connect(target.Id, cancellation: stop.Token);
                var request = await RouteTransport.SendTask(peer, new Message("tap-status", self, Target: target.Id)).WaitAsync(stop.Token);
                var reply = await RouteTransport.ReadResult(peer, request.RequestId, TimeSpan.FromSeconds(4), stop.Token);
                if (reply.Type == "tap-status" && reply.TapStatuses is [{ } current] && current.Node == target.Id)
                { db.PutTapStatus(current); state = current; live = true; }
            }
            catch (Exception e) when (e is IOException or TimeoutException or OperationCanceledException or System.Net.Sockets.SocketException) { }
        }
        var desired = db.TapConfig();
        Console.WriteLine($"Узел: {target.Id}. TAP в кластере: {(desired?.Enabled == true ? "включён" : "выключен")}. Подсеть: {desired?.Subnet ?? DefaultSubnet}.");
        if (state is null) { Console.WriteLine("Состояние адаптера неизвестно."); return; }
        Console.WriteLine($"Состояние: {state.State}{(live ? "" : " (последнее известное)")}. Проверка: {DateTimeOffset.FromUnixTimeMilliseconds(state.Updated):u}");
        if (state.Address is not null) Console.WriteLine($"IP: {state.Address}. MAC: {state.Mac}.");
        if (state.Error is not null) Console.WriteLine(state.Error);
        if (state.Links.Length > 0) CliOutput.Table(["Прямой TAP-канал", "RTT UDP, мс"], state.Links.Select(l => new CliCell[] { l.Node, l.Ms.ToString("F1") }));
        if (target.Id != self && live && desired is { Enabled: true } && state.Epoch == Epoch(desired, db.TapPool()) &&
            db.TapStatus(self) is { Address: not null } local && local.Epoch == state.Epoch && App.Now - local.Updated < 10_000 &&
            db.TapPool()?.Octets.TryGetValue(target.Id, out var octet) == true && state.Address == Address(desired.Subnet, octet).ToString())
        {
            try
            {
                using var ping = new Ping();
                var icmp = await ping.SendPingAsync(IPAddress.Parse(state.Address), 1300);
                Console.WriteLine(icmp.Status == IPStatus.Success ? $"ICMP через TAP: {icmp.RoundtripTime} мс." : "ICMP через TAP: нет ответа.");
            }
            catch (PingException) { Console.WriteLine("ICMP через TAP: проверка недоступна."); }
        }
    }
}

sealed partial class Store
{
    const string TapConfigKey = "tap_config", TapPoolKey = "tap_pool";
    internal TapConfig? TapConfig() => JsonSerializer.Deserialize<TapConfig>(Get(TapConfigKey) ?? "null", App.Json);
    internal TapPool? TapPool() => JsonSerializer.Deserialize<TapPool>(Get(TapPoolKey) ?? "null", App.Json);
    internal TapStatus? TapStatus(string node) => JsonSerializer.Deserialize<TapStatus>(Get("tap_status:" + node) ?? "null", App.Json);

    internal void ChangeTapConfig(string self, bool enabled, string? subnet)
    {
        var members = Nodes().ToArray();
        TapWrite((read, write) =>
        {
            var old = read.Get<TapConfig>(TapConfigKey);
            var selected = subnet ?? old?.Subnet ?? TapControl.DefaultSubnet;
            if (!TapControl.ValidSubnet(selected)) throw new ArgumentException("Некорректная TAP-подсеть.");
            if (enabled && read.Get<TapPool>(TapPoolKey) is null)
                write(TapPoolKey, TapControl.Allocate(new(Guid.NewGuid().ToString("N"), self, 0, []), members));
            if (old is null || enabled != old.Enabled || selected != old.Subnet)
                write(TapConfigKey, new TapConfig(Guid.NewGuid().ToString("N"), (old?.Version ?? 0) + 1, enabled, selected));
        });
    }

    internal void AllocateTapOctets(string self)
    {
        if (TapPool()?.Allocator != self) return;
        var members = Nodes().ToArray();
        TapWrite((read, write) =>
        {
            if (read.Get<TapPool>(TapPoolKey) is not { } old || old.Allocator != self) return;
            var next = TapControl.Allocate(old, members);
            if (next != old) write(TapPoolKey, next);
        });
    }

    internal void MergeTap(Message message)
    {
        var config = message.Tap;
        var pool = message.TapAddresses;
        if (config is not null || pool is not null) TapWrite((read, write) =>
        {
            if (config is { Version: > 0 and < long.MaxValue } && TapControl.Hex(config.Id, 32) && TapControl.ValidSubnet(config.Subnet))
            {
                var old = read.Get<TapConfig>(TapConfigKey);
                if (old is null || old.Version < config.Version || old.Version == config.Version && string.CompareOrdinal(old.Id, config.Id) < 0)
                    write(TapConfigKey, config);
            }
            if (pool is { Revision: > 0 and < long.MaxValue, Octets.Count: > 0 and <= 254 } && TapControl.Hex(pool.Id, 32) &&
                TapControl.Hex(pool.Allocator, 16) && pool.Octets.ContainsKey(pool.Allocator) &&
                pool.Octets.All(p => TapControl.Hex(p.Key, 16) && p.Value is >= 1 and <= 254) && pool.Octets.Values.Distinct().Count() == pool.Octets.Count)
            {
                var old = read.Get<TapPool>(TapPoolKey);
                if (old is null || string.CompareOrdinal(pool.Id, old.Id) < 0 || pool.Id == old.Id && pool.Allocator == old.Allocator &&
                    pool.Revision > old.Revision && old.Octets.All(p => pool.Octets.GetValueOrDefault(p.Key) == p.Value)) write(TapPoolKey, pool);
            }
        });
        foreach (var status in message.TapStatuses ?? []) PutTapStatus(status);
    }

    internal void PutTapStatus(TapStatus value)
    {
        if (!TapControl.Hex(value.Node, 16) || value.Updated <= 0 || value.Updated > App.Now + 60_000 ||
            value.Links is not { Length: <= 254 } || value.Links.Any(l => l is null || !TapControl.Hex(l.Node, 16) || !double.IsFinite(l.Ms) || l.Ms < 0) ||
            value.Epoch is not null && !TapControl.Hex(value.Epoch, 64) || value.Port is < 0 or > 65535 || value.Error?.Length > 1024) return;
        TapWrite((read, write) =>
        {
            var key = "tap_status:" + value.Node;
            if (value.Updated > (read.Get<TapStatus>(key)?.Updated ?? 0)) write(key, value);
        });
    }

    internal TapStatus[] TapStatuses()
    {
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "SELECT v FROM meta WHERE k LIKE 'tap_status:%'";
        using var rows = q.ExecuteReader(); var result = new List<TapStatus>();
        while (rows.Read()) if (JsonSerializer.Deserialize<TapStatus>(rows.GetString(0), App.Json) is { } status) result.Add(status);
        return result.ToArray();
    }

    internal interface ITapRead { T? Get<T>(string key) where T : class; }
    void TapWrite(Action<ITapRead, Action<string, object>> change)
    {
        using var c = Open(); using var tx = c.BeginTransaction(deferred: false);
        change(new TapReader(tx), (key, value) =>
        {
            using var command = c.CreateCommand(); command.Transaction = tx;
            command.CommandText = "INSERT INTO meta VALUES($k,$v) ON CONFLICT(k) DO UPDATE SET v=excluded.v";
            command.Parameters.AddWithValue("$k", key); command.Parameters.AddWithValue("$v", JsonSerializer.Serialize(value, App.Json)); command.ExecuteNonQuery();
        });
        tx.Commit();
    }
    sealed class TapReader(Microsoft.Data.Sqlite.SqliteTransaction tx) : ITapRead
    {
        public T? Get<T>(string key) where T : class
        {
            using var command = tx.Connection!.CreateCommand(); command.Transaction = tx;
            command.CommandText = "SELECT v FROM meta WHERE k=$k"; command.Parameters.AddWithValue("$k", key);
            return JsonSerializer.Deserialize<T>(command.ExecuteScalar() as string ?? "null", App.Json);
        }
    }
}
