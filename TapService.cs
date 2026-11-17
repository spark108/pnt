using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

sealed class TapService(Store db, X509Certificate2 cert, TapService.Runtime? runtime = null)
{
    internal sealed record Runtime(int Port, Func<IPAddress, byte[], TapAdapter> Adapter,
        Func<Node, CancellationToken, Task<Peer>> Connect);
    readonly string self = Certificate.Id(cert);
    readonly ConcurrentDictionary<string, (string Node, TapVpnSession Session)> vpnSessions = new();
    readonly ConcurrentDictionary<string, IPAddress> observed = new();
    volatile Network? current;

    internal Task Accept(Stream stream, Message message, CancellationToken token)
        => current is { } network ? network.Accept(stream, message, token) : Peer.Send(stream, new("tap-unavailable"));

    internal void Observe(string node, IPAddress? address)
    {
        if (address?.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address)) observed[node] = address;
    }

    internal TapVpnSession? InitiateVpn(string target, string sessionId)
        => target != self && TapControl.Hex(sessionId, 32) ? new(() => current?.Epoch, token => ConnectVpn(target, sessionId, token)) : null;

    internal TapVpnSession? RegisterVpn(string? origin, string? sessionId)
    {
        if (origin is null || origin == self || !TapControl.Hex(sessionId, 32)) return null;
        var session = new TapVpnSession(() => current?.Epoch);
        if (vpnSessions.TryAdd(sessionId!, (origin, session))) return session;
        session.Dispose();
        return null;
    }

    internal void UnregisterVpn(string? sessionId, TapVpnSession session)
    {
        if (sessionId is not null && vpnSessions.TryGetValue(sessionId, out var registration) && registration.Session == session)
            vpnSessions.TryRemove(new KeyValuePair<string, (string, TapVpnSession)>(sessionId, registration));
    }

    internal async Task AttachVpn(Stream stream, Message message, CancellationToken token)
    {
        var reply = new Message("tap-unavailable", self, RequestId: message.RequestId);
        if (message.Name is { } id && vpnSessions.TryGetValue(id, out var target) && target.Node == message.Id &&
            current?.OpenVpnPath(target.Node) is { } path)
        {
            if (path.Connect(message.TapOffer) && target.Session.Attach(path))
                reply = reply with { Type = "tap-vpn-ready", TapOffer = path.Offer() };
            else path.Dispose();
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        await Peer.Send(stream, reply).WaitAsync(timeout.Token);
    }

    async Task<TapVpnPath?> ConnectVpn(string target, string sessionId, CancellationToken token)
    {
        var path = current?.OpenVpnPath(target, requireRoute: true);
        if (path is null) return null;
        var connected = false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var peer = await new RouteTransport(db, cert).Connect(target, cancellation: timeout.Token);
            var request = await RouteTransport.SendTask(peer, new("tap-vpn", self, Name: sessionId, Target: target,
                TapOffer: path.Offer())).WaitAsync(timeout.Token);
            var reply = await RouteTransport.ReadResult(peer, request.RequestId, TimeSpan.FromSeconds(4), timeout.Token);
            if (reply.Type != "tap-vpn-ready" || reply.Id != target || !path.Connect(reply.TapOffer)) return null;
            connected = true;
            return path;
        }
        catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or TimeoutException or System.Security.Authentication.AuthenticationException) { return null; }
        finally { if (!connected) path.Dispose(); }
    }

    internal async Task Run(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                string? epoch = null, address = null;
                try
                {
                    var config = db.TapConfig();
                    var pool = db.TapPool();
                    epoch = TapControl.Epoch(config, pool);
                    var active = TapControl.Active(db);
                    if (!active || epoch is null || config is null || pool is null)
                        Status(null, null, null, active && config?.Enabled == true ? "ожидает адресацию" : "выключен", null, []);
                    else
                    {
                        db.AllocateTapOctets(self);
                        pool = db.TapPool()!;
                        if (pool.Octets.TryGetValue(self, out var octet))
                        {
                            var ip = TapControl.Address(config.Subnet, octet);
                            address = ip.ToString();
                            var mac = Convert.FromHexString("02" + self[..8] + octet.ToString("x2"));
                            var members = db.Nodes().Where(n => !n.Removed).ToArray();
                            var serviceIps = members.SelectMany(n => new[] { n.Ip, MultiplexPool.Address(self, n.Cert, n.Ip), observed.GetValueOrDefault(n.Id)?.ToString() })
                                .Append(App.OwnIp).Append(db.Get("bootstrap_host")).Where(s => s is not null)
                                .Select(s => IPAddress.TryParse(s, out var parsed) ? parsed : IPAddress.None);
                            await using var adapter = runtime?.Adapter(ip, mac) ?? await TapAdapter.Open(config.Subnet, ip, mac, serviceIps, token);
                            using var network = new Network(db, cert, self, epoch, ip, (byte)octet, adapter, Status, observed, runtime);
                            current = network;
                            try { await network.Run(token); }
                            finally { current = null; }
                        }
                        else Status(epoch, null, null, "ожидает адрес", "Нет зарезервированного номера для этого узла.", []);
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
                catch (Exception e)
                {
                    var error = e.GetBaseException().Message;
                    Status(epoch, address, null, "резервный транспорт", error[..Math.Min(error.Length, 1024)], []);
                }
                await Task.Delay(2500, token);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally { try { Status(null, null, null, "служба остановлена", null, []); } catch { } }
    }

    void Status(string? epoch, string? ip, string? mac, string state, string? error, TapLink[] links, int port = 0) =>
        db.PutTapStatus(new(self, epoch, ip, mac, state, error, App.Now, links, port));

    sealed class Link(string node, TapCipher receive, TapCipher send, IPEndPoint[] candidates)
    {
        internal readonly string Node = node;
        internal readonly TapCipher Receive = receive, Send = send;
        internal readonly long Created = Environment.TickCount64;
        internal readonly IPEndPoint[] Candidates = candidates;
        internal volatile IPEndPoint Endpoint = candidates[0];
        internal long ReplyAt;
        internal double Ms;
        readonly object probe = new();
        byte[]? pending;
        long started;
        internal bool Ready => Interlocked.Read(ref ReplyAt) is > 0 and var reply && Environment.TickCount64 - reply < 6500;
        internal byte[] Probe()
        {
            lock (probe)
            {
                var packet = RandomNumberGenerator.GetBytes(9);
                packet[0] = TapWire.Probe; pending = packet[1..]; started = Stopwatch.GetTimestamp();
                return packet;
            }
        }
        internal void Confirm(byte[] packet)
        {
            lock (probe)
            {
                if (pending is null || !packet.AsSpan(1).SequenceEqual(pending)) return;
                pending = null;
                Volatile.Write(ref Ms, Stopwatch.GetElapsedTime(started).TotalMilliseconds);
                Interlocked.Exchange(ref ReplyAt, Environment.TickCount64);
            }
        }
    }

    sealed class Network : IDisposable
    {
        readonly Store db;
        readonly X509Certificate2 cert;
        readonly string self, epoch;
        readonly IPAddress address;
        readonly byte octet;
        readonly byte[] prefix;
        readonly TapAdapter adapter;
        readonly Action<string?, string?, string?, string, string?, TapLink[], int> status;
        readonly ConcurrentDictionary<string, IPAddress> observed;
        readonly Runtime? runtime;
        readonly UdpClient udp;
        readonly int port;
        readonly ConcurrentDictionary<(string Node, bool Accepted), Link> links = new();
        readonly ConcurrentDictionary<string, Link> receivers = new(StringComparer.Ordinal);
        readonly ConcurrentDictionary<string, long> retry = new(StringComparer.Ordinal);
        volatile Snapshot snapshot = new([], [], [], []);
        internal Network(Store db, X509Certificate2 cert, string self, string epoch, IPAddress address, byte octet,
            TapAdapter adapter, Action<string?, string?, string?, string, string?, TapLink[], int> status,
            ConcurrentDictionary<string, IPAddress> observed, Runtime? runtime)
        {
            this.db = db; this.cert = cert; this.self = self; this.epoch = epoch; this.address = address;
            this.octet = octet; this.adapter = adapter; this.status = status; this.observed = observed; this.runtime = runtime; prefix = address.GetAddressBytes()[..3];
            var setting = Environment.GetEnvironmentVariable("PNT_TAP_PORT");
            port = runtime?.Port ?? (setting is null ? TapControl.DefaultPort : int.TryParse(setting, out var number) && number is > 0 and <= 65535
                ? number : throw new IOException("PNT_TAP_PORT должен быть номером UDP-порта 1–65535."));
            if (port == 442) throw new IOException("UDP 442 зарезервирован для служебного канала PNT.");
            udp = new UdpClient(new IPEndPoint(IPAddress.Any, port));
        }

        internal string Epoch => epoch;

        sealed record Snapshot(Dictionary<byte, string> Nodes, Dictionary<string, byte> Numbers,
            Dictionary<byte, byte[]> Macs, Dictionary<byte, byte[]> Routes);

        internal async Task Run(CancellationToken token)
        {
            using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
            if (runtime is null) Firewall.Open(port, "udp");
            var t = lifetime.Token;
            var jobs = new[] { Tick(t), ReadUdp(t), ReadTap(t) };
            try { await await Task.WhenAny(jobs); }
            finally
            {
                lifetime.Cancel();
                try { await Task.WhenAll(jobs); } catch { }
                if (runtime is null) Firewall.Close(port, "udp");
            }
        }

        internal async Task Accept(Stream stream, Message message, CancellationToken token)
        {
            var node = message.Id is { } origin ? db.Resolve(origin) : null;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            if (node is null || node.Id == self || TapCipher.From(message.TapOffer, epoch) is not { } send ||
                Endpoints(node, message.TapOffer!.Port) is not { Length: > 0 } endpoints ||
                TapControl.Epoch(db.TapConfig(), db.TapPool()) != epoch)
            { await Peer.Send(stream, new("tap-unavailable")).WaitAsync(timeout.Token); return; }
            var receive = new TapCipher();
            SetLink(new(node.Id, receive, send, endpoints), true);
            await Peer.Send(stream, new("tap-link-ready", self, TapOffer: receive.Offer(epoch, port))).WaitAsync(timeout.Token);
        }

        void SetLink(Link value, bool accepted)
        {
            receivers[value.Receive.Id] = value;
            links.AddOrUpdate((value.Node, accepted), value, (key, old) =>
            {
                receivers.TryRemove(old.Receive.Id, out _);
                return value;
            });
        }

        IPEndPoint[] Endpoints(Node node, int remotePort)
        {
            IPAddress.TryParse(node.Ip, out var registered);
            IPAddress.TryParse(MultiplexPool.Address(self, node.Cert, node.Ip), out var configured);
            IPAddress?[] addresses = [configured, observed.GetValueOrDefault(node.Id), registered];
            return addresses.OfType<IPAddress>().Distinct().Where(ip => ip.AddressFamily == AddressFamily.InterNetwork &&
                !ip.GetAddressBytes().AsSpan().StartsWith(prefix)).Select(ip => new IPEndPoint(ip, remotePort)).ToArray();
        }

        async Task Dial(Node node, CancellationToken token)
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
            budget.CancelAfter(TimeSpan.FromSeconds(3));
            var t = budget.Token;
            try
            {
                using var peer = runtime is null ? await Peer.Connect(node.Ip, node.Cert, cert, t) : await runtime.Connect(node, t);
                var receive = new TapCipher();
                await Peer.Send(peer.Stream, new("tap-link", self, TapOffer: receive.Offer(epoch, port))).WaitAsync(t);
                var reply = await Peer.Read(peer.Stream).WaitAsync(t);
                if (reply is not { Type: "tap-link-ready" } || reply.Id != node.Id || TapCipher.From(reply.TapOffer, epoch) is not { } send ||
                    Endpoints(node, reply.TapOffer!.Port) is not { Length: > 0 } endpoints) return;
                SetLink(new(node.Id, receive, send, endpoints), false);
            }
            catch (Exception e) when (e is IOException or OperationCanceledException or SocketException or System.Security.Authentication.AuthenticationException) { }
        }

        async Task Tick(CancellationToken token)
        {
            var nextDial = 0L;
            while (!token.IsCancellationRequested)
            {
                var pool = db.TapPool();
                if (!TapControl.Active(db) || TapControl.Epoch(db.TapConfig(), pool) != epoch || pool?.Octets.GetValueOrDefault(self) != octet) return;
                db.AllocateTapOctets(self);
                var nodes = db.Nodes().Where(n => !n.Removed && pool.Octets.ContainsKey(n.Id)).ToArray();
                var eligible = nodes.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
                foreach (var pair in links)
                    if (!eligible.Contains(pair.Key.Node) || Environment.TickCount64 - pair.Value.Created > 600_000)
                        if (links.TryRemove(pair)) receivers.TryRemove(pair.Value.Receive.Id, out _);
                foreach (var link in links.Values)
                {
                    var probe = link.Probe();
                    await Send(link, probe, token);
                    if (!link.Ready)
                        foreach (var candidate in link.Candidates.Where(c => !c.Equals(link.Endpoint))) await Send(link, probe, token, candidate);
                }
                var active = links.Values.Where(l => l.Ready).GroupBy(l => l.Node)
                    .Select(g => g.MinBy(l => Volatile.Read(ref l.Ms))!).ToArray();
                var direct = active.Select(l => new TapLink(l.Node, Volatile.Read(ref l.Ms))).ToArray();
                var report = new TapStatus(self, epoch, address.ToString(), Convert.ToHexString(adapter.Mac),
                    direct.Length > 0 ? "готов" : "адаптер поднят, UDP-путь не подтверждён",
                    direct.Length > 0 ? null : "Для межузлового VPN доступен текущий транспорт.",
                    App.Now, direct, port);
                status(report.Epoch, report.Address, report.Mac, report.State, report.Error, report.Links, report.Port);
                var known = db.TapStatuses().Where(s => s.Epoch == epoch && App.Now - s.Updated < 18_000 && eligible.Contains(s.Node) &&
                    TapControl.Hex(s.Mac, 12) && s.Address == new IPAddress([..prefix, (byte)pool.Octets[s.Node]]).ToString())
                    .ToDictionary(s => s.Node);
                known[self] = report;
                snapshot = Build(pool, known, nodes);
                if (Environment.TickCount64 >= nextDial)
                {
                    nextDial = Environment.TickCount64 + 2500;
                    var candidates = nodes.Where(n => n.Id != self && Endpoints(n, TapControl.DefaultPort).Length > 0 &&
                        !active.Any(l => l.Node == n.Id) && Environment.TickCount64 >= retry.GetValueOrDefault(n.Id))
                        .OrderBy(n => retry.GetValueOrDefault(n.Id)).ThenBy(n => n.BehindNat).Take(8).ToArray();
                    foreach (var node in candidates) retry[node.Id] = Environment.TickCount64 + (string.CompareOrdinal(self, node.Id) < 0 ? 7000 : 10_000);
                    await Task.WhenAll(candidates.Select(n => Dial(n, token)));
                }
                await Task.Delay(1200, token);
            }
        }

        Snapshot Build(TapPool pool, Dictionary<string, TapStatus> known, Node[] members)
        {
            var indices = known.Keys.ToDictionary(node => node, node => (byte)pool.Octets[node]);
            var names = indices.ToDictionary(p => p.Value, p => p.Key);
            var macs = known.ToDictionary(p => indices[p.Key], p => Convert.FromHexString(p.Value.Mac!));
            var relay = members.ToDictionary(n => n.Id, n => n.RelayEnabled);
            var best = new Dictionary<byte, byte[]>();
            var queue = new PriorityQueue<byte[], (int Reserve, double Delay)>();
            queue.Enqueue([octet], (0, 0));
            while (queue.TryDequeue(out var path, out var cost))
            {
                var last = path[^1];
                if (!best.TryAdd(last, path) || path.Length >= 10) continue;
                var node = names[last];
                foreach (var link in known[node].Links)
                    if (indices.TryGetValue(link.Node, out var next) && !best.ContainsKey(next))
                        queue.Enqueue([.. path, next], (cost.Reserve + (last == octet || relay[node] ? 0 : 1), cost.Delay + Math.Max(link.Ms, 0.1)));
            }
            best.Remove(octet);
            return new(names, indices, macs, best);
        }

        Link? Next(string node) => links.Values.Where(l => l.Node == node && l.Ready).MinBy(l => Volatile.Read(ref l.Ms));

        internal TapVpnPath? OpenVpnPath(string target, bool requireRoute = false)
        {
            if (db.Resolve(target) is null || db.TapPool()?.Octets.TryGetValue(target, out var number) != true) return null;
            bool Ready()
            {
                var state = snapshot;
                return state.Routes.TryGetValue((byte)number, out var path) &&
                    state.Nodes.TryGetValue(path[1], out var next) && Next(next) is not null;
            }
            if (requireRoute && !Ready()) return null;
            try { return new TapVpnPath(epoch, address, new IPAddress([..prefix, (byte)number]), Ready); }
            catch (SocketException) { return null; }
        }

        async Task ReadTap(CancellationToken token)
        {
            var buffer = new byte[TapAdapter.Mtu + 18];
            while (!token.IsCancellationRequested)
            {
                var length = await adapter.Read(buffer, token);
                if (length == 0) throw new IOException("TAP-адаптер отключён.");
                if (length is < 14 or > TapAdapter.Mtu + 14 || !buffer.AsSpan(6, 6).SequenceEqual(adapter.Mac)) continue;
                var state = snapshot;
                var frame = buffer[..length];
                if (TapWire.Destination(frame, prefix, octet) is not { } target || !state.Routes.TryGetValue(target, out var path) ||
                    !state.Nodes.TryGetValue(path[1], out var next) || Next(next) is not { } link) continue;
                await Send(link, TapWire.Frame(path, frame), token);
            }
        }

        async Task ReadUdp(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                UdpReceiveResult packet;
                try { packet = await udp.ReceiveAsync(token); }
                catch (SocketException) { await Task.Delay(50, token); continue; }
                var id = TapCipher.Recipient(packet.Buffer);
                if (id is null || !receivers.TryGetValue(id, out var link) || link.Receive.Open(packet.Buffer) is not { } payload ||
                    packet.RemoteEndPoint.Address.GetAddressBytes().AsSpan().StartsWith(prefix)) continue;
                link.Endpoint = packet.RemoteEndPoint;
                if (payload is [TapWire.Probe, _, _, _, _, _, _, _, _])
                {
                    payload[0] = TapWire.Pong;
                    await Send(link, payload, token); continue;
                }
                if (payload is [TapWire.Pong, _, _, _, _, _, _, _, _]) { link.Confirm(payload); continue; }
                var state = snapshot;
                if (!state.Numbers.TryGetValue(link.Node, out var previous) || TapWire.Parse(payload, previous, octet) is not { } data ||
                    !state.Macs.TryGetValue(data.Path[0], out var origin) || !data.Frame.AsSpan(6, 6).SequenceEqual(origin) ||
                    TapWire.Destination(data.Frame, prefix, data.Path[0]) != data.Path[^1]) continue;
                var at = Array.IndexOf(data.Path, octet);
                if (at == data.Path.Length - 1)
                {
                    if (data.Frame.AsSpan(0, 6).SequenceEqual(adapter.Mac) ||
                        data.Frame[12] == 8 && data.Frame[13] == 6 && data.Frame.AsSpan(0, 6).IndexOfAnyExcept((byte)255) < 0)
                        await adapter.Write(data.Frame, token);
                }
                else if (state.Nodes.TryGetValue(data.Path[at + 1], out var next) && Next(next) is { } outgoing)
                    await Send(outgoing, payload, token);
            }
        }

        async ValueTask Send(Link link, byte[] payload, CancellationToken token, IPEndPoint? destination = null)
        {
            try { await udp.SendAsync(link.Send.Seal(payload), destination ?? link.Endpoint, token); }
            catch (SocketException) { }
        }

        public void Dispose() { snapshot = new([], [], [], []); links.Clear(); udp.Dispose(); }
    }
}
