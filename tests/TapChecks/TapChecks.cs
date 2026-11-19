using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Pnt;

static class TapChecks
{
    static void Require(bool condition, string detail)
    {
        if (!condition) throw new InvalidOperationException(detail);
    }

    public static async Task Main()
    {
        CheckSettings();
        CheckFrameAndWire();
        await CheckRoutedEthernet();
        await CheckVpnFailover();
        Console.WriteLine("TAP checks passed.");
    }

    static void CheckSettings()
    {
        var path = Path.Combine(Path.GetTempPath(), $"pnt-tap-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        try
        {
            using var first = new Store(Path.Combine(path, "a.db"));
            using var second = new Store(Path.Combine(path, "b.db"));
            const string a = "0101010101010101", b = "0202020202020202", c = "0303030303030303";
            first.Set("cluster", "test");
            first.Set("self", a);
            first.Put(new Node(a, "a", "10.1.1.1", new string('a',64), 1));
            first.Put(new Node(b, "b", "10.1.1.2", new string('b',64), 1, BehindNat: true));
            Require(App.NodeColumns[4] == "Тип соединения" &&
                App.NodeRows(first, null).Select(row => row[4].Value).Order().SequenceEqual(new[] { "—", "NAT" }.Order()),
                "The connection type column must be present even with TAP disabled.");
            first.ChangeTapConfig(a, true, null);
            var old = first.TapConfig()!;
            var pool = first.TapPool()!;
            Require(old is { Enabled: true, Subnet: "37.0.0.0/24" }, "First enable must use the default /24.");
            second.MergeTap(new Message("sync", Tap: old, TapAddresses: pool));
            second.ChangeTapConfig(b, true, "10.234.42.0/24");
            first.MergeTap(new Message("sync", Tap: second.TapConfig(), TapAddresses: second.TapPool()));
            Require(first.TapConfig()!.Subnet == "10.234.42.0/24" && first.TapPool()!.Octets[b] == pool.Octets[b],
                "Subnet migration from another node changed its final octet.");
            Require(TapControl.Epoch(old, pool) != TapControl.Epoch(first.TapConfig(), pool), "Subnet migration did not invalidate old sessions.");
            var now = App.Now;
            var epoch = TapControl.Epoch(first.TapConfig(), first.TapPool());
            first.MergeTap(new Message("sync", TapStatuses:
            [
                new(b, epoch, "10.234.42.2", "020000000002", "готов", null, now, [new(a, 91)], Pings: [new(a, 24, now)])
            ]));
            var remoteRows = App.NodeRows(first, b);
            var tapIndex = remoteRows.FindIndex(row => row[2].Value == "10.234.42.1");
            Require(tapIndex > 0 && remoteRows[tapIndex - 1][2].Value == "10.1.1.1" &&
                remoteRows[tapIndex][3].Value == "24 ms" && remoteRows[tapIndex][4].Value == "TAP",
                "The TAP row must follow its regular IP and use ICMP from the selected node.");
            Require(App.NodeRows(first, null).Single(row => row[2].Value == "10.234.42.2")[3].Value == "нет замера",
                "A different source must not reuse another node's ICMP measurements.");
            second.MergeTap(new Message("sync", Tap: old));
            Require(second.TapConfig()!.Subnet == "10.234.42.0/24", "A late replication message rolled back the subnet.");
            first.ChangeTapConfig(a, false, null);
            Require(first.TapConfig() is { Enabled: false, Subnet: "10.234.42.0/24" }, "Disabling lost the subnet.");
            Require(App.NodeRows(first, null).All(row => row[4].Value != "TAP"), "Disabling TAP left extra rows in the list.");
            first.ChangeTapConfig(a, true, null);
            Require(first.TapConfig() is { Enabled: true, Subnet: "10.234.42.0/24" }, "Re-enabling lost the configured subnet.");
            first.Put(new Node(c, "c", "10.1.1.3", new string('c',64), 1));
            first.AllocateTapOctets(b);
            Require(!first.TapPool()!.Octets.ContainsKey(c), "A second allocator issued an address.");
            first.AllocateTapOctets(a);
            second.MergeTap(new Message("sync", Tap: first.TapConfig(), TapAddresses: first.TapPool()));
            Require(second.TapPool()!.Octets[c] == 3 && second.TapPool()!.Octets[b] == 2, "New allocation did not replicate.");
            Require(!TapControl.ValidSubnet("37.0.0.1/24") && !TapControl.ValidSubnet("37.0.0.0/16") && !TapControl.ValidSubnet("037.0.0.0/24"),
                "Noncanonical prefixes were accepted.");
            Require(TapAdapter.Overlap([37,0,0], "37.0.0.12/32") && TapAdapter.Overlap([37,0,0], "37.0.0.0/8")
                && !TapAdapter.Overlap([37,0,0], "0.0.0.0/0") && !TapAdapter.Overlap([37,0,0], "37.0.1.0/24"), "Route collision detection failed.");
        }
        finally { Directory.Delete(path, recursive:true); }
    }

    static void CheckFrameAndWire()
    {
        var receiver = new TapCipher();
        var epoch = new string('a', 64);
        var transmitter = TapCipher.From(receiver.Offer(epoch, 44342), epoch)!;
        var frame = new byte[34]; frame[12] = 8; frame[14] = 0x45; frame[26] = frame[30] = 37; frame[29] = 1; frame[33] = 3;
        Require(TapWire.Destination(frame, [37,0,0], 1) == 3 && TapWire.Destination(frame, [37,0,0], 2) is null, "Source IP isolation failed.");
        var payload = TapWire.Frame([1,2,3], frame);
        Require(TapWire.Parse(payload, 1, 2)?.Path is [1,2,3] && TapWire.Parse(payload, 2, 3)?.Frame.SequenceEqual(frame) == true,
            "Intermediate could not parse the unicast frame.");
        Require(TapWire.Parse(payload, 1, 3) is null && TapWire.Parse(TapWire.Frame([1,2,1,3], frame), 1, 2) is null,
            "A skipped hop or forwarding loop was accepted.");
        var sealedFrame = transmitter.Seal(payload);
        var second = transmitter.Seal([1]);
        var tamper = (byte[])sealedFrame.Clone(); tamper[^1] ^= 1;
        Require(receiver.Open(tamper) is null && receiver.Open(second) is [1] && receiver.Open(sealedFrame)?.SequenceEqual(payload) == true &&
            receiver.Open(sealedFrame) is null, "Authentication, out of order delivery or replay protection failed.");
        Require(TapCipher.From(receiver.Offer(epoch, 44342), new string('b',64)) is null, "An old subnet epoch was accepted.");
    }

    static async Task CheckRoutedEthernet()
    {
        var path = Path.Combine(Path.GetTempPath(), $"pnt-tap-route-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        using var end = new CancellationTokenSource(TimeSpan.FromSeconds(28));
        var token = end.Token;
        var certs = Enumerable.Range(0,3).Select(i => Certificate.Load(Path.Combine(path, $"{i}.pfx"))).ToArray();
        var stores = Enumerable.Range(0,3).Select(i => new Store(Path.Combine(path, $"{i}.db"))).ToArray();
        var controls = Enumerable.Range(0,3).Select(_ => new TcpListener(IPAddress.Loopback,0)).ToArray();
        var adapters = new FakeAdapter?[3];
        var members = certs.Select((certificate, i) => new Node(Certificate.Id(certificate), $"tap-{i}", "127.0.0.1",
            Certificate.Fingerprint(certificate), 1)).ToArray();
        var running = new List<Task>();
        try
        {
            for (var i = 0; i < 3; i++)
            {
                controls[i].Start();
                stores[i].Set("cluster", "test");
                stores[i].Set("self", members[i].Id);
                foreach (var node in members) stores[i].Put(node);
            }
            stores[0].ChangeTapConfig(members[0].Id, true, "10.234.42.0/24");
            var config = stores[0].TapConfig()!;
            var pool = stores[0].TapPool()!;
            var initial = new Message("sync", Tap: config, TapAddresses: pool);
            var reserved = Enumerable.Range(0,3).Select(_ => new UdpClient(new IPEndPoint(IPAddress.Loopback,0))).ToArray();
            var ports = reserved.Select(u => ((IPEndPoint)u.Client.LocalEndPoint!).Port).ToArray();
            Array.ForEach(reserved, u => u.Dispose());
            for (var i = 0; i < 3; i++)
            {
                var from = i;
                stores[from].MergeTap(initial);
                var runtime = new TapService.Runtime(ports[from], (ip, mac) =>
                {
                    var adapter = new FakeAdapter(ip, mac);
                    Volatile.Write(ref adapters[from], adapter);
                    return adapter;
                }, (member, cancellation) =>
                {
                    var to = Array.FindIndex(members, m => m.Id == member.Id);
                    if (Math.Abs(from - to) != 1) throw new IOException("Link deliberately unavailable.");
                    return Peer.ConnectRaw(member.Ip, member.Cert, certs[from], cancellation, ((IPEndPoint)controls[to].LocalEndpoint).Port);
                });
                var service = new TapService(stores[from], certs[from], runtime);
                running.Add(service.Run(token));
                running.Add(Accept(from, service));
            }
            async Task Accept(int i, TapService service)
            {
                while (!token.IsCancellationRequested)
                {
                    using var socket = await controls[i].AcceptTcpClientAsync(token);
                    using var peer = await Peer.Accept(socket, certs[i]);
                    var message = await Peer.Read(peer.Stream).WaitAsync(token);
                    Require(message is { Type: "tap-link" } && stores[i].Resolve(peer.RemoteId)?.Cert == peer.RemoteFingerprint,
                        "TAP control was not authenticated by the expected node certificate.");
                    await service.Accept(peer.Stream, message!, token);
                }
            }
            var watch = System.Diagnostics.Stopwatch.StartNew();
            byte[]? frame = null, reply = null;
            while (!token.IsCancellationRequested)
            {
                var statuses = stores.Select((s, i) => s.TapStatus(members[i].Id)).OfType<TapStatus>().ToArray();
                foreach (var store in stores) store.MergeTap(new Message("sync", TapStatuses: statuses));
                if (statuses.Length == 3 && statuses[0].Links.Length == 1 && statuses[1].Links.Length == 2 && statuses[2].Links.Length == 1 &&
                    Volatile.Read(ref adapters[0]) is { } source && Volatile.Read(ref adapters[2]) is { } target)
                {
                    frame ??= Ipv4(source, target);
                    source.Outbound.Writer.TryWrite(frame);
                    if (target.Inbound.Reader.TryRead(out reply)) break;
                }
                if (watch.Elapsed > TimeSpan.FromSeconds(20)) throw new TimeoutException("TAP frame did not reach the destination through the middle node.");
                await Task.Delay(220, token);
            }
            Require(frame is not null && reply?.SequenceEqual(frame) == true, "The relayed Ethernet frame was corrupted.");
            Require(adapters[1] is { } middle && !middle.Inbound.Reader.TryRead(out _), "The relay injected transit traffic into its operating system.");
        }
        finally
        {
            end.Cancel();
            try { await Task.WhenAll(running); } catch (OperationCanceledException) { }
            Array.ForEach(controls, l => l.Stop());
            Array.ForEach(stores, s => s.Dispose());
            Array.ForEach(certs, c => c.Dispose());
            Directory.Delete(path, recursive:true);
        }
    }

    static byte[] Ipv4(FakeAdapter from, FakeAdapter to)
    {
        var frame = new byte[34];
        to.Mac.CopyTo(frame,0); from.Mac.CopyTo(frame,6);
        frame[12] = 8; frame[14] = 0x45;
        from.Address.GetAddressBytes().CopyTo(frame,26); to.Address.GetAddressBytes().CopyTo(frame,30);
        return frame;
    }

    sealed class FakeAdapter(IPAddress address, byte[] mac) : TapAdapter
    {
        internal readonly IPAddress Address = address;
        internal readonly Channel<byte[]> Outbound = Channel.CreateUnbounded<byte[]>();
        internal readonly Channel<byte[]> Inbound = Channel.CreateUnbounded<byte[]>();
        internal override byte[] Mac => mac;
        internal override async ValueTask<int> Read(byte[] frame, CancellationToken token)
        {
            var data = await Outbound.Reader.ReadAsync(token);
            data.CopyTo(frame,0);
            return data.Length;
        }
        internal override ValueTask Write(byte[] frame, CancellationToken token) => Inbound.Writer.WriteAsync(frame, token);
        public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    static async Task CheckVpnFailover()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(16));
        var token = deadline.Token;
        string? epoch = null;
        var ip1 = IPAddress.Loopback;
        var ip2 = IPAddress.Parse("127.0.0.2");
        using var exitPath = new TapVpnSession(() => Volatile.Read(ref epoch));
        using var entryPath = new TapVpnSession(() => Volatile.Read(ref epoch), _ =>
        {
            if (Volatile.Read(ref epoch) is not { } active) return Task.FromResult<TapVpnPath?>(null);
            var left = new TapVpnPath(active, ip1, ip2, () => Volatile.Read(ref epoch) == active);
            var right = new TapVpnPath(active, ip2, ip1, () => Volatile.Read(ref epoch) == active);
            if (left.Connect(right.Offer()) && right.Connect(left.Offer()) && exitPath.Attach(right))
                return Task.FromResult<TapVpnPath?>(left);
            left.Dispose(); right.Dispose();
            return Task.FromResult<TapVpnPath?>(null);
        });
        using var listener = new TcpListener(ip1, 0); listener.Start();
        async Task<(TcpClient, TcpClient)> Connect()
        {
            var client = new TcpClient();
            var accept = listener.AcceptTcpClientAsync(token);
            await client.ConnectAsync(ip1, ((IPEndPoint)listener.LocalEndpoint).Port, token);
            return (client, await accept);
        }
        var (external, entry) = await Connect();
        var (fallback, exit) = await Connect();
        using var resources = new PairDisposer(external, entry, fallback, exit);
        using var target = new UdpClient(new IPEndPoint(ip1, 0));
        using var monitored = new CountingStream(fallback.GetStream());
        var relay = VpnDatagrams.Relay(entry.GetStream(), monitored, () => true, token, true, entryPath);
        var sink = VpnDatagrams.Exit(exit.GetStream(), ip1.ToString(), ((IPEndPoint)target.Client.LocalEndPoint!).Port, () => true, token,
            keepAlive:true, path:exitPath);
        try
        {
            var length = 6500;
            var original = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
            async Task<IPEndPoint> RoundTrip(byte[] data)
            {
                await VpnDatagrams.Write(external.GetStream(), data, token);
                var packet = await target.ReceiveAsync(token);
                Require(packet.Buffer.SequenceEqual(data), "VPN datagram was corrupted at exit.");
                await target.SendAsync(packet.Buffer, packet.RemoteEndPoint, token);
                Require((await VpnDatagrams.Read(external.GetStream(), token)).SequenceEqual(data), "VPN reply did not reach the client.");
                return packet.RemoteEndPoint;
            }
            var fallbackEndpoint = await RoundTrip([7]);
            Require(monitored.Written > 0 && monitored.Received > 0, "The old stream was unavailable before TAP was enabled.");
            var bytesWritten = monitored.Written;
            var bytesRead = monitored.Received;
            Volatile.Write(ref epoch, new string('a', 64));
            await Task.Delay(2200, token);
            var endpoint = await RoundTrip(original);
            Require(endpoint.Equals(fallbackEndpoint), "Enabling TAP replaced the exit socket.");
            Require(monitored.Written == bytesWritten && monitored.Received == bytesRead, "VPN payload used the old transport while TAP was available.");
            Volatile.Write(ref epoch, null);
            Require(endpoint.Equals(await RoundTrip([9, 8, 7])), "Failover replaced the exit socket.");
            Require(monitored.Written > bytesWritten && monitored.Received > bytesRead, "VPN failed to fall back to the old stream.");
            bytesWritten = monitored.Written;
            bytesRead = monitored.Received;
            Volatile.Write(ref epoch, new string('b', 64));
            await Task.Delay(3700, token);
            Require(endpoint.Equals(await RoundTrip(original)), "Subnet migration replaced the exit socket.");
            Require(monitored.Written == bytesWritten && monitored.Received == bytesRead, "VPN did not move to the new TAP epoch.");
            await VpnDatagrams.WriteFrame(external.GetStream(), new VpnDatagrams.Frame(0, []), token);
            Require((await VpnDatagrams.ReadFrame(external.GetStream(), token, true)).Size == ushort.MaxValue, "Legacy heartbeat did not survive failover.");
        }
        finally
        {
            deadline.Cancel();
            try { await Task.WhenAll(relay, sink); } catch (OperationCanceledException) { }
        }
    }

    sealed class PairDisposer(params IDisposable[] sockets) : IDisposable
    { public void Dispose() { foreach (var socket in sockets) socket.Dispose(); } }

    sealed class CountingStream(Stream inner) : Stream
    {
        long received, written;
        internal long Received => Interlocked.Read(ref received);
        internal long Written => Interlocked.Read(ref written);
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> bytes, CancellationToken token = default)
        { var count = await inner.ReadAsync(bytes, token); Interlocked.Add(ref received, count); return count; }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken token = default)
        { await inner.WriteAsync(bytes, token); Interlocked.Add(ref written, bytes.Length); }
    }
}
