using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;

namespace Pnt;

static class TransportChecks
{
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    public static async Task Main()
    {
        if (!QuicTransport.Supported) throw new Exception("QUIC is required for this test; install libmsquic on Linux.");
        Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL", "0");
        var directory = Path.Combine(Path.GetTempPath(), "pnt-quic-check-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); Environment.SetEnvironmentVariable("PNT_DATA_DIR", directory);
        using var a = Certificate.Load(Path.Combine(directory, "a.pfx"));
        using var b = Certificate.Load(Path.Combine(directory, "b.pfx"));
        using var other = Certificate.Load(Path.Combine(directory, "other.pfx"));
        var aid = Certificate.Id(a); var bid = Certificate.Id(b);
        var afp = Certificate.Fingerprint(a); var bfp = Certificate.Fingerprint(b);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var holding = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var bytes = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        var connections = 0;
        async Task Echo(Stream stream, string fingerprint, string remote)
        {
            var request = await Peer.Read(stream);
            if (request?.Type == "hold")
            {
                holding.TrySetResult(); await release.Task;
                var received = new byte[bytes.Length];
                await stream.ReadExactlyAsync(received);
                Assert(received.SequenceEqual(bytes), "Bulk stream data corrupted.");
                await Peer.Send(stream, new Message("bulk-ok"));
            }
            else await Peer.Send(stream, new Message("echo", Output: request?.Output, Id: remote));
        }
        QuicTransport.Register(aid, Echo); QuicTransport.Register(bid, Echo);
        bool Authorized(string id, string fp) => id == bid && fp == bfp;
        using var stop = new CancellationTokenSource();
        var listener = await QuicTransport.Listen(a, new IPEndPoint(IPAddress.Loopback, 0), Authorized, stop.Token)
            ?? throw new Exception("QUIC listener unavailable.");
        var port = listener.LocalEndPoint.Port;
        var listening = QuicTransport.AcceptLoop(listener, aid, Authorized, (_, _) => Interlocked.Increment(ref connections), stop.Token);
        try
        {
            using var first = await Peer.Connect("127.0.0.1", afp, b, port: port);
            Console.WriteLine("Connected: " + first.Transport);
            Assert(first.Transport == "quic", "UDP was not selected as the primary transport.");
            await Peer.Send(first.Stream, new Message("echo", Output: "first"));
            Assert((await Peer.Read(first.Stream).WaitAsync(TimeSpan.FromSeconds(10)))?.Output == "first", "QUIC request failed.");
            Console.WriteLine("First request passed");
            await Task.WhenAll(Enumerable.Range(0, 24).Select(async i =>
            {
                using var peer = await Peer.Connect("127.0.0.1", afp, b, port: port);
                await Peer.Send(peer.Stream, new Message("echo", Output: i.ToString()));
                Assert((await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(10)))?.Output == i.ToString(), "Concurrent QUIC streams mixed data.");
            }));
            Assert(connections == 1, "Tasks did not reuse a persistent UDP connection.");
            Console.WriteLine("Concurrent streams passed");
            using (var reverse = await Peer.Connect("192.0.2.1", bfp, a, port: port))
            {
                Assert(reverse.Transport == "quic", "Reverse NAT channel was not reused.");
                await Peer.Send(reverse.Stream, new Message("echo", Output: "reverse"));
                Assert((await Peer.Read(reverse.Stream).WaitAsync(TimeSpan.FromSeconds(10)))?.Output == "reverse", "NAT reverse request failed.");
            }
            Console.WriteLine("Reverse channel passed");
            using (var blocked = await Peer.Connect("127.0.0.1", afp, b, port: port))
            {
                await Peer.Send(blocked.Stream, new Message("hold"));
                await holding.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Console.WriteLine("Bulk receiver paused");
                var writing = blocked.Stream.WriteAsync(bytes).AsTask();
                await Task.Delay(100);
                Console.WriteLine("Bulk receiver remains paused");
                using var fast = await Peer.Connect("127.0.0.1", afp, b, port: port);
                await Peer.Send(fast.Stream, new Message("echo", Output: "independent"));
                Assert((await Peer.Read(fast.Stream).WaitAsync(TimeSpan.FromSeconds(2)))?.Output == "independent", "A blocked stream delayed other QUIC streams.");
                Console.WriteLine("Independent request passed");
                release.TrySetResult();
                await writing.WaitAsync(TimeSpan.FromSeconds(10));
                Console.WriteLine("Bulk write completed");
                Assert((await Peer.Read(blocked.Stream).WaitAsync(TimeSpan.FromSeconds(10)))?.Type == "bulk-ok", "Bulk transfer failed.");
            }
            Assert(await QuicTransport.Connect("127.0.0.1", Certificate.Fingerprint(other), b, default, port) is null, "Incorrect server pin accepted.");
            Assert(await QuicTransport.Connect("127.0.0.1", afp, other, default, port) is null, "Unknown client certificate accepted.");
            using (var afterReject = await Peer.Connect("127.0.0.1", afp, b, port: port))
            {
                await Peer.Send(afterReject.Stream, new Message("echo", Output: "still-listening"));
                Assert((await Peer.Read(afterReject.Stream).WaitAsync(TimeSpan.FromSeconds(3)))?.Output == "still-listening", "Rejected handshake stopped the listener.");
            }
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            try { await Peer.Connect("127.0.0.1", afp, b, cancelled.Token, port); throw new Exception("Cancellation ignored."); }
            catch (OperationCanceledException) { }
        }
        finally
        {
            release.TrySetResult(); stop.Cancel();
            QuicTransport.CloseLocal(aid); QuicTransport.CloseLocal(bid);
            await listener.DisposeAsync(); await listening;
        }
        using var db = new Store(Path.Combine(directory, "pnt.db"));
        db.Set("self", aid); db.Set("cluster", "transport-check");
        db.Put(new Node(aid, "server", "127.0.0.1", afp, App.Now));
        db.Put(new Node(bid, "client", "127.0.0.2", bfp, App.Now));
        var service = new Service(db, a);
        var tcp = new TcpListener(IPAddress.Loopback, 0); tcp.Start();
        port = ((IPEndPoint)tcp.LocalEndpoint).Port;
        using var tcpStop = new CancellationTokenSource();
        var tcpLoop = Task.Run(async () =>
        {
            try
            {
                while (!tcpStop.IsCancellationRequested)
                {
                    var socket = await tcp.AcceptTcpClientAsync(tcpStop.Token);
                    _ = Task.Run(async () =>
                    {
                        try { await (Task)typeof(Service).GetMethod("Handle", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(service, [socket])!; }
                        catch { socket.Dispose(); }
                    });
                }
            }
            catch (OperationCanceledException) { }
        });
        try
        {
            using var fallback = await Peer.Connect("127.0.0.1", afp, b, port: port);
            Assert(fallback.Transport == "tcp", "TCP fallback failed when UDP was unavailable.");
            await Peer.Send(fallback.Stream, new Message("route-info", bid));
            Assert((await Peer.Read(fallback.Stream))?.Type == "route-info", "Fallback did not preserve the existing protocol.");
            using var upgradeStop = new CancellationTokenSource();
            var upgradeListener = await QuicTransport.Listen(a, new IPEndPoint(IPAddress.Loopback, port), Authorized, upgradeStop.Token)
                ?? throw new Exception("Upgrade listener unavailable.");
            var upgrading = QuicTransport.AcceptLoop(upgradeListener, aid, Authorized, (_, _) => { }, upgradeStop.Token);
            try
            {
                Console.WriteLine("Waiting for automatic UDP retry after TCP fallback");
                await Task.Delay(TimeSpan.FromSeconds(31));
                using var upgraded = await Peer.Connect("127.0.0.1", afp, b, port: port);
                Assert(upgraded.Transport == "quic", "TCP fallback prevented automatic recovery to UDP.");
                await Peer.Send(upgraded.Stream, new Message("route-info", bid));
                Assert((await Peer.Read(upgraded.Stream).WaitAsync(TimeSpan.FromSeconds(5)))?.Type == "route-info", "Recovered UDP channel failed.");
            }
            finally { upgradeStop.Cancel(); await upgradeListener.DisposeAsync(); await upgrading; }
        }
        finally
        {
            MultiplexPool.CloseLocal(aid); MultiplexPool.CloseLocal(bid);
            tcpStop.Cancel(); tcp.Stop(); await tcpLoop;
        }
        var live = new Service(db, a, 0);
        var serving = live.Run();
        try
        {
            using var peer = await Peer.Connect("127.0.0.1", afp, b, port: live.ControlPort);
            Assert(peer.Transport == "quic", "Service did not start UDP transport.");
            await Peer.Send(peer.Stream, new Message("route-info", bid));
            Assert((await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(5)))?.Type == "route-info", "Service did not dispatch QUIC requests.");
            using(var measured=await Peer.Connect("127.0.0.1",afp,b,port:live.ControlPort))
            {
                Assert(measured.Transport=="quic","Probe did not use QUIC");
                Assert(double.IsFinite(await LatencyProbe.Measure(measured,bid,aid)),"QUIC RTT failed");
            }
            var member = db.Resolve(bid)!;
            db.Put(member with { Removed = true, Version = member.Version + 1 });
            using var revoked = await Peer.Connect("127.0.0.1", afp, b, port: live.ControlPort);
            await Peer.Send(revoked.Stream, new Message("route-info", bid));
            Assert((await Peer.Read(revoked.Stream).WaitAsync(TimeSpan.FromSeconds(5)))?.Type == "error", "Removed member retained access through an established QUIC session.");
        }
        finally
        {
            live.Stop(); await serving.WaitAsync(TimeSpan.FromSeconds(10)); MultiplexPool.CloseLocal(bid);
        }
        Console.WriteLine("PASS: UDP priority, persistent QUIC, independent streams, bulk transfer, reverse NAT, certificate pins, authorization, revocation, cancellation, TCP fallback and automatic UDP recovery.");
    }
}
