using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Pnt;

interface ITapVpnChannel
{
    ValueTask<bool> TrySend(byte[] data, CancellationToken token);
    Task Run(Func<byte[],Task> deliver, CancellationToken token);
}

// This socket is bound to the real TAP IPv4 address. Its packets traverse the same
// Ethernet path as other traffic on that adapter, rather than a parallel UDP relay.
sealed class TapVpnPath : ITapVpnChannel, IDisposable
{
    const int Chunk = 1000, Header = 9, MaxDatagram = 65507;
    internal const int FirstPort = 44400, LastPort = 44999;
    readonly string epoch;
    readonly IPAddress target;
    readonly Func<bool> routeReady;
    readonly UdpClient udp;
    readonly int localPort;
    readonly TapCipher receive = new();
    TapCipher? send;
    long lastReply;
    int sequence;
    long probe;
    readonly Dictionary<uint, Incoming> pending = [];

    internal TapVpnPath(string epoch, IPAddress self, IPAddress target, Func<bool> routeReady)
    {
        this.epoch = epoch; this.target = target; this.routeReady = routeReady;
        var start = RandomNumberGenerator.GetInt32(LastPort - FirstPort + 1);
        for (var i = 0; i <= LastPort - FirstPort; i++)
        {
            var port = FirstPort + (start + i) % (LastPort - FirstPort + 1);
            try { udp = new UdpClient(new IPEndPoint(self, port)); localPort = port; return; }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse) { }
        }
        throw new SocketException((int)SocketError.AddressAlreadyInUse);
    }

    internal TapOffer Offer() => receive.Offer(epoch, localPort);
    internal string Epoch => epoch;
    internal bool Connect(TapOffer? remote)
    {
        if (remote is not { Port: >= FirstPort and <= LastPort } || TapCipher.From(remote, epoch) is not { } cipher) return false;
        try { udp.Connect(target, remote!.Port); send = cipher; return true; }
        catch (SocketException) { return false; }
    }

    internal async Task Probe(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            if (routeReady())
            {
                var packet = new byte[9]; packet[0] = TapWire.Probe;
                BinaryPrimitives.WriteInt64BigEndian(packet.AsSpan(1), Interlocked.Increment(ref probe));
                await Send(packet, token);
            }
            await Task.Delay(1000, token);
        }
    }

    public async ValueTask<bool> TrySend(byte[] data, CancellationToken token)
    {
        var last = Interlocked.Read(ref lastReply);
        if (data.Length is < 1 or > MaxDatagram || last == 0 || Environment.TickCount64 - last > 3200 || !routeReady()) return false;
        var id = unchecked((uint)Interlocked.Increment(ref sequence));
        for (var offset = 0; offset < data.Length; offset += Chunk)
        {
            var count = Math.Min(Chunk, data.Length - offset);
            var packet = new byte[Header + count]; packet[0] = 3;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1), id);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(5), (ushort)data.Length);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(7), (ushort)offset);
            data.AsSpan(offset, count).CopyTo(packet.AsSpan(Header));
            if (!await Send(packet, token)) return false;
        }
        return true;
    }

    public async Task Run(Func<byte[],Task> deliver, CancellationToken token)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        var jobs = new[] { Read(deliver, stop.Token), Probe(stop.Token) };
        try { await await Task.WhenAny(jobs); }
        finally { stop.Cancel(); try { await Task.WhenAll(jobs); } catch { } }
    }

    internal async Task Read(Func<byte[], Task> deliver, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            UdpReceiveResult datagram;
            try { datagram = await udp.ReceiveAsync(token); }
            catch (SocketException)
            {
                Interlocked.Exchange(ref lastReply, 0);
                await Task.Delay(100, token); continue;
            }
            if (receive.Open(datagram.Buffer) is not { } packet) continue;
            if (packet is [TapWire.Probe, _, _, _, _, _, _, _, _])
            { packet[0] = TapWire.Pong; await Send(packet, token); continue; }
            if (packet is [TapWire.Pong, _, _, _, _, _, _, _, _])
            {
                var sent = Interlocked.Read(ref probe);
                var value = BinaryPrimitives.ReadInt64BigEndian(packet.AsSpan(1));
                if (value > 0 && value <= sent && sent - value <= 2) Interlocked.Exchange(ref lastReply, Environment.TickCount64);
                continue;
            }
            if (packet.Length <= Header || packet[0] != 3) continue;
            var id = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(1));
            var length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(5));
            var offset = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(7));
            if (length is < 1 or > MaxDatagram || offset >= length || offset % Chunk != 0 ||
                packet.Length != Header + Math.Min(Chunk, length - offset)) continue;
            if (offset == 0 && length <= Chunk) { await deliver(packet[Header..]); continue; }
            var now = Environment.TickCount64;
            foreach (var stale in pending.Where(x => now - x.Value.Created > 2000).Select(x => x.Key).ToArray()) pending.Remove(stale);
            if (!pending.TryGetValue(id, out var current))
            {
                if (pending.Count >= 12) continue;
                pending[id] = current = new Incoming(length, now);
            }
            if (current.Buffer.Length != length || !current.Offsets.Add(offset)) continue;
            packet.AsSpan(Header).CopyTo(current.Buffer.AsSpan(offset));
            if (current.Offsets.Count == (length + Chunk - 1) / Chunk)
            { pending.Remove(id); await deliver(current.Buffer); }
        }
    }

    async ValueTask<bool> Send(byte[] packet, CancellationToken token)
    {
        if (send is null) return false;
        try { await udp.SendAsync(send.Seal(packet), token); return true; }
        catch (SocketException) { Interlocked.Exchange(ref lastReply, 0); return false; }
        catch (ObjectDisposedException) { return false; }
    }

    sealed class Incoming(int length, long created)
    {
        internal readonly long Created = created;
        internal readonly byte[] Buffer = new byte[length];
        internal readonly HashSet<ushort> Offsets = [];
    }

    public void Dispose() => udp.Dispose();
}

// The PNT stream remains the fallback for the entire VPN session. Attachment to a
// TAP epoch is negotiable independently, including after a live prefix change.
sealed class TapVpnSession(Func<string?> availableEpoch,
    Func<CancellationToken,Task<TapVpnPath?>>? connect = null) : ITapVpnChannel, IDisposable
{
    sealed class Attachment(TapVpnPath path)
    {
        internal readonly TapVpnPath Path = path;
        internal Task? Work;
        internal CancellationTokenSource? Stop;
    }

    readonly object gate = new();
    readonly List<Attachment> retired = [];
    Attachment? current;
    bool finished;

    internal bool Attach(TapVpnPath path)
    {
        lock (gate)
        {
            if (finished || path.Epoch != availableEpoch()) return false;
            Retire();
            Volatile.Write(ref current, new(path));
            return true;
        }
    }

    public ValueTask<bool> TrySend(byte[] data, CancellationToken token)
    {
        var path = Volatile.Read(ref current)?.Path;
        return path is not null && path.Epoch == availableEpoch() ? path.TrySend(data, token) : ValueTask.FromResult(false);
    }

    public async Task Run(Func<byte[],Task> deliver, CancellationToken token)
    {
        Task<TapVpnPath?>? dialing = null;
        var nextDial = 0L;
        try
        {
            while (!token.IsCancellationRequested)
            {
                var epoch = availableEpoch();
                lock (gate)
                {
                    if (finished) return;
                    if (current?.Work?.Exception?.GetBaseException() is UnauthorizedAccessException revoked) throw revoked;
                    if (current is { } value && (value.Path.Epoch != epoch || value.Work?.IsCompleted == true)) Retire();
                    if (current is { Work: null } attach)
                    {
                        attach.Stop = CancellationTokenSource.CreateLinkedTokenSource(token);
                        attach.Work = attach.Path.Run(deliver, attach.Stop.Token);
                    }
                    retired.RemoveAll(r =>
                    {
                        if (r.Work?.IsCompleted == false) return false;
                        _ = r.Work?.Exception;
                        r.Stop?.Dispose();
                        return true;
                    });
                }
                if (dialing?.IsCompleted == true)
                {
                    var path = await dialing;
                    if (path is not null && !Attach(path)) path.Dispose();
                    dialing = null;
                }
                if (connect is not null && epoch is not null && Volatile.Read(ref current) is null &&
                    dialing is null && Environment.TickCount64 >= nextDial)
                {
                    nextDial = Environment.TickCount64 + 3000;
                    dialing = connect(token);
                }
                await Task.Delay(350, token);
            }
        }
        finally
        {
            if (dialing is not null)
                try { (await dialing)?.Dispose(); } catch (OperationCanceledException) { }
            Attachment[] pending;
            lock (gate) { finished = true; Retire(); pending = retired.ToArray(); retired.Clear(); }
            foreach (var item in pending)
            {
                try { if (item.Work is not null) await item.Work; } catch { }
                finally { item.Stop?.Dispose(); }
            }
        }
    }

    void Retire()
    {
        if (current is not { } value) return;
        Volatile.Write(ref current, null);
        value.Stop?.Cancel();
        value.Path.Dispose();
        retired.Add(value);
    }

    public void Dispose()
    {
        lock (gate)
        {
            finished = true; Retire();
        }
    }
}
