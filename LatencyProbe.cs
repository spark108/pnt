using System.Diagnostics;
using System.Security.Cryptography;

namespace Pnt;

static class LatencyProbe
{
    const int Size = 16;
    public static async Task<double> Measure(Peer peer, string source, string target, CancellationToken token = default, int samples = 3)
    {
        if (samples is not (1 or 3)) throw new ArgumentOutOfRangeException(nameof(samples));
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(8));
        var request = new Message("latency-open", source, Target: target, RequestId: peer.RouteReady?.RequestId ?? Guid.NewGuid().ToString("N"),
            Deadline: App.Now + 10_000, ProbeCount: samples);
        await Peer.Send(peer.Stream, request).WaitAsync(budget.Token);
        var ready = await Peer.Read(peer.Stream).WaitAsync(budget.Token);
        if (ready?.Type != "latency-ready" || ready.Id != target || ready.RequestId != request.RequestId || ready.ProbeCount != samples)
            throw new IOException(ready?.Error ?? "Узел не поддерживает короткие замеры PNT.");
        var timings = new double[samples];
        var nonce = new byte[Size]; var reply = new byte[Size];
        for (var i = 0; i < samples; i++)
        {
            RandomNumberGenerator.Fill(nonce);
            var started = Stopwatch.GetTimestamp();
            await peer.Stream.WriteAsync(nonce, budget.Token);
            await peer.Stream.FlushAsync(budget.Token);
            await peer.Stream.ReadExactlyAsync(reply, budget.Token);
            timings[i] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            if (!nonce.AsSpan().SequenceEqual(reply)) throw new IOException("Ответ замера PNT не соответствует запросу.");
        }
        Array.Sort(timings);
        return timings[timings.Length / 2];
    }

    public static async Task Reply(Stream stream, Message request, string self, CancellationToken token)
    {
        if (request.Target != self || request.ProbeCount is not (1 or 3) || request.RequestId is not { Length: 32 })
        {
            await Peer.Send(stream, new Message("error", Error: "Некорректный запрос замера PNT.", RequestId: request.RequestId)); return;
        }
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(TimeSpan.FromSeconds(10));
        await Peer.Send(stream, new Message("latency-ready", self, RequestId: request.RequestId, ProbeCount: request.ProbeCount)).WaitAsync(budget.Token);
        var nonce = new byte[Size];
        for (var i = 0; i < request.ProbeCount; i++)
        {
            await stream.ReadExactlyAsync(nonce, budget.Token);
            await stream.WriteAsync(nonce, budget.Token);
            await stream.FlushAsync(budget.Token);
        }
    }
}
