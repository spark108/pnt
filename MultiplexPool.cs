using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

static class MultiplexPool
{
    static readonly ConcurrentDictionary<string, MultiplexSession> sessions = new();
    static readonly ConcurrentDictionary<string, SemaphoreSlim> gates = new();
    static readonly ConcurrentDictionary<string, Func<Stream, string, string, Task>> handlers = new();
    static readonly ConcurrentDictionary<MultiplexSession, string> active = new();
    internal static void Register(string self, Func<Stream, string, string, Task> handler) => handlers[self] = handler;
    internal static bool IsService(string self) => handlers.ContainsKey(self);
    static string Key(string self, string fingerprint) => self + ":" + fingerprint;

    public static async Task<Peer> Connect(string ip, string fingerprint, X509Certificate2 cert, CancellationToken token)
    {
        var self = Certificate.Id(cert); var key = Key(self, fingerprint);
        var gate = gates.GetOrAdd(key, _ => new SemaphoreSlim(1,1));
        await gate.WaitAsync(token);
        try
        {
            if (!sessions.TryGetValue(key, out var session) || !session.Alive)
            {
                var raw = await Peer.ConnectRaw(ip, fingerprint, cert, token);
                try
                {
                    await Peer.Send(raw.Stream, new Message("mux", self, Name: handlers.ContainsKey(self) ? "service" : "client")).WaitAsync(TimeSpan.FromSeconds(5), token);
                    var reply = await Peer.Read(raw.Stream).WaitAsync(TimeSpan.FromSeconds(5), token);
                    if (reply?.Type != "mux-ready")
                    {
                        raw.Dispose();
                        // Old nodes still support the original pinned TLS protocol during rollout.
                        return await Peer.ConnectRaw(ip, fingerprint, cert, token);
                    }
                    session = Create(raw, self, true);
                    sessions[key] = session;
                    session.Start();
                }
                catch { raw.Dispose(); throw; }
            }
            var stream = await session.Open(token);
            return new Peer(stream, session.Fingerprint, session.RemoteId);
        }
        finally { gate.Release(); }
    }

    internal static async Task Accept(Peer raw, string self, bool bidirectional)
    {
        await Peer.Send(raw.Stream, new Message("mux-ready", self));
        var session = Create(raw, self, false);
        if (bidirectional) sessions.AddOrUpdate(Key(self, raw.RemoteFingerprint), session, (_, old) => old.Alive ? old : session);
        session.Start();
        await session.Completion;
    }

    static MultiplexSession Create(Peer raw, string self, bool client)
    {
        var session = new MultiplexSession(raw, client, async stream =>
        {
            try
            {
                if (handlers.TryGetValue(self, out var handler)) await handler(stream, raw.RemoteFingerprint, raw.RemoteId);
            }
            finally { stream.Dispose(); }
        });
        active[session] = self;
        _ = session.Completion.ContinueWith(_ => active.TryRemove(session, out var ignored), TaskScheduler.Default);
        return session;
    }

    internal static void CloseLocal(string self)
    {
        foreach (var pair in active.Where(p => p.Value == self)) pair.Key.Close();
    }
}
