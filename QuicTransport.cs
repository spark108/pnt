using System.Collections.Concurrent;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;

namespace Pnt;

static class QuicTransport
{
    [SupportedOSPlatformGuard("windows")]
    [SupportedOSPlatformGuard("linux")]
    internal static bool Supported => (OperatingSystem.IsWindows() || OperatingSystem.IsLinux()) && QuicConnection.IsSupported;
    internal static bool Enabled => Environment.GetEnvironmentVariable("PNT_DISABLE_QUIC") != "1";
    static readonly SslApplicationProtocol protocol = new("pnt/1");
    static readonly ConcurrentDictionary<string, Session> sessions = new();
    static readonly ConcurrentDictionary<Session, string> active = new();
    static readonly ConcurrentDictionary<string, SemaphoreSlim> gates = new();
    static readonly ConcurrentDictionary<string, long> retryAfter = new();
    static readonly ConcurrentDictionary<string, Func<Stream, string, string, Task>> handlers = new();
    static string Key(string self, string fingerprint, int port) => self + ":" + fingerprint + ":" + port;

    internal static void Register(string self, Func<Stream, string, string, Task> handler) => handlers[self] = handler;

    internal static bool DisposeStream(Stream stream)
    {
        if (!Supported || stream is not QuicStream quic) return false;
        _ = FinishStream(quic); return true;
    }
    static async Task FinishStream(QuicStream stream)
    {
        if (!Supported) return;
        try
        {
            var closing = stream.DisposeAsync().AsTask();
            try { await closing.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (TimeoutException) { stream.Abort(QuicAbortDirection.Both, 2); await closing; }
        }
        catch { }
    }

    internal static async Task<Peer?> Connect(string host, string fingerprint, X509Certificate2 cert, CancellationToken token, int port = 442)
    {
        token.ThrowIfCancellationRequested();
        if (!Enabled || !Supported) return null;
        var self = Certificate.Id(cert); var key = Key(self, fingerprint, port);
        var gate = gates.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(token);
        try
        {
            if (sessions.TryGetValue(key, out var current) && current.Alive)
            {
                try { return await current.Open(token); }
                catch when (!token.IsCancellationRequested)
                {
                    current.Close(); retryAfter[key] = Environment.TickCount64 + 30_000; return null;
                }
            }
            if (retryAfter.TryGetValue(key, out var due) && Environment.TickCount64 < due) return null;
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token);
            limit.CancelAfter(TimeSpan.FromSeconds(2));
            QuicConnection? connection = null;
            try
            {
                connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
                {
                    RemoteEndPoint = new DnsEndPoint(host, port),
                    DefaultCloseErrorCode = 1, DefaultStreamErrorCode = 2,
                    MaxInboundBidirectionalStreams = 256, MaxInboundUnidirectionalStreams = 0,
                    IdleTimeout = TimeSpan.FromSeconds(45), KeepAliveInterval = TimeSpan.FromSeconds(10),
                    ClientAuthenticationOptions = new SslClientAuthenticationOptions
                    {
                        TargetHost = "pnt-node", ApplicationProtocols = [protocol],
                        ClientCertificates = new X509CertificateCollection { cert },
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        RemoteCertificateValidationCallback = (_, presented, _, _) => Matches(presented, fingerprint)
                    }
                }, limit.Token);
                var control = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, limit.Token);
                await Peer.Send(control, new Message("quic", self, Name: handlers.ContainsKey(self) ? "service" : "client")).WaitAsync(limit.Token);
                var reply = await Peer.Read(control).WaitAsync(limit.Token);
                using var remote = new X509Certificate2(connection.RemoteCertificate!);
                if (reply?.Type != "quic-ready" || reply.Id != Certificate.Id(remote)) throw new IOException("QUIC channel not authorized.");
                var session = new Session(connection, control, self);
                sessions[key] = session;
                retryAfter.TryRemove(key, out _);
                session.Start();
                connection = null;
                try { return await session.Open(token); }
                catch when (!token.IsCancellationRequested) { session.Close(); throw; }
            }
            catch when (!token.IsCancellationRequested)
            {
                retryAfter[key] = Environment.TickCount64 + 30_000;
                return null;
            }
            finally { if (connection is not null) await connection.DisposeAsync(); }
        }
        finally { gate.Release(); }
    }

    static bool Matches(X509Certificate? presented, string fingerprint)
    {
        if (presented is null) return false;
        using var cert = new X509Certificate2(presented);
        return Certificate.Fingerprint(cert) == fingerprint;
    }

    internal static async Task<QuicListener?> Listen(X509Certificate2 cert, IPEndPoint endpoint, Func<string, string, bool> authorized, CancellationToken token)
    {
        if (!Enabled || !Supported) return null;
        var options = new QuicServerConnectionOptions
            {
                DefaultCloseErrorCode = 1, DefaultStreamErrorCode = 2,
                MaxInboundBidirectionalStreams = 256, MaxInboundUnidirectionalStreams = 0,
                IdleTimeout = TimeSpan.FromSeconds(45), KeepAliveInterval = TimeSpan.FromSeconds(10),
                HandshakeTimeout = TimeSpan.FromSeconds(5),
                ServerAuthenticationOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificate = cert, ClientCertificateRequired = true, ApplicationProtocols = [protocol],
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    RemoteCertificateValidationCallback = (_, presented, _, _) =>
                    {
                        if (presented is null) return false;
                        using var remote = new X509Certificate2(presented);
                        return authorized(Certificate.Id(remote), Certificate.Fingerprint(remote));
                    }
                }
            };
        return await QuicListener.ListenAsync(new QuicListenerOptions
        {
            ListenEndPoint = endpoint, ApplicationProtocols = [protocol], ListenBacklog = 64,
            ConnectionOptionsCallback = (_, _, _) => Supported ? ValueTask.FromResult(options) : throw new PlatformNotSupportedException()
        }, token);
    }

    internal static async Task AcceptLoop(QuicListener listener, string self, Func<string, string, bool> authorized, Action<string, IPAddress> observed, CancellationToken token)
    {
        if (!Supported) return;
        try
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var connection = await listener.AcceptConnectionAsync(token);
                    _ = Accept(connection, self, authorized, observed, token);
                }
                catch (QuicException) when (!token.IsCancellationRequested) { }
                catch (AuthenticationException) when (!token.IsCancellationRequested) { }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (token.IsCancellationRequested) { }
    }

    static async Task Accept(QuicConnection connection, string self, Func<string, string, bool> authorized, Action<string, IPAddress> observed, CancellationToken token)
    {
        if (!Supported) return;
        var adopted = false;
        try
        {
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token);
            limit.CancelAfter(TimeSpan.FromSeconds(5));
            using var remote = new X509Certificate2(connection.RemoteCertificate!);
            var remoteId = Certificate.Id(remote); var fingerprint = Certificate.Fingerprint(remote);
            var control = await connection.AcceptInboundStreamAsync(limit.Token);
            var hello = await Peer.Read(control).WaitAsync(limit.Token);
            if (hello?.Type != "quic" || hello.Id != remoteId || hello.Name is not ("service" or "client") || !authorized(remoteId, fingerprint))
                throw new IOException("QUIC channel not authorized.");
            observed(remoteId, connection.RemoteEndPoint.Address);
            await Peer.Send(control, new Message("quic-ready", self)).WaitAsync(limit.Token);
            var session = new Session(connection, control, self);
            if (hello.Name == "service")
                sessions.AddOrUpdate(Key(self, fingerprint, ((IPEndPoint)connection.LocalEndPoint).Port), session, (_, old) => old.Alive ? old : session);
            session.Start(); adopted = true;
        }
        catch { }
        finally { if (!adopted) { try { await connection.DisposeAsync(); } catch { } } }
    }

    internal static void CloseLocal(string self)
    {
        if (!Supported) return;
        foreach (var pair in active.Where(p => p.Value == self)) pair.Key.Close();
        foreach (var pair in sessions.Where(p => p.Key.StartsWith(self + ":", StringComparison.Ordinal))) sessions.TryRemove(pair.Key, out _);
        foreach (var pair in retryAfter.Where(p => p.Key.StartsWith(self + ":", StringComparison.Ordinal))) retryAfter.TryRemove(pair.Key, out _);
    }

    sealed class Session
    {
        readonly QuicConnection connection;
        readonly QuicStream control;
        readonly string self;
        readonly CancellationTokenSource stop = new();
        readonly string fingerprint, remoteId;
        int closed;
        public bool Alive => Volatile.Read(ref closed) == 0;
        public Session(QuicConnection connection, QuicStream control, string self)
        {
            if (!Supported) throw new PlatformNotSupportedException();
            this.connection = connection; this.control = control; this.self = self;
            using var remote = new X509Certificate2(connection.RemoteCertificate!);
            fingerprint = Certificate.Fingerprint(remote); remoteId = Certificate.Id(remote);
            active[this] = self;
        }
        public void Start() { _ = Run(); }
        public async Task<Peer> Open(CancellationToken token)
        {
            if (!Supported) throw new PlatformNotSupportedException();
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token, stop.Token);
            limit.CancelAfter(TimeSpan.FromSeconds(2));
            var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, limit.Token);
            try
            {
                await Peer.Send(stream, new Message("quic-open", self)).WaitAsync(limit.Token);
                var ready = await Peer.Read(stream).WaitAsync(limit.Token);
                if (ready?.Type != "quic-open-ready" || ready.Id != remoteId) throw new IOException("QUIC stream not confirmed.");
                return new Peer(stream, fingerprint, remoteId, connection.RemoteEndPoint.Address, "quic");
            }
            catch { stream.Abort(QuicAbortDirection.Both, 2); await FinishStream(stream); throw; }
        }
        async Task Run()
        {
            if (!Supported) return;
            try
            {
                var ending = control.ReadAsync(new byte[1], stop.Token).AsTask();
                var accepting = AcceptStreams();
                try { await Task.WhenAny(ending, accepting); }
                finally
                {
                    Close();
                    try { await Task.WhenAll(ending, accepting); } catch { }
                }
            }
            catch { }
            finally { Close(); }
        }
        async Task AcceptStreams()
        {
            if (!Supported) return;
            while (!stop.IsCancellationRequested)
            {
                var stream = await connection.AcceptInboundStreamAsync(stop.Token);
                _ = Handle(stream);
            }
        }
        async Task Handle(QuicStream stream)
        {
            if (!Supported) return;
            try
            {
                var opening = await Peer.Read(stream).WaitAsync(TimeSpan.FromSeconds(5), stop.Token);
                if (opening?.Type != "quic-open" || opening.Id != remoteId) throw new IOException("Invalid QUIC stream header.");
                await Peer.Send(stream, new Message("quic-open-ready", self)).WaitAsync(stop.Token);
                if (handlers.TryGetValue(self, out var handler)) await handler(stream, fingerprint, remoteId);
            }
            catch { }
            finally { await FinishStream(stream); }
        }
        public void Close()
        {
            if (Interlocked.Exchange(ref closed, 1) != 0) return;
            stop.Cancel(); active.TryRemove(this, out _);
            _ = Dispose();
        }
        async Task Dispose()
        {
            if (!Supported) return;
            try { await connection.CloseAsync(1); } catch { }
            try { await control.DisposeAsync(); } catch { }
            try { await connection.DisposeAsync(); } catch { }
        }
    }
}
