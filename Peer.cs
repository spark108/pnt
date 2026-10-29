using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Pnt;

static class Certificate
{
    public static string Fingerprint(X509Certificate2 cert) => Convert.ToHexString(SHA256.HashData(cert.RawData));
    public static string Id(X509Certificate2 cert) => Convert.ToHexString(SHA256.HashData(cert.GetPublicKey()))[..16].ToLowerInvariant();
    public static X509Certificate2 Load(string path)
    {
        if (File.Exists(path)) return X509CertificateLoader.LoadPkcs12FromFile(path, null, X509KeyStorageFlags.Exportable);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=pnt-node", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"), new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.2")], false));
        using var created = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        File.WriteAllBytes(path, created.Export(X509ContentType.Pkcs12));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite);
        return X509CertificateLoader.LoadPkcs12FromFile(path, null, X509KeyStorageFlags.Exportable);
    }
}

sealed class Peer : IDisposable
{
    readonly TcpClient? socket;
    readonly string? fingerprint;
    readonly string? remoteId;
    public Stream Stream { get; }
    public IPAddress? RemoteAddress => socket?.Client.RemoteEndPoint is IPEndPoint endpoint ? endpoint.Address : null;
    public Message? RouteReady { get; set; }
    public string RemoteFingerprint => fingerprint!;
    public string RemoteId => remoteId!;
    Peer(TcpClient socket, SslStream stream)
    {
        this.socket = socket; Stream = stream;
        using var remote = new X509Certificate2(stream.RemoteCertificate!);
        fingerprint=Certificate.Fingerprint(remote);remoteId=Certificate.Id(remote);
    }
    internal Peer(Stream stream, string fingerprint, string remoteId) { Stream = stream; this.fingerprint = fingerprint; this.remoteId = remoteId; }
    public void Dispose() { Stream.Dispose(); socket?.Dispose(); }
    internal void EnableKeepAlive()
    {
        if(socket==null)return;
        socket.Client.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.KeepAlive,true);
        foreach(var option in new[]{(SocketOptionName.TcpKeepAliveTime,3),(SocketOptionName.TcpKeepAliveInterval,2),(SocketOptionName.TcpKeepAliveRetryCount,3)})
            try{socket.Client.SetSocketOption(SocketOptionLevel.Tcp,option.Item1,option.Item2);}catch(SocketException){}
    }

    public static Task<Peer> Connect(string ip, string expectedFingerprint, X509Certificate2 cert, CancellationToken cancellation = default)
        => MultiplexPool.Connect(ip, expectedFingerprint, cert, cancellation);

    internal static async Task<Peer> ConnectRaw(string ip, string? expectedFingerprint, X509Certificate2 cert, CancellationToken cancellation = default, int port = 442)
    {
        var tcp = new TcpClient();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await tcp.ConnectAsync(ip, port, timeout.Token);
            var tls = new SslStream(tcp.GetStream(), false, (sender, presented, chain, errors) =>
                presented != null && (expectedFingerprint is null || Certificate.Fingerprint(new X509Certificate2(presented)) == expectedFingerprint));
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "pnt-node", ClientCertificates = new X509CertificateCollection { cert },
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, timeout.Token);
            return new Peer(tcp, tls);
        }
        catch { tcp.Dispose(); throw; }
    }

    public static async Task<Peer> Accept(TcpClient tcp, X509Certificate2 cert)
    {
        try
        {
            var tls = new SslStream(tcp.GetStream(), false, (sender, presented, chain, errors) => presented != null);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = cert, ClientCertificateRequired = true, EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, timeout.Token);
            return new Peer(tcp, tls);
        }
        catch { tcp.Dispose(); throw; }
    }

    public static async Task Send(Stream stream, Message m)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(m, App.Json);
        if (bytes.Length > 4_000_000) throw new Exception("Слишком большое сообщение.");
        await stream.WriteAsync(BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(bytes.Length)));
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
    }
    public static async Task<Message?> Read(Stream stream)
    {
        var len = new byte[4];
        if (!await ReadExact(stream, len)) return null;
        var size = System.Net.IPAddress.NetworkToHostOrder(BitConverter.ToInt32(len));
        if (size is < 1 or > 4_000_000) throw new Exception("Недопустимая длина сообщения.");
        var data = new byte[size];
        if (!await ReadExact(stream, data)) return null;
        return JsonSerializer.Deserialize<Message>(data, App.Json);
    }
    static async Task<bool> ReadExact(Stream stream, byte[] bytes)
    {
        var offset = 0;
        while (offset < bytes.Length)
        {
            var n = await stream.ReadAsync(bytes.AsMemory(offset));
            if (n == 0) return false;
            offset += n;
        }
        return true;
    }
}
