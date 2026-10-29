using System.Reflection;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Pnt;

sealed class WebPanel(Store db)
{
    public const int Port = 8016;
    readonly SemaphoreSlim gate = new(1, 1);
    readonly Dictionary<string, (int Failures, long Until)> attempts = new();
    WebApplication? app;
    X509Certificate2? webCertificate;

    public async Task Refresh()
    {
        await gate.WaitAsync();
        try
        {
            var enabled = db.Web()?.Enabled == true && db.Get("left") != "1" && db.Self()?.Removed != true;
            if (enabled && app is null) await Start();
            if (!enabled && app is not null) await StopCore();
        }
        finally { gate.Release(); }
    }

    public async Task Stop()
    {
        await gate.WaitAsync();
        try { await StopCore(); }
        finally { gate.Release(); }
    }

    async Task Start()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [] });
        var webCert = LoadWebCertificate();
        builder.WebHost.ConfigureKestrel(options => options.ListenAnyIP(Port, endpoint => endpoint.UseHttps(webCert)));
        var server = builder.Build();
        server.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.XContentTypeOptions = "nosniff";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            if (db.Web() is not { Enabled: true } config) { context.Response.StatusCode = 503; return; }
            if (!Authorize(context, config))
            {
                context.Response.Headers.WWWAuthenticate = "Basic realm=\"PNT\", charset=\"UTF-8\"";
                context.Response.StatusCode = 401;
                return;
            }
            await next();
        });
        var resource = Assembly.GetExecutingAssembly().GetManifestResourceNames()
            .Single(x => x.EndsWith(".web.index.html", StringComparison.OrdinalIgnoreCase));
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)!;
        using var reader = new StreamReader(stream);
        var html = reader.ReadToEnd();
        server.MapGet("/", () => Results.Content(html, "text/html; charset=utf-8"));
        server.MapGet("/api/state", () => Results.Json(new
        {
            self = db.Get("self"),
            nodes = db.Nodes().Where(x => !x.Removed).Select(x => new { x.Id, x.Name, x.Ip, x.Updating, x.UpdatingSince }),
            pings = db.Pings(),
            links = db.Links().Where(p => p.Updated > App.Now - 30_000),
            rules = db.Rules().Where(x => !x.Removed).Select(x => new { x.Id, x.In, x.InPort, x.Via, x.To, x.ToPort }),
            time = App.Now
        }));
        try
        {
            await server.StartAsync();
            app = server;
            webCertificate = webCert;
            Firewall.Open(Port);
            Console.WriteLine($"pnt: web listening on HTTPS {Port}");
        }
        catch { await server.DisposeAsync(); webCert.Dispose(); throw; }
    }

    X509Certificate2 LoadWebCertificate()
    {
        var path = Path.Combine(App.Dir, "web.pfx");
        var address = IPAddress.Parse(db.Self()!.Ip);
        if (File.Exists(path))
        {
            var existing = X509CertificateLoader.LoadPkcs12FromFile(path, null, X509KeyStorageFlags.Exportable);
            var san = existing.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            if (san?.EnumerateIPAddresses().Contains(address) == true && existing.NotAfter > DateTime.Now.AddDays(7)) return existing;
            existing.Dispose();
        }
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=PNT Web", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(address);
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1")], false));
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        File.WriteAllBytes(path, created.Export(X509ContentType.Pkcs12));
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return X509CertificateLoader.LoadPkcs12FromFile(path, null, X509KeyStorageFlags.Exportable);
    }

    bool Authorize(HttpContext context, WebConfig config)
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        lock (attempts)
        {
            if (attempts.TryGetValue(ip, out var state) && state.Until > App.Now) return false;
        }
        var valid = false;
        try
        {
            var header = context.Request.Headers.Authorization.ToString();
            if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase) && header.Length < 2048)
            {
                var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..]));
                var separator = credentials.IndexOf(':');
                if (separator >= 0 && credentials[..separator] == "admin")
                {
                    var computed = Rfc2898DeriveBytes.Pbkdf2(credentials[(separator + 1)..],
                        Convert.FromHexString(config.Salt), 210_000, HashAlgorithmName.SHA256, 32);
                    valid = CryptographicOperations.FixedTimeEquals(computed, Convert.FromHexString(config.Hash));
                }
            }
        }
        catch (FormatException) { }
        lock (attempts)
        {
            if (valid) attempts.Remove(ip);
            else
            {
                var failures = attempts.TryGetValue(ip, out var state) && state.Until > App.Now - 60_000 ? state.Failures + 1 : 1;
                attempts[ip] = (failures, failures >= 5 ? App.Now + 30_000 : App.Now);
            }
        }
        return valid;
    }

    async Task StopCore()
    {
        if (app is null) return;
        var old = app;
        app = null;
        await old.StopAsync();
        await old.DisposeAsync();
        webCertificate?.Dispose();
        webCertificate = null;
        Firewall.Close(Port);
        Console.WriteLine("pnt: web stopped");
    }
}
