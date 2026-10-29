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

record RenameNode(string? Name);

sealed class WebPanel(Store db, X509Certificate2 cert)
{
    public const int Port = 8016;
    readonly SemaphoreSlim gate = new(1, 1);
    readonly Dictionary<string, (int Failures, long Until)> attempts = new();
    readonly string csrfToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    readonly SemaphoreSlim forwardChanges = new(1,1);
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
        builder.WebHost.ConfigureKestrel(options => { options.Limits.MaxRequestBodySize=16*1024; options.ListenAnyIP(Port, endpoint => endpoint.UseHttps(webCert)); });
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
            if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
            {
                var origin=context.Request.Headers.Origin.ToString();
                if (context.Request.Headers["X-PNT-CSRF"] != csrfToken ||
                    origin.Length>0 && !string.Equals(origin,$"{context.Request.Scheme}://{context.Request.Host}",StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.StatusCode=403;return;
                }
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
            csrfToken,
            nodes = db.Nodes().Where(x => !x.Removed).Select(x => new { x.Id, x.Name, x.Ip, x.Updating, x.UpdatingSince, x.BehindNat, x.Platform }),
            pings = db.Pings(),
            links = db.Links().Where(p => p.Updated > App.Now - 30_000),
            routes = db.Nodes().Where(x => !x.Removed).SelectMany(x => db.Routes(x.Id)),
            rules = db.Rules().Where(x => !x.Removed),
            time = App.Now
        }));
        server.MapPut("/api/nodes/{id}/name", async (string id,RenameNode input,HttpContext context) =>
        {
            var name=input.Name?.Trim();
            if(string.IsNullOrEmpty(name) || name.Length>64 || name.Any(char.IsControl))
                return Results.BadRequest(new {error="Имя: от 1 до 64 символов, без управляющих символов."});
            await forwardChanges.WaitAsync(context.RequestAborted);
            try
            {
                var node=db.Nodes().FirstOrDefault(n=>n.Id==id && !n.Removed);
                if(node is null)return Results.NotFound(new {error="Узел не найден."});
                var renamed=node with{Name=name,Version=Math.Max(App.Now,node.Version+1)};
                db.Put(renamed);
                return Results.Ok(new {renamed.Id,renamed.Name});
            }
            finally{forwardChanges.Release();}
        });
        server.MapGet("/api/nodes/{node}/interfaces",async (string node,HttpContext context) =>
        {
            try {return Results.Json(await Forwarding.GetInterfaces(db,cert,node,context.RequestAborted));}
            catch(ArgumentException e){return Results.BadRequest(new {error=e.Message});}
            catch(Exception e){return Results.Json(new {error=e.GetBaseException().Message},statusCode:503);}
        });
        server.MapPost("/api/forwards",async (CreateForward input,HttpContext context) =>
        {
            await forwardChanges.WaitAsync(context.RequestAborted);
            try {return Results.Json(await Forwarding.Create(db,cert,input,context.RequestAborted),statusCode:201);}
            catch(ArgumentException e){return Results.BadRequest(new {error=e.Message});}
            catch(Exception e){return Results.Json(new {error=e.GetBaseException().Message},statusCode:503);}
            finally{forwardChanges.Release();}
        });
        server.MapDelete("/api/forwards/{ruleId}",async (string ruleId,HttpContext context) =>
        {
            await forwardChanges.WaitAsync(context.RequestAborted);
            try
            {
                var rule=db.Rules().FirstOrDefault(r=>r.Id==ruleId && !r.Removed);
                if(rule is null)return Results.NotFound(new {error="Проброс не найден."});
                db.Put(rule with {Removed=true,Version=Math.Max(App.Now,rule.Version+1)});
                return Results.Ok(new {removed=ruleId});
            }
            finally{forwardChanges.Release();}
        });
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
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite);
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
