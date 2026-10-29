using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

sealed class Service(Store db, X509Certificate2 cert)
{
    readonly string id = Certificate.Id(cert);
    readonly Dictionary<string, TcpListener> listeners = new();
    readonly CancellationTokenSource stop = new();
    readonly Dictionary<string, Task> checks = new();
    readonly WebPanel web = new(db);

    public async Task Run()
    {
        var control = new TcpListener(IPAddress.Any, 442); control.Start();
        Firewall.Open(442);
        Console.WriteLine("pnt: service listening on TCP 442");
        using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, x => { x.Cancel = true; stop.Cancel(); });
        Console.CancelKeyPress += (_, x) => { x.Cancel = true; stop.Cancel(); };
        _ = Task.Run(Maintain);
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var socket = await control.AcceptTcpClientAsync(stop.Token);
                _ = Task.Run(async () => { try { await Handle(socket); } catch (Exception e) { Console.Error.WriteLine("pnt: peer: " + e.Message); socket.Dispose(); } });
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            await web.Stop();
            control.Stop();
            foreach (var l in listeners.Values) { Firewall.Close(((IPEndPoint)l.LocalEndpoint).Port); l.Stop(); }
            Firewall.Close(442);
        }
    }

    async Task Handle(TcpClient socket)
    {
        using var peer = await Peer.Accept(socket, cert);
        var request = await Peer.Read(peer.Stream);
        if (request == null) return;
        if (request.Type == "join") { await Join(peer, request); return; }
        var known = db.Nodes().FirstOrDefault(x => x.Id == request.Id && x.Cert == peer.RemoteFingerprint);
        if (known?.Removed == true && request.Type == "sync")
        {
            await Peer.Send(peer.Stream, Sync());
            return;
        }
        if (known == null || known.Removed || db.Get("left") == "1" || db.Self()?.Removed == true)
        {
            await Peer.Send(peer.Stream, new Message("error", Error: "Узел не состоит в кластере или исключён.")); return;
        }
        switch (request.Type)
        {
            case "sync":
                Merge(request);
                await Peer.Send(peer.Stream, Sync());
                break;
            case "probe":
                if (request.Target == id) await Peer.Send(peer.Stream, new Message("ok", Hops: (request.Hops ?? []).Append(id).ToArray()));
                else await RelayProbe(peer.Stream, request);
                break;
            case "exec":
                if (request.Target == id) await Execute(peer.Stream, request);
                else await RelayRequest(peer.Stream, request);
                break;
            case "ping-external":
                if (request.Target == id) await ExecuteExternalPing(peer.Stream, request);
                else await RelayRequest(peer.Stream, request);
                break;
            case "tcp-check":
                if (request.Target == id)
                {
                    await Peer.Send(peer.Stream, new Message("ready", Hops: (request.Hops ?? []).Append(id).ToArray()));
                    var check = await Management.CheckSsh(request.Host ?? "");
                    await Peer.Send(peer.Stream, new Message("ping-result", Ip: check.Ip, PingMs: check.Ms, Error: check.Error));
                }
                else await RelayRequest(peer.Stream, request);
                break;
            case "tunnel": await Tunnel(peer.Stream, request); break;
            default: await Peer.Send(peer.Stream, new Message("error", Error: "Неизвестный запрос.")); break;
        }
    }

    async Task Join(Peer peer, Message m)
    {
        var invite = db.Invites().FirstOrDefault(x => x.Id == m.Target && x.Secret == m.Secret && !x.Used && x.Expires > App.Now);
        if (invite == null || m.Id != peer.RemoteId || m.Name == null || m.Ip == null || m.Cert != peer.RemoteFingerprint ||
            m.Ip != invite.Ip || !IPAddress.TryParse(m.Ip, out _))
        {
            await Peer.Send(peer.Stream, new Message("error", Error: "Недействительное приглашение, сертификат или адрес узла.")); return;
        }
        if (m.Name.Length is < 1 or > 64 || db.Nodes().Any(x => x.Id == m.Id))
        {
            await Peer.Send(peer.Stream, new Message("error", Error: "Имя недопустимо или ID узла уже использован.")); return;
        }
        if (!db.Consume(invite)) { await Peer.Send(peer.Stream, new Message("error", Error: "Приглашение уже использовано.")); return; }
        db.Put(new Node(m.Id, m.Name, m.Ip, m.Cert, App.Now));
        await Peer.Send(peer.Stream, new Message("welcome", id, Nodes: db.Nodes().ToArray(), Rules: db.Rules().ToArray(), KeyHash: db.Get("key_hash"), Update: db.Update(), Web: db.Web()));
    }

    Message Sync() => new("sync", id, Nodes: db.Nodes().ToArray(), Rules: db.Rules().ToArray(), Update: db.Update(), Pings: db.Pings().ToArray(), Web: db.Web());

    void Merge(Message m)
    {
        foreach (var n in m.Nodes ?? [])
        {
            var old = db.Nodes().FirstOrDefault(x => x.Id == n.Id);
            // A member's certificate is immutable, including across gossip updates.
            if (old != null && old.Cert != n.Cert) continue;
            if (n.Ip.Length > 64 || n.Name.Length > 64) continue;
            db.Put(n);
        }
        foreach (var r in m.Rules ?? []) db.Put(r);
        foreach (var ping in m.Pings ?? []) db.PutPing(ping);
        if (m.Update is not null) db.PutUpdate(m.Update);
        if (m.Web is not null) db.PutWeb(m.Web);
    }

    async Task Maintain()
    {
        while (!stop.IsCancellationRequested)
        {
            try
            {
                await web.Refresh();
                await RefreshListeners();
                if (db.Get("cluster") != null && (db.Self()?.Removed != true || db.Get("left") == "1"))
                {
                    foreach (var n in db.Nodes().Where(x => !x.Removed && x.Id != id))
                    {
                        if (!checks.TryGetValue(n.Id, out var previous) || previous.IsCompleted)
                            checks[n.Id] = CheckNode(n);
                    }
                    foreach (var key in checks.Where(x => x.Value.IsCompleted && db.Resolve(x.Key) is null).Select(x => x.Key).ToArray()) checks.Remove(key);
                    if (db.Self()?.Removed != true) LaunchPendingUpdate();
                }
            }
            catch (Exception e) { Console.Error.WriteLine("pnt: maintenance: " + e.Message); }
            await Task.Delay(5000, stop.Token);
        }
    }

    async Task CheckNode(Node node)
    {
        try
        {
            var watch = Stopwatch.StartNew();
            using var peer = await Peer.Connect(node.Ip, node.Cert, cert);
            await Peer.Send(peer.Stream, Sync()).WaitAsync(TimeSpan.FromSeconds(8));
            var reply = await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(8));
            if (reply?.Type != "sync") throw new IOException("Нет ответа синхронизации.");
            Merge(reply);
            db.SetPing(node.Id, watch.Elapsed.TotalMilliseconds, true, [id, node.Id]);
        }
        catch
        {
            if (stop.IsCancellationRequested) return;
            try { await Probe(node.Id, [], true); }
            catch { }
        }
    }

    void LaunchPendingUpdate()
    {
        var update = db.Update();
        if (update is null || db.Get("update_applied") == update.Id) return;
        if (db.Get("update_attempt_id") == update.Id && long.TryParse(db.Get("update_attempt_time"), out var last) && App.Now - last < 300_000) return;
        db.Set("update_attempt_id", update.Id);
        db.Set("update_attempt_time", App.Now.ToString());
        const string sourceFile = "/etc/pnt/source-dir";
        if (!File.Exists(sourceFile)) { Console.Error.WriteLine("pnt: путь исходников для автообновления не настроен."); return; }
        var script = Path.Combine(File.ReadAllText(sourceFile).Trim(), "pnt.sh");
        if (!File.Exists(script)) { Console.Error.WriteLine("pnt: скрипт автообновления не найден: " + script); return; }
        try
        {
            using var process = new Process { StartInfo = new ProcessStartInfo("systemd-run") { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true } };
            var invoker = File.Exists("/etc/pnt/invoker") ? File.ReadAllText("/etc/pnt/invoker").Trim() : "root";
            foreach (var arg in new[] { "--unit=pnt-update-" + update.Id[..12], "--collect", "--property=Type=exec", "--setenv=PNT_INVOKER=" + invoker, "/bin/sh", script, "_worker", "update", update.Id, update.Id }) process.StartInfo.ArgumentList.Add(arg);
            process.Start();
            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit(10_000);
            if (!process.HasExited || process.ExitCode != 0) Console.Error.WriteLine("pnt: автообновление не запущено: " + output);
            else Console.WriteLine("pnt: запущено автообновление " + update.Commit);
        }
        catch (Exception e) { Console.Error.WriteLine("pnt: автообновление: " + e.Message); }
    }

    async Task RefreshListeners()
    {
        var desired = db.Get("left") == "1" || db.Self()?.Removed == true
            ? new Dictionary<string, Rule>()
            : db.Rules().Where(x => !x.Removed && x.In == id).ToDictionary(x => x.Id);
        foreach (var key in listeners.Keys.Except(desired.Keys).ToArray())
        {
            var port = ((IPEndPoint)listeners[key].LocalEndpoint).Port;
            listeners[key].Stop(); listeners.Remove(key); Firewall.Close(port);
        }
        foreach (var (key, rule) in desired)
        {
            if (listeners.ContainsKey(key)) continue;
            try
            {
                var listener = new TcpListener(IPAddress.Any, rule.InPort); listener.Start(); listeners[key] = listener;
                Firewall.Open(rule.InPort);
                _ = Task.Run(async () =>
                {
                    while (listeners.ContainsKey(key))
                    {
                        try
                        {
                            var client = await listener.AcceptTcpClientAsync();
                            _ = Task.Run(async () => { using (client) { try { await Forward(client.GetStream(), rule); } catch (Exception e) { Console.Error.WriteLine("pnt: forward: " + e.Message); } } });
                        }
                        catch (ObjectDisposedException) { break; }
                        catch (SocketException) { break; }
                    }
                });
            }
            catch (Exception e) { Console.Error.WriteLine($"pnt: cannot listen {rule.InPort}: {e.Message}"); }
        }
    }

    async Task Forward(Stream incoming, Rule r)
    {
        var target = db.Resolve(r.To);
        if (r.Via == id || (r.Via == null && target?.Id == id))
        {
            using var tcp = new TcpClient(); await tcp.ConnectAsync(target == null ? r.To : target.Id == id ? IPAddress.Loopback.ToString() : target.Ip, r.ToPort);
            await CopyBoth(incoming, tcp.GetStream()); return;
        }
        var routeTarget = r.Via ?? target?.Id ?? throw new Exception("Назначение недоступно.");
        using var route = await OpenRoute(routeTarget, new Message("tunnel", id, Target: r.To, Port: r.ToPort, Via: r.Via, Hops: [id]));
        await CopyBoth(incoming, route.Stream);
    }

    async Task Tunnel(Stream incoming, Message request)
    {
        if (request.Hops?.Contains(id) == true || (request.Hops?.Length ?? 0) > 8) { await Peer.Send(incoming, new Message("error", Error: "Петля маршрута.")); return; }
        var target = db.Resolve(request.Target ?? "");
        if (request.Via == id || (request.Via == null && target?.Id == id))
        {
            var host = target == null ? request.Target! : target.Id == id ? IPAddress.Loopback.ToString() : target.Ip;
            if (target == null && (!IPAddress.TryParse(host, out _) || request.Via != id)) { await Peer.Send(incoming, new Message("error", Error: "Внешний IP запрещён.")); return; }
            using var tcp = new TcpClient();
            try { await tcp.ConnectAsync(host, request.Port); }
            catch (Exception e) { await Peer.Send(incoming, new Message("error", Error: e.Message)); return; }
            await Peer.Send(incoming, new Message("ready")); await CopyBoth(incoming, tcp.GetStream()); return;
        }
        var destination = request.Via ?? target?.Id;
        if (destination == null) { await Peer.Send(incoming, new Message("error", Error: "Узел не найден.")); return; }
        try
        {
            using var route = await OpenRoute(destination, request with { Id = id, Hops = (request.Hops ?? []).Append(id).ToArray() });
            await Peer.Send(incoming, new Message("ready")); await CopyBoth(incoming, route.Stream);
        }
        catch (Exception e) { await Peer.Send(incoming, new Message("error", Error: e.Message)); }
    }

    async Task<Peer> OpenRoute(string destination, Message request)
    {
        var nodes = RoutePlanner.Candidates(db, id, destination, request.Hops ?? []).ToArray();
        foreach (var n in nodes)
        {
            Peer? p = null;
            try
            {
                p = await Peer.Connect(n.Ip, n.Cert, cert);
                await Peer.Send(p.Stream, request);
                var answer = await Peer.Read(p.Stream).WaitAsync(TimeSpan.FromSeconds(30));
                if (answer?.Type == "ready") { p.RouteReady = answer; return p; }
            }
            catch { }
            p?.Dispose();
        }
        throw new Exception("Маршрут к узлу не найден.");
    }

    async Task RelayProbe(Stream incoming, Message request)
    {
        try
        {
            var route = await Probe(request.Target!, request.Hops ?? []);
            await Peer.Send(incoming, new Message("ok", Hops: route));
        }
        catch { await Peer.Send(incoming, new Message("error", Error: "Узел недоступен.")); }
    }

    async Task<string[]> Probe(string target, string[] hops, bool skipDirect = false)
    {
        if (hops.Contains(id) || hops.Length > 8 || db.Resolve(target) is null) throw new Exception("Петля маршрута или узел не найден.");
        var nodes = RoutePlanner.Candidates(db, id, target, hops, skipDirect);
        foreach (var n in nodes)
        {
            try
            {
                var watch = Stopwatch.StartNew(); using var p = await Peer.Connect(n.Ip, n.Cert, cert);
                await Peer.Send(p.Stream, new Message("probe", id, Target: target, Hops: hops.Append(id).ToArray()));
                var answer = await Peer.Read(p.Stream).WaitAsync(TimeSpan.FromSeconds(30));
                if (answer?.Type == "ok" && answer.Hops is { Length: > 1 } path &&
                    path[0] == (hops.FirstOrDefault() ?? id) && path[^1] == target && path.Contains(id))
                {
                    var localRoute = path.SkipWhile(x => x != id).ToArray();
                    db.SetPing(target, watch.Elapsed.TotalMilliseconds, localRoute.Length == 2, localRoute);
                    return path;
                }
            }
            catch { }
        }
        throw new Exception("Нет связи.");
    }

    async Task RelayRequest(Stream incoming, Message request)
    {
        if (request.Hops?.Contains(id) == true || (request.Hops?.Length ?? 0) > 8 ||
            request.Target is null || db.Resolve(request.Target) is null)
        {
            await Peer.Send(incoming, new Message("error", Error: "Маршрут к узлу не найден.")); return;
        }
        try
        {
            using var route = await OpenRoute(request.Target, request with
            {
                Id = id, Hops = (request.Hops ?? []).Append(id).ToArray()
            });
            await Peer.Send(incoming, new Message("ready", Hops: route.RouteReady?.Hops));
            await CopyBoth(incoming, route.Stream);
        }
        catch (Exception e) { await Peer.Send(incoming, new Message("error", Error: e.Message)); }
    }

    async Task ExecuteExternalPing(Stream incoming, Message request)
    {
        if (request.Host is null)
        {
            await Peer.Send(incoming, new Message("error", Error: "Не указана цель пинга.")); return;
        }
        await Peer.Send(incoming, new Message("ready", Hops: (request.Hops ?? []).Append(id).ToArray()));
        var result = await ExternalPing.Measure(request.Host);
        await Peer.Send(incoming, new Message("ping-result", Ip: result.Ip, PingMs: result.Ms, Error: result.Error));
    }

    async Task Execute(Stream incoming, Message request)
    {
        if (request.Command is not { Length: > 0 and <= 16_384 })
        {
            await Peer.Send(incoming, new Message("error", Error: "Пустая или слишком длинная команда.")); return;
        }
        using var process = new Process { StartInfo = new ProcessStartInfo(request.Interactive ? "/usr/bin/script" : "/bin/sh")
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            RedirectStandardInput = request.Interactive, WorkingDirectory = App.Dir
        } };
        if (request.Interactive) { process.StartInfo.ArgumentList.Add("-qef"); }
        process.StartInfo.ArgumentList.Add("-c");
        process.StartInfo.ArgumentList.Add(request.Command);
        if (request.Interactive) process.StartInfo.ArgumentList.Add("/dev/null");
        try { process.Start(); }
        catch (Exception e) { await Peer.Send(incoming, new Message("error", Error: e.Message)); return; }
        try
        {
            await Peer.Send(incoming, new Message("ready", Hops: (request.Hops ?? []).Append(id).ToArray()));
            _ = Task.Run(async () =>
            {
                try
                {
                    while (await Peer.Read(incoming) is Message input)
                        if (request.Interactive && input.Type == "exec-input")
                        {
                            await process.StandardInput.WriteAsync(input.Output);
                            await process.StandardInput.FlushAsync();
                        }
                }
                catch { }
                try { if (!process.HasExited) process.Kill(true); }
                catch { }
            });
            using var writeLock = new SemaphoreSlim(1, 1);
            async Task Pump(StreamReader reader, bool stderr)
            {
                var buffer = new char[4096];
                int count;
                while ((count = await reader.ReadAsync(buffer)) > 0)
                {
                    await writeLock.WaitAsync();
                    try { await Peer.Send(incoming, new Message("exec-output", Output: new string(buffer, 0, count), Stderr: stderr)); }
                    finally { writeLock.Release(); }
                }
            }
            await Task.WhenAll(Pump(process.StandardOutput, false), Pump(process.StandardError, true), process.WaitForExitAsync());
            await Peer.Send(incoming, new Message("exec-exit", ExitCode: process.ExitCode));
        }
        catch
        {
            if (!process.HasExited) process.Kill(true);
            throw;
        }
    }

    static async Task CopyBoth(Stream a, Stream b)
    {
        using var done = new CancellationTokenSource();
        var first = a.CopyToAsync(b, done.Token); var second = b.CopyToAsync(a, done.Token);
        await Task.WhenAny(first, second); done.Cancel();
        try { await Task.WhenAll(first, second); } catch (OperationCanceledException) { } catch (IOException) { }
    }
}
