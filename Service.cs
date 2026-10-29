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
    readonly Dictionary<string, (Task Work, long Due)> routeScans = new();
    Task topologyWork = Task.CompletedTask;
    Task bootstrapWork = Task.CompletedTask;
    readonly WebPanel web = new(db, cert);
    readonly RouteTransport routing = new(db, cert);

    public async Task Run()
    {
        RegisterMultiplex();
        if(db.Get("bootstrap_peer_cert") is string fp && db.Get("bootstrap_host") is string host)MultiplexPool.SetAddress(id,fp,host);
        if(db.Self() is Node own && own.Platform!=App.Platform)db.Put(own with{Platform=App.Platform,Version=Math.Max(App.Now,own.Version+1)});
        var control = new TcpListener(IPAddress.Any, 442); control.Start();
        Firewall.Open(442);
        Console.WriteLine("pnt: service listening on TCP 442");
        using var term = OperatingSystem.IsLinux() ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, x => { x.Cancel = true; stop.Cancel(); }) : null;
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
            MultiplexPool.CloseLocal(id);
            await web.Stop();
            control.Stop();
            foreach (var l in listeners.Values) { Firewall.Close(((IPEndPoint)l.LocalEndpoint).Port); l.Stop(); }
            Firewall.Close(442);
        }
    }
    public void Stop()=>stop.Cancel();

    async Task Handle(TcpClient socket)
    {
        RegisterMultiplex();
        using var peer = await Peer.Accept(socket, cert);
        var request = await Peer.Read(peer.Stream);
        if (request == null) return;
        if(request.Type=="enroll"){await Enrollment.Receive(db,cert,peer,request,stop.Token);return;}
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
        if (request.Type == "mux")
        {
            if(!known.BehindNat && Enrollment.Private(known.Ip) && peer.RemoteAddress is IPAddress remoteAddress && remoteAddress.MapToIPv4().ToString()!=known.Ip)
                db.Put(known with{BehindNat=true,Version=Math.Max(App.Now,known.Version+1)});
            await MultiplexPool.Accept(peer, id, request.Name == "service"); return;
        }
        await Dispatch(peer.Stream, request);
    }

    void RegisterMultiplex() => MultiplexPool.Register(id, async (stream, fingerprint, remote) =>
    {
        var request = await Peer.Read(stream).WaitAsync(TimeSpan.FromSeconds(20));
        if (request is null) return;
        var member = db.Resolve(remote);
        if (member is null || member.Cert != fingerprint || request.Id != remote || db.Get("left") == "1" || db.Self()?.Removed == true)
        {
            await Peer.Send(stream, new Message("error", Error: "Узел не состоит в активном кластере.", RequestId: request.RequestId)); return;
        }
        await Dispatch(stream, request);
    });

    async Task Dispatch(Stream stream, Message request, bool routed = false)
    {
        switch (request.Type)
        {
            case "route-info":
                await Peer.Send(stream, new Message("route-info", id, Pings: db.Pings().ToArray(), Links: db.Links().ToArray())); break;
            case "route-search":
                if (request.Hops is {Length: > 0} trail && trail[^1] == request.Id || request.Id == id && request.Hops is {Length: 0})
                    await Peer.Send(stream, new Message("route-found", id, RequestId: request.RequestId, Routes: await routing.Search(request)));
                break;
            case "route-open":
                await OpenFixedRoute(stream, request); break;
            case "sync":
                Merge(request);
                await Peer.Send(stream, Sync() with { RequestId = request.RequestId });
                break;
            case "probe":
                if (request.Target == id) await Peer.Send(stream, new Message("ok", Hops: (request.Hops ?? []).Append(id).ToArray(), RequestId: request.RequestId));
                else await RelayProbe(stream, request);
                break;
            case "exec":
                if (request.Target == id) await Execute(stream, request, !routed);
                else await RelayRequest(stream, request);
                break;
            case "exec-route":
                if (request.Target == id)
                {
                    await Peer.Send(stream, new Message("ready", Hops: (request.Hops ?? []).Append(id).ToArray()));
                    var command = await Peer.Read(stream).WaitAsync(TimeSpan.FromSeconds(30));
                    if (command?.Type == "exec" && command.Target == id)
                        await Execute(stream, command with { Hops = request.Hops }, false);
                }
                else await RelayRequest(stream, request);
                break;
            case "ping-external":
                if (request.Target == id) await ExecuteExternalPing(stream, request, !routed);
                else await RelayRequest(stream, request);
                break;
            case "tcp-check":
                if (request.Target == id)
                {
                    if (!routed) await Peer.Send(stream, new Message("ready", Hops: (request.Hops ?? []).Append(id).ToArray()));
                    var check = await Management.CheckSsh(request.Host ?? "");
                    await Peer.Send(stream, new Message("ping-result", Ip: check.Ip, PingMs: check.Ms, Error: check.Error, RequestId: request.RequestId));
                }
                else await RelayRequest(stream, request);
                break;
            case "interfaces":
                if (request.Target == id)
                    await Peer.Send(stream,new Message("interfaces",id,Interfaces:Forwarding.Interfaces(),RequestId:request.RequestId));
                break;
            case "tunnel": await Tunnel(stream, request); break;
            default: await Peer.Send(stream, new Message("error", Error: "Неизвестный запрос.")); break;
        }
    }

    async Task OpenFixedRoute(Stream incoming, Message request)
    {
        var path = request.Hops;
        var index = path is null ? -1 : Array.IndexOf(path, id);
        if (path is null || path.Length is < 1 or > 10 || path.Distinct().Count() != path.Length ||
            index < 0 || path[^1] != request.Target || request.RequestId is not { Length: 32 } ||
            request.Deadline <= App.Now || request.Deadline > App.Now + 60_000 ||
            (index == 0 ? request.Id != id : path[index - 1] != request.Id) ||
            path.Any(n => db.Resolve(n) is null))
        {
            await Peer.Send(incoming, new Message("error", Error: "Недопустимый или устаревший маршрут.", RequestId: request.RequestId)); return;
        }
        if (index < path.Length - 1)
        {
            var next = db.Resolve(path[index + 1])!;
            using var limit = new CancellationTokenSource(TimeSpan.FromMilliseconds(Math.Max(1, request.Deadline - App.Now)));
            using var peer = await Peer.Connect(next.Ip, next.Cert, cert, limit.Token);
            await Peer.Send(peer.Stream, request with { Id = id }).WaitAsync(limit.Token);
            var reply = await Peer.Read(peer.Stream).WaitAsync(limit.Token);
            if (reply is null) return;
            await Peer.Send(incoming, reply).WaitAsync(limit.Token);
            if (reply.Type == "ready") await CopyBoth(incoming, peer.Stream);
            return;
        }
        await Peer.Send(incoming, new Message("ready", Hops: path, RequestId: request.RequestId));
        var task = await Peer.Read(incoming).WaitAsync(TimeSpan.FromSeconds(20));
        if (task is null) return;
        if (task.RequestId != request.RequestId || task.Id != path[0] || task.Deadline <= App.Now ||
            task.Type is not ("sync" or "probe" or "exec" or "ping-external" or "tcp-check" or "interfaces" or "tunnel"))
        {
            await Peer.Send(incoming, new Message("error", Error: "Запрос просрочен или не соответствует маршруту.", RequestId: task.RequestId)); return;
        }
        if (task.Type != "sync" && task.Type != "tunnel" && task.Target != id)
        {
            await Peer.Send(incoming, new Message("error", Error: "Назначение задачи не совпадает с маршрутом.", RequestId: task.RequestId)); return;
        }
        if (task.Type == "tunnel" && (task.Via ?? task.Target) != id)
        {
            await Peer.Send(incoming, new Message("error", Error: "Неверный узел выхода.", RequestId: task.RequestId)); return;
        }
        await Dispatch(incoming, task with { Hops = path.SkipLast(1).ToArray() }, true);
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
        db.Put(new Node(m.Id, m.Name, m.Ip, m.Cert, App.Now,Platform:m.Platform=="windows"?"windows":"linux"));
        await Peer.Send(peer.Stream, new Message("welcome", id, Nodes: db.Nodes().ToArray(), Rules: db.Rules().ToArray(), KeyHash: db.Get("key_hash"), Update: db.Update(), Web: db.Web()));
    }

    Message Sync() => new("sync", id, Nodes: db.Nodes().ToArray(), Rules: db.Rules().ToArray(), Update: db.Update(), Pings: db.Pings().ToArray(), Web: db.Web(), Links: db.Links().ToArray());

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
        foreach (var link in m.Links ?? []) db.PutLink(link);
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
                if(db.Get("cluster") is null && db.Get("bootstrap_host") is not null && bootstrapWork.IsCompleted)
                    bootstrapWork=Bootstrap();
                if (db.Get("cluster") != null && (db.Self()?.Removed != true || db.Get("left") == "1"))
                {
                    if (topologyWork.IsCompleted) topologyWork = routing.RefreshTopology(stop.Token);
                    foreach (var n in db.Nodes().Where(x => !x.Removed && x.Id != id))
                    {
                        if (!routeScans.TryGetValue(n.Id, out var scan) || scan.Work.IsCompleted && scan.Due <= App.Now)
                            routeScans[n.Id] = (ScanRoutes(n.Id), App.Now + Random.Shared.Next(20_000,30_001));
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
    async Task Bootstrap()
    {
        try{await Enrollment.Connect(db,cert,stop.Token);}
        catch(OperationCanceledException){}
        catch(Exception e){Console.Error.WriteLine("pnt: bootstrap: "+e.Message);}
    }

    async Task ScanRoutes(string target)
    {
        try { await routing.Refresh(target, stop.Token); }
        catch (OperationCanceledException) { }
        catch (Exception e) { Console.Error.WriteLine("pnt: route search: " + e.Message); }
    }

    async Task CheckNode(Node node)
    {
        try
        {
            using var peer = await routing.Connect(node.Id, cancellation: stop.Token);
            var watch = Stopwatch.StartNew();
            var request = await RouteTransport.SendTask(peer, Sync());
            var reply = await RouteTransport.ReadResult(peer, request.RequestId, TimeSpan.FromSeconds(8), stop.Token);
            if (reply.Type != "sync") return;
            Merge(reply);
            var path = peer.RouteReady!.Hops!;
            db.SetPing(node.Id, (peer.RouteReady.PingMs ?? 0) + watch.Elapsed.TotalMilliseconds, path.Length == 2, path);
        }
        catch { }
    }

    void LaunchPendingUpdate()
    {
        var update = db.Update();
        if (update is null || db.Get("update_applied") == update.Id) return;
        if (db.Get("update_attempt_id") == update.Id && long.TryParse(db.Get("update_attempt_time"), out var last) && App.Now - last < 300_000) return;
        db.Set("update_attempt_id", update.Id);
        db.Set("update_attempt_time", App.Now.ToString());
        var sourceFile = Path.Combine(App.ConfigDir,"source-dir");
        if (!File.Exists(sourceFile)) { Console.Error.WriteLine("pnt: путь исходников для автообновления не настроен."); return; }
        var script = Path.Combine(File.ReadAllText(sourceFile).Trim(), OperatingSystem.IsWindows()?"deploy/pnt.ps1":"pnt.sh");
        if (!File.Exists(script)) { Console.Error.WriteLine("pnt: скрипт автообновления не найден: " + script); return; }
        try
        {
            if(OperatingSystem.IsWindows())
            {
                using var child=new Process {StartInfo=new ProcessStartInfo("powershell.exe"){UseShellExecute=false,CreateNoWindow=true}};
                foreach(var argument in new[]{"-NoProfile","-ExecutionPolicy","Bypass","-File",script,"-Action","update","-EventId",update.Id})child.StartInfo.ArgumentList.Add(argument);
                child.Start();return;
            }
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
            listeners[key].Stop(); listeners.Remove(key);
            if (!listeners.Values.Any(l => ((IPEndPoint)l.LocalEndpoint).Port == port)) Firewall.Close(port);
        }
        foreach (var (key, rule) in desired)
        {
            if (listeners.ContainsKey(key)) continue;
            try
            {
                Forwarding.ValidateSelection(Forwarding.Interfaces(),rule.InInterface,rule.InAddress,true);
                var listener = new TcpListener(IPAddress.Parse(rule.InAddress), rule.InPort);
                try { Forwarding.BindDevice(listener.Server,rule.InInterface); listener.Start(); }
                catch {listener.Stop();throw;}
                listeners[key] = listener;
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
            using var tcp = await Forwarding.Connect(target == null ? r.To : target.Id == id ? IPAddress.Loopback.ToString() : target.Ip, r.ToPort,r.OutInterface,r.OutAddress);
            await CopyBoth(incoming, tcp.GetStream()); return;
        }
        var routeTarget = r.Via ?? target?.Id ?? throw new Exception("Назначение недоступно.");
        using var route = await OpenRoute(routeTarget, new Message("tunnel", id, Target: r.To, Port: r.ToPort, Via: r.Via, Hops: [id],OutAddress:r.OutAddress,OutInterface:r.OutInterface));
        await CopyBoth(incoming, route.Stream);
    }

    async Task Tunnel(Stream incoming, Message request)
    {
        if (request.Hops?.Contains(id) == true || (request.Hops?.Length ?? 0) > 8) { await Peer.Send(incoming, new Message("error", Error: "Петля маршрута.", RequestId: request.RequestId)); return; }
        var target = db.Resolve(request.Target ?? "");
        if (request.Via == id || (request.Via == null && target?.Id == id))
        {
            var host = target == null ? request.Target! : target.Id == id ? IPAddress.Loopback.ToString() : target.Ip;
            if (target == null && (!IPAddress.TryParse(host, out _) || request.Via != id)) { await Peer.Send(incoming, new Message("error", Error: "Внешний IP запрещён.", RequestId: request.RequestId)); return; }
            TcpClient tcp;
            try { tcp = await Forwarding.Connect(host,request.Port,request.OutInterface,request.OutAddress); }
            catch (Exception e) { await Peer.Send(incoming, new Message("error", Error: e.Message, RequestId: request.RequestId)); return; }
            using(tcp) {await Peer.Send(incoming, new Message("ready", RequestId: request.RequestId)); await CopyBoth(incoming, tcp.GetStream());} return;
        }
        var destination = request.Via ?? target?.Id;
        if (destination == null) { await Peer.Send(incoming, new Message("error", Error: "Узел не найден.", RequestId: request.RequestId)); return; }
        try
        {
            using var route = await OpenRoute(destination, request with { Id = id, Hops = (request.Hops ?? []).Append(id).ToArray() });
            await Peer.Send(incoming, new Message("ready", RequestId: request.RequestId)); await CopyBoth(incoming, route.Stream);
        }
        catch (Exception e) { await Peer.Send(incoming, new Message("error", Error: e.Message, RequestId: request.RequestId)); }
    }

    async Task<Peer> OpenRoute(string destination, Message request)
    {
        var peer = await routing.Connect(destination);
        try
        {
            var task = await RouteTransport.SendTask(peer, request with { Id = id });
            var answer = await RouteTransport.ReadResult(peer, task.RequestId, TimeSpan.FromSeconds(15));
            if (answer.Type != "ready") throw new IOException(answer.Error ?? "Назначение недоступно.");
            return peer;
        }
        catch { peer.Dispose(); throw; }
    }

    async Task RelayProbe(Stream incoming, Message request)
    {
        try
        {
            var route = await Probe(request.Target!, request.Hops ?? []);
            await Peer.Send(incoming, new Message("ok", Hops: route));
        }
        catch { await Peer.Send(incoming, new Message("error", Error: "Узел недоступен.", RequestId: request.RequestId)); }
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
            await Peer.Send(incoming, new Message("error", Error: "Маршрут к узлу не найден.", RequestId: request.RequestId)); return;
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
        catch (Exception e) { await Peer.Send(incoming, new Message("error", Error: e.Message, RequestId: request.RequestId)); }
    }

    async Task ExecuteExternalPing(Stream incoming, Message request, bool sendReady = true)
    {
        if (request.Host is null)
        {
            await Peer.Send(incoming, new Message("error", Error: "Не указана цель пинга.", RequestId: request.RequestId)); return;
        }
        if (sendReady) await Peer.Send(incoming, new Message("ready", Hops: (request.Hops ?? []).Append(id).ToArray()));
        var result = await ExternalPing.Measure(request.Host);
        await Peer.Send(incoming, new Message("ping-result", Ip: result.Ip, PingMs: result.Ms, Error: result.Error, RequestId: request.RequestId));
    }

    async Task Execute(Stream incoming, Message request, bool sendReady = true)
    {
        if (request.Command is not { Length: > 0 and <= 16_384 })
        {
            await Peer.Send(incoming, new Message("error", Error: "Пустая или слишком длинная команда.", RequestId: request.RequestId)); return;
        }
        var windows=OperatingSystem.IsWindows();
        using var process = new Process { StartInfo = new ProcessStartInfo(windows ? "cmd.exe" : request.Interactive ? "/usr/bin/script" : "/bin/sh")
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            RedirectStandardInput = request.Interactive, WorkingDirectory = App.Dir
        } };
        if(windows)process.StartInfo.Arguments="/d /s /c \"chcp 65001>nul & "+request.Command+"\"";
        else
        {
            if (request.Interactive) process.StartInfo.ArgumentList.Add("-qef");
            process.StartInfo.ArgumentList.Add("-c");process.StartInfo.ArgumentList.Add(request.Command);
            if (request.Interactive) process.StartInfo.ArgumentList.Add("/dev/null");
        }
        try { process.Start(); }
        catch (Exception e) { await Peer.Send(incoming, new Message("error", Error: e.Message, RequestId: request.RequestId)); return; }
        try
        {
            if (sendReady) await Peer.Send(incoming, new Message("ready", Hops: (request.Hops ?? []).Append(id).ToArray()));
            _ = Task.Run(async () =>
            {
                try
                {
                    while (await Peer.Read(incoming) is Message input)
                        if (request.Interactive && input.Type == "exec-input" && input.RequestId == request.RequestId)
                        {
                            await process.StandardInput.WriteAsync(windows?input.Output?.Replace("\n","\r\n"):input.Output);
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
                    try { await Peer.Send(incoming, new Message("exec-output", Output: new string(buffer, 0, count), Stderr: stderr, RequestId: request.RequestId)); }
                    finally { writeLock.Release(); }
                }
            }
            await Task.WhenAll(Pump(process.StandardOutput, false), Pump(process.StandardError, true), process.WaitForExitAsync());
            await Peer.Send(incoming, new Message("exec-exit", ExitCode: process.ExitCode, RequestId: request.RequestId));
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
