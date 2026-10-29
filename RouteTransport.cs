using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

// Discovery opens control channels only. Application tasks are sent after a route is selected.
sealed class RouteTransport(Store db, X509Certificate2 cert)
{
    readonly SemaphoreSlim topologyGate = new(1, 1);
    long topologyTime;

    readonly System.Collections.Concurrent.ConcurrentDictionary<string, SemaphoreSlim> scans = new();
    readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> scanTimes = new();
    readonly Dictionary<string, (double Cost, int Count, long Until)> searches = new();

    public async Task<Peer> Connect(string target, Action<string>? progress = null, CancellationToken cancellation = default)
    {
        var self = Certificate.Id(cert);
        if (target == self)
        {
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            limit.CancelAfter(TimeSpan.FromSeconds(8));
            return await OpenPath([self], Guid.NewGuid().ToString("N"), limit.Token);
        }
        for (var pass = 0; pass < 2; pass++)
        {
            foreach (var route in db.Routes(target).Where(r => App.Now-r.Updated < RouteCache.FreshFor && r.Path.All(n => db.Resolve(n) is not null))
                .OrderByDescending(r => r.Primary).ThenBy(r => r.Ms))
            {
                cancellation.ThrowIfCancellationRequested();
                try
                {
                    progress?.Invoke("Соединение по маршруту: " + string.Join(" → ", route.Path.Select(Name)));
                    using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                    limit.CancelAfter(TimeSpan.FromSeconds(8));
                    var peer = await OpenPath(route.Path, Guid.NewGuid().ToString("N"), limit.Token);
                    db.ChangeRoutes(target, old => old.Select(r => r.Path.SequenceEqual(route.Path)
                        ? r with { Updated = App.Now, Ms = peer.RouteReady!.PingMs ?? r.Ms, Successes = r.Successes+1,
                            Primary = r.Primary || !old.Any(p => p.Primary && App.Now-p.Updated<RouteCache.FreshFor) } : r).ToList());
                    return peer;
                }
                catch when (!cancellation.IsCancellationRequested)
                {
                    db.ChangeRoutes(target, old => old.Select(r => r.Path.SequenceEqual(route.Path)
                        ? r with { Updated = 0, Failures = r.Failures+1, Streak = 0, Primary = false } : r).ToList());
                }
            }
            if (pass == 0)
            {
                progress?.Invoke("Нет свежего маршрута; ожидание поиска...");
                await Refresh(target, cancellation);
            }
        }
        throw new IOException("Нет подтверждённого маршрута к узлу.");
    }

    async Task<Peer> OpenPath(string[] path, string requestId, CancellationToken token)
    {
        var self = Certificate.Id(cert);
        var next = db.Resolve(!MultiplexPool.IsService(self) || path.Length == 1 ? self : path[1]) ?? throw new IOException("Узел исключён.");
        Peer? peer = null;
        try
        {
            var watch = Stopwatch.StartNew();
            peer = await Peer.Connect(next.Id == self ? "127.0.0.1" : next.Ip, next.Cert, cert, token);
            await Peer.Send(peer.Stream, new Message("route-open", self, Target: path[^1], Hops: path,
                RequestId: requestId, Deadline: App.Now+20_000)).WaitAsync(token);
            var reply = await Peer.Read(peer.Stream).WaitAsync(token);
            if (reply?.Type != "ready" || reply.RequestId != requestId || reply.Hops is null || !reply.Hops.SequenceEqual(path))
                throw new IOException(reply?.Error ?? "Маршрут не подтверждён.");
            peer.RouteReady = reply with { PingMs = watch.Elapsed.TotalMilliseconds };
            return peer;
        }
        catch { peer?.Dispose(); throw; }
    }

    public async Task Refresh(string target, CancellationToken cancellation = default)
    {
        var gate = scans.GetOrAdd(target, _ => new SemaphoreSlim(1,1));
        await gate.WaitAsync(cancellation);
        try
        {
            if (scanTimes.TryGetValue(target, out var scanned) && App.Now-scanned<10_000) return;
            if (db.Resolve(target) is null) return;
            await RefreshTopology(cancellation);
            var self = Certificate.Id(cert);
            var discovered = await Search(new Message("route-search", self, Target: target, Hops: [],
                RequestId: Guid.NewGuid().ToString("N"), Deadline: App.Now+10_000, PingMs: 0));
            var paths = discovered.Concat(RoutePlanner.Paths(db,self,target))
                .DistinctBy(p => string.Join("/",p)).Take(48).ToArray();
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            budget.CancelAfter(TimeSpan.FromSeconds(15));
            using var slots = new SemaphoreSlim(8);
            var measured = await Task.WhenAll(paths.Select(async path =>
            {
                var entered = false;
                try
                {
                    await slots.WaitAsync(budget.Token); entered=true;
                    using var peer = await OpenPath(path,Guid.NewGuid().ToString("N"),budget.Token);
                    return (Path: path, Ms: peer.RouteReady!.PingMs!.Value);
                }
                catch { return (Path: path, Ms: double.PositiveInfinity); }
                finally { if(entered) slots.Release(); }
            }));
            cancellation.ThrowIfCancellationRequested();
            db.ChangeRoutes(target, old => RouteCache.Apply(old,target,measured.Where(m => double.IsFinite(m.Ms))));
            scanTimes[target] = App.Now;
        }
        finally { gate.Release(); }
    }

    // Bounded flooding: paths travel with the request and replies return on the same streams.
    public async Task<string[][]> Search(Message request)
    {
        var self=Certificate.Id(cert); var path=request.Hops ?? [];
        if (!MultiplexPool.IsService(self))
        {
            using var local = await Peer.Connect("127.0.0.1", Certificate.Fingerprint(cert), cert);
            await Peer.Send(local.Stream, request with { Id = self, Hops = [] });
            var found = await Peer.Read(local.Stream).WaitAsync(TimeSpan.FromSeconds(12));
            return found?.Type == "route-found" && found.RequestId == request.RequestId ? found.Routes ?? [] : [];
        }
        if(request.RequestId is not {Length:32} || request.Target is null || db.Resolve(request.Target) is null ||
            path.Contains(self) || path.Length>8 || request.Deadline<=App.Now || request.Deadline>App.Now+15_000) return [];
        var cost=request.PingMs ?? 0;
        if(!double.IsFinite(cost) || cost<0) return [];
        lock(searches)
        {
            foreach(var expired in searches.Where(p => p.Value.Until<App.Now).Select(p=>p.Key).ToArray()) searches.Remove(expired);
            var key=request.RequestId+request.Target;
            if(searches.TryGetValue(key,out var old) && (old.Cost<=cost || old.Count>=2)) return [];
            searches[key]=(cost,old.Count+1,request.Deadline);
        }
        path=path.Append(self).ToArray();
        if(request.Target==self) return [path];
        using var budget=new CancellationTokenSource(TimeSpan.FromMilliseconds(Math.Max(1,request.Deadline-App.Now)));
        using var slots=new SemaphoreSlim(8);
        var replies=await Task.WhenAll(RoutePlanner.Candidates(db,self,request.Target,path)
            .OrderBy(n=>n.Id==request.Target?0:1).ThenBy(_=>Random.Shared.Next()).Select(async next =>
        {
            var entered=false;
            try
            {
                await slots.WaitAsync(budget.Token);entered=true;
                var watch=Stopwatch.StartNew();
                using var peer=await Peer.Connect(next.Ip,next.Cert,cert,budget.Token);
                await Peer.Send(peer.Stream,request with {Id=self,Hops=path,PingMs=cost+watch.Elapsed.TotalMilliseconds}).WaitAsync(budget.Token);
                var reply=await Peer.Read(peer.Stream).WaitAsync(budget.Token);
                return reply?.Type=="route-found" && reply.RequestId==request.RequestId ? reply.Routes ?? [] : Array.Empty<string[]>();
            }
            catch { return Array.Empty<string[]>(); }
            finally {if(entered) slots.Release();}
        }));
        return replies.SelectMany(p=>p).Where(p=>p.Length<=10 && p.Length>=path.Length && p.Take(path.Length).SequenceEqual(path) &&
            p[^1]==request.Target && p.Distinct().Count()==p.Length && p.All(n=>db.Resolve(n)is not null))
            .DistinctBy(p=>string.Join("/",p)).OrderBy(p=>p.Length).Take(8).ToArray();
    }

    public static async Task<Message> SendTask(Peer peer, Message task, int startWithinSeconds = 20)
    {
        var request = task with { RequestId = peer.RouteReady!.RequestId, Deadline = App.Now + startWithinSeconds * 1000L };
        await Peer.Send(peer.Stream, request).WaitAsync(TimeSpan.FromSeconds(8));
        return request;
    }

    public static async Task<Message> ReadResult(Peer peer, string? requestId, TimeSpan timeout, CancellationToken token = default)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(timeout);
        var result = await Peer.Read(peer.Stream).WaitAsync(budget.Token) ?? throw new IOException("Соединение закрыто без результата.");
        if (result.RequestId != requestId) throw new IOException("Ответ относится к другому запросу.");
        return result;
    }

    internal async Task RefreshTopology(CancellationToken token)
    {
        await topologyGate.WaitAsync(token);
        try
        {
            if (App.Now - topologyTime < 5_000) return;
            topologyTime = App.Now;
            var self = Certificate.Id(cert);
            if (!MultiplexPool.IsService(self))
            {
                using var local = await Peer.Connect("127.0.0.1", Certificate.Fingerprint(cert), cert, token);
                await Peer.Send(local.Stream, new Message("route-info", self)).WaitAsync(TimeSpan.FromSeconds(5), token);
                var reply = await Peer.Read(local.Stream).WaitAsync(TimeSpan.FromSeconds(5), token);
                foreach (var link in reply?.Links ?? []) db.PutLink(link);
                return;
            }
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token);
            limit.CancelAfter(TimeSpan.FromSeconds(5));
            using var slots = new SemaphoreSlim(8);
            await Task.WhenAll(db.Nodes().Where(n => !n.Removed && n.Id != self).Select(async node =>
            {
                var entered = false;
                try
                {
                    await slots.WaitAsync(limit.Token); entered = true;
                    var watch = Stopwatch.StartNew();
                    using var peer = await Peer.Connect(node.Ip, node.Cert, cert, limit.Token);
                    await Peer.Send(peer.Stream, new Message("route-info", self)).WaitAsync(limit.Token);
                    var reply = await Peer.Read(peer.Stream).WaitAsync(limit.Token);
                    if (reply?.Type == "route-info")
                    {
                        foreach (var ping in reply.Links ?? reply.Pings ?? []) db.PutLink(ping);
                        db.PutLink(new PingReport(self,node.Id,watch.Elapsed.TotalMilliseconds,App.Now,true,[self,node.Id]));
                    }
                }
                catch { }
                finally { if (entered) slots.Release(); }
            }));
        }
        finally { topologyGate.Release(); }
    }

    string Name(string id) => db.Resolve(id)?.Name ?? id;
}
