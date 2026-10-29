using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

static class RoutingChecks
{
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }

    sealed class Host(Store db, X509Certificate2 cert, string ip, int delay) : IDisposable
    {
        readonly TcpListener listener = new(IPAddress.Parse(ip),442);
        readonly Service service = new(db,cert);
        public int Delay = delay;
        public bool Online = true;
        public int Accepted;
        public void Start()
        {
            listener.Start();
            _ = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        var socket = await listener.AcceptTcpClientAsync();
                        Interlocked.Increment(ref Accepted);
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                if (!Online) { socket.Dispose(); return; }
                                await Task.Delay(Delay);
                                await (Task)typeof(Service).GetMethod("Handle", BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(service,[socket])!;
                            }
                            catch { socket.Dispose(); }
                        });
                    }
                }
                catch { }
            });
        }
        public Task Maintain() => (Task)typeof(Service).GetMethod("Maintain",BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(service,null)!;
        public void Dispose()
        {
            ((CancellationTokenSource)typeof(Service).GetField("stop",BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(service)!).Cancel();
            listener.Stop();
            MultiplexPool.CloseLocal(Certificate.Id(cert));
        }
    }

    public static async Task Main()
    {
        var folder = Path.Combine(Path.GetTempPath(),"pnt-routing-check-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        Environment.SetEnvironmentVariable("PNT_DATA_DIR",folder);
        using var a = Certificate.Load(Path.Combine(folder,"a.pfx"));
        using var b = Certificate.Load(Path.Combine(folder,"b.pfx"));
        using var c = Certificate.Load(Path.Combine(folder,"c.pfx"));
        using var d = Certificate.Load(Path.Combine(folder,"d.pfx"));
        var ids = new[]{a,b,c,d}.Select(Certificate.Id).ToArray();
        var certs = new[]{a,b,c,d};
        var ips = new[]{"127.0.0.1","127.0.0.2","127.0.0.4","127.0.0.3"};
        Store MakeStore(int own)
        {
            var db = new Store(Path.Combine(folder,own+".db"));
            db.Set("self",ids[own]); db.Set("cluster","test");
            for (var i=0;i<4;i++) db.Put(new Node(ids[i],"node-"+i,own==0&&i==2?"127.0.0.9":ips[i],Certificate.Fingerprint(certs[i]),App.Now));
            return db;
        }
        using var da=MakeStore(0);using var db=MakeStore(1);using var dc=MakeStore(2);using var dd=MakeStore(3);
        using var ha=new Host(da,a,ips[0],0);using var hb=new Host(db,b,ips[1],10);
        using var hc=new Host(dc,c,ips[2],0);using var hd=new Host(dd,d,ips[3],200);
        ha.Start();hb.Start();hc.Start();hd.Start();
        var router=new RouteTransport(da,a);
        await router.Refresh(ids[2]);
        var saved=da.Routes(ids[2]);
        Assert(saved.Count(r=>r.Updated>0)>=2,"Missing alternate routes");
        var initial=saved.Single(r=>r.Primary);
        Assert(initial.Ms==saved.Where(r=>r.Updated>0).Min(r=>r.Ms),"Did not prefer measured fast route");
        using(var disk=new Store(Path.Combine(folder,"0.db"))) Assert(disk.Routes(ids[2]).Count>=2,"Routes not persisted");
        Assert(dc.Self()!.Name=="node-2","Discovery executed a task");
        using(var peer=await new RouteTransport(da,a).Connect(ids[2]))
        {
            Assert(peer.RouteReady!.Hops!.SequenceEqual(initial.Path),"Wrong fixed path");
            var request=await RouteTransport.SendTask(peer,new Message("sync",ids[0],Nodes:[dc.Self()! with{Name="applied",Version=App.Now+1}]));
            var result=await RouteTransport.ReadResult(peer,request.RequestId,TimeSpan.FromSeconds(5));
            Assert(result.Type=="sync"&&dc.Self()!.Name=="applied","Task did not reach endpoint");
        }
        using(var peer=await router.Connect(ids[2]))
        {
            var request=await RouteTransport.SendTask(peer,new Message("sync",ids[0],Nodes:[dc.Self()! with{Name="expired",Version=App.Now+1}]),-1);
            var result=await RouteTransport.ReadResult(peer,request.RequestId,TimeSpan.FromSeconds(5));
            Assert(result.Type=="error"&&dc.Self()!.Name=="applied","Expired task executed");
        }
        var accepted=hb.Accepted;
        await Task.WhenAll(Enumerable.Range(0,20).Select(async _ =>
        {
            using var peer=await Peer.Connect(ips[1],Certificate.Fingerprint(b),a);
            await Peer.Send(peer.Stream,new Message("route-info",ids[0]));
            Assert((await Peer.Read(peer.Stream))?.Type=="route-info","Concurrent logical stream failed");
        }));
        Assert(hb.Accepted==accepted,"TLS socket was recreated for logical streams");
        var sink=new TcpListener(IPAddress.Loopback,0);sink.Start();
        using(var busy=await router.Connect(ids[1]))
        {
            var request=await RouteTransport.SendTask(busy,new Message("tunnel",ids[0],Target:ids[1],Port:((IPEndPoint)sink.LocalEndpoint).Port));
            using var socket=await sink.AcceptTcpClientAsync();socket.ReceiveBufferSize=1024;
            Assert((await RouteTransport.ReadResult(busy,request.RequestId,TimeSpan.FromSeconds(5))).Type=="ready","Tunnel failed");
            var transfer=busy.Stream.WriteAsync(new byte[16*1024*1024].AsMemory()).AsTask();
            await Task.Delay(300);
            using(var other=await Peer.Connect(ips[1],Certificate.Fingerprint(b),a))
            {
                await Peer.Send(other.Stream,new Message("route-info",ids[0]));
                Assert((await Peer.Read(other.Stream).WaitAsync(TimeSpan.FromSeconds(3)))?.Type=="route-info","Slow stream blocked control traffic");
            }
            busy.Dispose();socket.Dispose();
            try{await transfer.WaitAsync(TimeSpan.FromSeconds(5));}catch(OperationCanceledException){}catch(IOException){}
        }
        sink.Stop();
        var echo=new TcpListener(IPAddress.Loopback,0);echo.Start();
        var echoWork=Task.Run(async()=>
        {
            using var socket=await echo.AcceptTcpClientAsync();var network=socket.GetStream();var buffer=new byte[8192];
            int count;while((count=await network.ReadAsync(buffer))>0)await network.WriteAsync(buffer.AsMemory(0,count));
        });
        using(var tunnel=await router.Connect(ids[1]))
        {
            var request=await RouteTransport.SendTask(tunnel,new Message("tunnel",ids[0],Target:ids[1],Port:((IPEndPoint)echo.LocalEndpoint).Port));
            Assert((await RouteTransport.ReadResult(tunnel,request.RequestId,TimeSpan.FromSeconds(5))).Type=="ready","Echo tunnel failed");
            var sent=System.Security.Cryptography.RandomNumberGenerator.GetBytes(512*1024);var received=new byte[sent.Length];
            await Task.WhenAll(tunnel.Stream.WriteAsync(sent.AsMemory()).AsTask(),tunnel.Stream.ReadExactlyAsync(received).AsTask()).WaitAsync(TimeSpan.FromSeconds(10));
            Assert(sent.SequenceEqual(received),"Multiplexed forwarding corrupted data");
        }
        echo.Stop();await echoWork.WaitAsync(TimeSpan.FromSeconds(5));
        var failedId=initial.Path[1]; var failedHost=failedId==ids[1]?hb:hd;
        failedHost.Online=false; MultiplexPool.CloseLocal(failedId);
        using(var peer=await router.Connect(ids[2])) Assert(!peer.RouteReady!.Hops!.Contains(failedId),"Did not use backup after primary failure");
        failedHost.Online=true;
        var before=da.Routes(ids[2]).Max(r=>r.Streak);
        var maintenance=ha.Maintain();
        await Task.Delay(36_000);
        Assert(da.Routes(ids[2]).Any(r=>r.Streak>before),"Background discovery stopped while routes were available");
        hb.Delay=200;hd.Delay=0;
        var old=new[]{new CachedRoute("t",["a","b","t"],100,App.Now,5,0,5,true)};
        var measurements=new[]{(Path:new[]{"a","b","t"},Ms:100.0),(Path:new[]{"a","d","t"},Ms:50.0)};
        var round1=RouteCache.Apply(old,"t",measurements);
        var round2=RouteCache.Apply(round1,"t",measurements);
        Assert(round2.Single(r=>r.Primary).Path[1]=="b","Route switched before three checks");
        var round3=RouteCache.Apply(round2,"t",measurements);
        Assert(round3.Single(r=>r.Primary).Path[1]=="d","Did not switch to stable faster route");
        using var cancelled=new CancellationTokenSource();cancelled.Cancel();
        try { using var peer=await router.Connect(ids[2],cancellation:cancelled.Token);throw new Exception("Cancellation ignored"); }
        catch(OperationCanceledException) { }
        Console.WriteLine("PASS: discovery, persisted backups, fixed dispatch, deadlines, failover, background refresh, hysteresis, cancellation, concurrent streams reuse TLS");
        // The OS temp directory is retained for diagnostics; it contains only test identities.
    }
}
