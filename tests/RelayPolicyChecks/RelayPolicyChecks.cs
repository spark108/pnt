using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Pnt;

static class RelayPolicyChecks
{
    static void Assert(bool value,string text){if(!value)throw new Exception(text);}
    public static async Task Main()
    {
        var folder=Path.Combine(Path.GetTempPath(),"pnt-relay-policy-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
        Environment.SetEnvironmentVariable("PNT_DATA_DIR",folder);Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");Environment.SetEnvironmentVariable("PNT_DISABLE_QUIC","1");
        var certs=Enumerable.Range(0,4).Select(i=>Certificate.Load(Path.Combine(folder,i+".pfx"))).ToArray();var ids=certs.Select(Certificate.Id).ToArray();
        var members=ids.Select((id,i)=>new Node(id,"node"+i,"unreachable invalid host",Certificate.Fingerprint(certs[i]),App.Now,RelayEnabled:i==3)).ToArray();
        var legacy=JsonSerializer.SerializeToNode(members[0],App.Json)!.AsObject();legacy.Remove("relayEnabled");
        Assert(legacy.Deserialize<Node>(App.Json)!.RelayEnabled,"Existing nodes without a policy must default to ordinary relay");
        Assert(new Node("n","name","ip","cert",1).RelayEnabled,"New nodes must default to ordinary relay");
        var reserve=new[]{ids[0],ids[1],ids[2]};var normal=new[]{ids[0],ids[3],ids[2]};var policy=new RelayPolicy(members);
        Assert(policy.ReserveCount(normal)==0&&policy.ReserveCount(reserve)==1&&policy.ReserveCount([ids[0],ids[2]])==0,"Endpoints were treated as transit");
        var cached=new[]{new CachedRoute(ids[2],reserve,1,App.Now,9,0,9,true)};
        var measured=new[]{(Path:reserve,Ms:1.0),(Path:normal,Ms:500.0)};
        bool Reserved(string id)=>members.Any(n=>n.Id==id&&!n.RelayEnabled);
        Assert(RouteCache.Apply(cached,ids[2],measured,reserveOnly:Reserved).Single(r=>r.Primary).Path.SequenceEqual(normal),"Fast reserved primary beat ordinary transit");
        Assert(RouteCache.Apply(cached,ids[2],[(reserve,1.0)],reserveOnly:Reserved).Single(r=>r.Primary).Path.SequenceEqual(reserve),"Only fallback route was rejected");
        var crowded=Enumerable.Range(0,6).Select(i=>(Path:new[]{ids[0],"ordinary"+i,ids[2]},Ms:100.0+i)).Append((reserve,1.0));
        Assert(RouteCache.Apply([],ids[2],crowded,reserveOnly:Reserved).Any(r=>r.Path.SequenceEqual(reserve)),"Cache dropped the emergency relay");
        using(var settings=new Store(Path.Combine(folder,"settings.db")))
        {
            settings.Set("cluster","test");settings.Set("self",ids[0]);settings.Put(members[0] with{RelayEnabled=true});var old=settings.Self()!;
            var disabled=NodeManagement.SetRelay(settings,null,false);Assert(!disabled.RelayEnabled&&disabled.Version>old.Version&&disabled.Cert==old.Cert&&disabled.Name==old.Name&&!disabled.Removed,"Relay setting changed identity or membership");
            Assert(NodeManagement.SetRelay(settings,null,false).Version==disabled.Version,"Repeated disable changed the version");
            Assert(JsonSerializer.Deserialize<Node>(JsonSerializer.Serialize(disabled,App.Json),App.Json)!.RelayEnabled==false,"Relay mode lost in gossip JSON");
            Assert(NodeManagement.SetRelay(settings,null,true).RelayEnabled,"Re-enable failed");
        }
        var stores=Enumerable.Range(0,4).Select(i=>{var db=new Store(Path.Combine(folder,i+".db"));db.Set("cluster","test");db.Set("self",ids[i]);foreach(var member in members)db.Put(member);return db;}).ToArray();
        var services=stores.Select((db,i)=>new Service(db,certs[i],0)).ToArray();var links=new List<Task>();
        foreach(var service in services)typeof(Service).GetMethod("RegisterMultiplex",BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(service,null);
        async Task Link(int left,int right)
        {
            using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var accepted=listener.AcceptTcpClientAsync();
            var connecting=Peer.ConnectRaw("127.0.0.1",Certificate.Fingerprint(certs[right]),certs[left],port:((IPEndPoint)listener.LocalEndpoint).Port);var socket=await accepted;
            links.Add(Task.Run(async()=>{try{await (Task)typeof(Service).GetMethod("Handle",BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(services[right],[socket])!;}catch{socket.Dispose();}}));
            var peer=await connecting;await Peer.Send(peer.Stream,new("mux",ids[left],Name:"service"));Assert((await Peer.Read(peer.Stream))?.Type=="mux-ready","Mux not accepted");links.Add(MultiplexPool.Adopt(peer,ids[left]));
        }
        async Task Probe(Peer peer)
        {
            var request=await RouteTransport.SendTask(peer,new("probe",ids[0],Target:ids[2]));Assert((await RouteTransport.ReadResult(peer,request.RequestId,TimeSpan.FromSeconds(5))).Type=="ok","Task did not reach reserve-mode endpoint");
        }
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(100));
        try
        {
            await Link(0,1);await Link(1,2);await Link(0,3);await Link(3,2);
            stores[0].ChangeRoutes(ids[2],_=>[cached[0],new(ids[2],normal,500,App.Now,1,0,1)]);
            using(var peer=await new RouteTransport(stores[0],certs[0]).Connect(ids[2],cancellation:stop.Token)){Assert(peer.RouteReady!.Hops!.SequenceEqual(normal),"Connect preferred reserved cached primary");await Probe(peer);}
            stores[0].ChangeRoutes(ids[2],_=>[cached[0] with{Updated=App.Now}]);
            using(var peer=await new RouteTransport(stores[0],certs[0]).Connect(ids[2],cancellation:stop.Token)){Assert(peer.RouteReady!.Hops!.SequenceEqual(normal),"Discovery did not find ordinary transit before using cached reserve");await Probe(peer);}
            MultiplexPool.CloseLocal(ids[3]);
            using var fallback=await new RouteTransport(stores[0],certs[0]).Connect(ids[2],cancellation:stop.Token);
            Assert(fallback.RouteReady!.Hops!.SequenceEqual(reserve),"Emergency relay did not restore reachability");await Probe(fallback);
            var files=new FtpConfig(Guid.NewGuid().ToString("N"),true,App.Now);stores[2].PutFtp(files);
            using var streaming=await new RouteTransport(stores[0],certs[0]).Connect(ids[2],cancellation:stop.Token);
            var session=await RouteTransport.SendTask(streaming,new("file-session",ids[0],Target:ids[2],Secret:files.Id));Assert((await RouteTransport.ReadResult(streaming,session.RequestId,TimeSpan.FromSeconds(5))).Type=="file-ready","Persistent route session not ready");
            async Task Stat(){var path=OperatingSystem.IsWindows()?"/"+folder.Replace(":","").Replace('\\','/'):folder;await Peer.Send(streaming.Stream,new("file-request",RequestId:session.RequestId,File:new("stat",path,Settings:files.Id)));Assert((await RouteTransport.ReadResult(streaming,session.RequestId,TimeSpan.FromSeconds(5))).Type=="file-result","Open stream interrupted by relay change");}
            await Stat();
            await Link(0,3);await Link(3,2);
            using(var peer=await new RouteTransport(stores[0],certs[0]).Connect(ids[2],cancellation:stop.Token)){Assert(peer.RouteReady!.Hops!.SequenceEqual(normal),"Recovered ordinary transit did not replace reserved primary");await Probe(peer);}
            NodeManagement.SetRelay(stores[0],ids[1],true);NodeManagement.SetRelay(stores[0],ids[1],false);await Stat();
            using(var sync=await new RouteTransport(stores[0],certs[0]).Connect(ids[2],cancellation:stop.Token))
            {var changed=stores[0].Resolve(ids[1])!;var request=await RouteTransport.SendTask(sync,new("sync",ids[0],Nodes:[changed]));var reply=await RouteTransport.ReadResult(sync,request.RequestId,TimeSpan.FromSeconds(5));Assert(reply.Type=="sync"&&stores[2].Resolve(ids[1]) is {RelayEnabled:false} propagated&&propagated.Version==changed.Version,"Relay policy was not synchronized to another member");}
            var candidates=RoutePlanner.Candidates(stores[0],ids[0],ids[2],[]).ToArray();Assert(candidates[0].Id==ids[2]&&Array.FindIndex(candidates,n=>n.Id==ids[3])<Array.FindIndex(candidates,n=>n.Id==ids[1]),"Discovery candidate priority or target access wrong");
            Console.WriteLine("PASS: default-on compatibility, persisted policy/identity, endpoint access, ordinary-before-reserve cache and discovery, emergency failover, ordinary route recovery and uninterrupted open streams.");
        }
        finally{foreach(var service in services)service.Stop();foreach(var id in ids)MultiplexPool.CloseLocal(id);try{await Task.WhenAll(links).WaitAsync(TimeSpan.FromSeconds(5));}catch{}foreach(var db in stores)db.Dispose();foreach(var cert in certs)cert.Dispose();}
    }
}
