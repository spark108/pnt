using System.Text.Json;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
namespace Pnt;
static class VpnUsageChecks
{
 static void Assert(bool condition,string message){if(!condition)throw new Exception(message);}
 public static async Task Main()
 {
  var directory=Path.Combine(Path.GetTempPath(),"pnt-vpn-usage-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
  var path=Path.Combine(directory,"test.db");
  const string exit="1111111111111111",entry="2222222222222222",transit="3333333333333333",other="4444444444444444",client="aaaaaaaaaaaaaaaa",second="bbbbbbbbbbbbbbbb";
  var now=App.Now;
  VpnStatistics Stats(long rx,long tx,string mode="direct",params string[] route)=>new(now/1000,rx,tx,true,true,mode,Route:route.Length==0?[exit]:route);
  void Add(Store db,long time,VpnStatistics stats)=>VpnUsage.Record(db,exit,new Dictionary<string,VpnStatistics>{{client,stats}},time);
  try{
   using(var db=new Store(path)){
    VpnUsage.Record(db,exit,new Dictionary<string,VpnStatistics>(),now);
    var empty=VpnUsage.Read(db,now);Assert(empty.Since==now&&empty.Updated==now&&empty.Clients.Length==0,"Empty successful sample appeared stale");
    Add(db,now+1000,Stats(1000,2000));
    var first=VpnUsage.Read(db,now+1000).Clients.Single();Assert(first.Connections==1&&first.Active==1&&first.Received==0&&first.Sent==0,"First baseline counted old traffic");
    Add(db,now+16000,Stats(1100,2200));
    Add(db,now+31000,Stats(1200,2300) with{Handshake=now/1000+30});
    var direct=VpnUsage.Read(db,now+31000).Clients.Single();Assert(direct.Connections==1&&direct.Direct==1&&direct.Received==200&&direct.Sent==300,"Rekey inflated session count or counters");
    Add(db,now+46000,Stats(1300,2500,"relay",entry,transit,exit));
    Add(db,now+61000,Stats(1500,2600,"relay",other,transit,exit));
    Add(db,now+76000,Stats(1600,2700,"relay",entry,transit,exit));
    var changed=VpnUsage.Read(db,now+76000);
    Assert(changed.Clients.Single().Connections==1&&changed.Clients.Single().Direct==1&&changed.Clients.Single().Relay==1,"Failover inflated logical connections");
    Assert(changed.Routes.Length==3&&changed.Routes.All(r=>r.Connections==1),"Distinct routes were lost or duplicates counted");
    Assert(changed.Nodes.Single(n=>n.Node==transit) is {Connections:1,Clients:1,Transit:1,Entry:0,Received:400,Sent:400},"Transit session counted more than once across route changes");
    Assert(!changed.Nodes.Any(n=>n.Node==exit)&&changed.Nodes.Single(n=>n.Node==entry).Entry==1,"Exit counted as intermediate or entry missing");
    Add(db,now+61000,Stats(999999,999999));
    Assert(VpnUsage.Read(db,now+76000).Clients.Single().Received==600,"Stale/duplicate snapshot changed accounting");
   }
   using(var db=new Store(path)){
    Add(db,now+91000,Stats(1700,2800,"relay",entry,transit,exit));
    Assert(VpnUsage.Read(db,now+91000).Clients.Single().Connections==1,"Service restart duplicated an active session");
    Add(db,now+106000,Stats(20,30));
    Assert(VpnUsage.Read(db,now+106000).Clients.Single().Received==720,"Counter reset lost traffic or caused overflow");
    Add(db,now+121000,Stats(20,30) with{Connected=false});
    Assert(VpnUsage.Read(db,now+121000).Clients.Single().Active==0,"Explicitly disconnected session remained active");
    Add(db,now+136000,Stats(40,60));
    Assert(VpnUsage.Read(db,now+136000).Clients.Single().Connections==2,"Reconnect after disconnection not counted");
    Assert(VpnUsage.Read(db,now+400000).Clients.Single().Active==0,"Stale session reported active without collector");
    Add(db,now+400000,Stats(80,120));
    Assert(VpnUsage.Read(db,now+400000).Clients.Single().Connections==3,"Long observation gap did not create a session");
    VpnUsage.Record(db,exit,new Dictionary<string,VpnStatistics>{{client,Stats(100,140)},{second,Stats(500,1000,"relay",entry,exit)}},now+415000);
    VpnUsage.Record(db,exit,new Dictionary<string,VpnStatistics>{{client,Stats(120,180)},{second,Stats(550,1075,"relay",entry,exit)}},now+430000);
    var snapshot=VpnUsage.Read(db,now+430000);
    Assert(snapshot.Clients.Length==2&&snapshot.Clients.Sum(c=>c.Connections)==4&&snapshot.Clients.Sum(c=>c.Active)==2,"Per-client/total counts differ");
    Assert(snapshot.Nodes.Single(n=>n.Node==entry).Clients==2,"Node client count missing");
    Assert(JsonSerializer.Deserialize<VpnUsageReport>(JsonSerializer.Serialize(snapshot,App.Json),App.Json)!.Clients.Length==2,"Routed report JSON lost data");
    var before=snapshot.Updated;
    try{Add(db,now+445000,Stats(900,900,"relay",entry,"not-a-node"));throw new Exception("Invalid path accepted");}catch(IOException){}
    Assert(VpnUsage.Read(db,now+445000).Updated==before,"Invalid snapshot was partially committed");
    VpnUsage.Record(db,exit,new Dictionary<string,VpnStatistics>(),now+445000);
    Assert(VpnUsage.Read(db,now+445000).Clients.All(c=>c.Active==0),"Missing backend peers not closed");
    using var output=new StringWriter();var original=Console.Out;try{Console.SetOut(output);VpnUsage.Print(db,snapshot,now+430000);}finally{Console.SetOut(original);}
    Assert(output.ToString().Contains("Накопительная статистика")&&output.ToString().Contains(transit)&&output.ToString().Contains(client),"Status omitted users or transit IDs");
   }
   Console.WriteLine("PASS: persistent sampled sessions, rekeys, failover, client/mode/path/node aggregates, counter reset, stale samples, expiration and status output");
  }finally{Directory.Delete(directory,true);}
  await CheckRoutedReport();
 }
 static async Task CheckRoutedReport()
 {
  Environment.SetEnvironmentVariable("PNT_DISABLE_QUIC","1");Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");
  var folder=Path.Combine(Path.GetTempPath(),"pnt-vpn-usage-route-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
  using var a=Certificate.Load(Path.Combine(folder,"a.pfx"));using var b=Certificate.Load(Path.Combine(folder,"b.pfx"));
  var aid=Certificate.Id(a);var bid=Certificate.Id(b);
  using var sourceDb=new Store(Path.Combine(folder,"a.db"));using var targetDb=new Store(Path.Combine(folder,"b.db"));
  var source=new Node(aid,"source","unreachable",Certificate.Fingerprint(a),App.Now);
  var target=new Node(bid,"target","unreachable",Certificate.Fingerprint(b),App.Now);
  foreach(var pair in new[]{(Db:sourceDb,Id:aid),(Db:targetDb,Id:bid)}){pair.Db.Set("self",pair.Id);pair.Db.Set("cluster","test");pair.Db.Put(source);pair.Db.Put(target);}
  const string client="aaaaaaaaaaaaaaaa";var now=App.Now;
  VpnUsage.Record(targetDb,bid,new Dictionary<string,VpnStatistics>{{client,new(now/1000,100,200,true,true,"relay",Route:[aid,bid])}},now);
  VpnUsage.Record(targetDb,bid,new Dictionary<string,VpnStatistics>{{client,new(now/1000,150,275,true,true,"relay",Route:[aid,bid])}},now+1);
  var requester=new Service(sourceDb,a,0);var server=new Service(targetDb,b,0);
  typeof(Service).GetMethod("RegisterMultiplex",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(requester,null);
  using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var accepted=listener.AcceptTcpClientAsync();
  var connect=Peer.ConnectRaw("127.0.0.1",Certificate.Fingerprint(b),a,port:((IPEndPoint)listener.LocalEndpoint).Port);
  using var socket=await accepted;
  var serving=Task.Run(async()=>await (Task)typeof(Service).GetMethod("Handle",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(server,[socket])!);
  var raw=await connect;await Peer.Send(raw.Stream,new Message("mux",aid,Name:"service"));Assert((await Peer.Read(raw.Stream))?.Type=="mux-ready","Report channel not accepted");
  var adopted=MultiplexPool.Adopt(raw,aid);
  try{
   sourceDb.ChangeRoutes(bid,_=>[new CachedRoute(bid,[aid,bid],1,App.Now,1,0,1,true)]);
   var json=await VpnControl.Query(sourceDb,a,bid,new("usage"));
   var report=JsonSerializer.Deserialize<VpnUsageReport>(json,App.Json)!;
   Assert(report.Clients.Single() is {Client:client,Connections:1,Relay:1,Received:50,Sent:75},"Remote server report lost session/traffic data");
   Assert(report.Routes.Single().Route.SequenceEqual([aid,bid]),"Remote report lost authenticated route IDs");
   Assert(VpnUsage.Read(sourceDb,App.Now).Clients.Length==0,"Remote usage polluted requesting node history");
   Console.WriteLine("PASS: VPN usage queried over authenticated routed RPC without an active VPN backend");
  }finally{
   requester.Stop();server.Stop();MultiplexPool.CloseLocal(aid);MultiplexPool.CloseLocal(bid);
   await Task.WhenAll(adopted,serving).WaitAsync(TimeSpan.FromSeconds(5));
   sourceDb.Dispose();targetDb.Dispose();
   Directory.Delete(folder,true);
  }
 }

}
