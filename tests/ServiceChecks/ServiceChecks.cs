using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
namespace Pnt;
static class ServiceChecks
{
static void Assert(bool ok,string message){if(!ok)throw new Exception(message);}
sealed class FailingStream:MemoryStream
{
 public override void Write(byte[] buffer,int offset,int count)=>throw new IOException("Disk full");
 public override void Write(ReadOnlySpan<byte> buffer)=>throw new IOException("Disk full");
}
public static async Task Main()
{
var directory=Path.Combine(Path.GetTempPath(),"pnt-log-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
try{
 long now=0;int attempts=0;var recovered=new MemoryStream();
 using(var log=new ServiceLog(Path.Combine(directory,"injected.log"),_=>++attempts==1?new FailingStream():recovered,()=>now)){
 log.WriteLine("failure must not stop maintenance");
 Assert(attempts==1,"Initial log was not opened");
 for(int i=0;i<10;i++)log.WriteLine("maintenance continues");
 Assert(attempts==1,"Disk error caused a retry storm");
 now=5000;log.WriteLine("recovered");
 Assert(attempts==2&&Encoding.UTF8.GetString(recovered.ToArray()).Contains("recovered"),"Log did not recover after disk space returned");
 }
 now=0;attempts=0;
 using(var log=new ServiceLog(Path.Combine(directory,"denied.log"),_=>{attempts++;throw new UnauthorizedAccessException();},()=>now)){
 log.WriteLine("startup");now=5000;log.WriteLine("retry");Assert(attempts==2,"Access errors did not recover/retry safely");
 }
 var path=Path.Combine(directory,"service.log");
 using(var log=new ServiceLog(path,limit:80)){
 log.WriteLine(new string('x',100));log.WriteLine("new-log");
 Assert(File.Exists(path+".previous")&&File.ReadAllText(path+".previous").Contains(new string('x',100)),"Running log rotation lost prior log");
 }
 Assert(File.ReadAllText(path).Contains("new-log"),"Rotation did not keep logging");
 await CheckIndependentMeasurements(directory);
 Console.WriteLine("PASS: independent ping during blocked sync, disk-full log failures never escape, retries are bounded, recovery and runtime rotation");
}finally{Directory.Delete(directory,true);}
}
static async Task CheckIndependentMeasurements(string directory)
{
 Environment.SetEnvironmentVariable("PNT_DISABLE_QUIC","1");Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");
 using var a=Certificate.Load(Path.Combine(directory,"a.pfx"));using var b=Certificate.Load(Path.Combine(directory,"b.pfx"));
 var aid=Certificate.Id(a);var bid=Certificate.Id(b);
 using var db=new Store(Path.Combine(directory,"node.db"));db.Set("self",aid);db.Set("cluster","test");
 var source=new Node(aid,"NAT","10.0.0.5",Certificate.Fingerprint(a),App.Now,BehindNat:true);
 var target=new Node(bid,"public","unreachable",Certificate.Fingerprint(b),App.Now);db.Put(source);db.Put(target);
 var service=new Service(db,a,0);
 typeof(Service).GetMethod("RegisterMultiplex",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(service,null);
 var syncEntered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
 var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
 MultiplexPool.Register(bid,async (stream,_,_)=>{
  var route=(await Peer.Read(stream))!;
  await Peer.Send(stream,new Message("ready",Hops:route.Hops,RequestId:route.RequestId));
  var task=(await Peer.Read(stream))!;
  if(task.Type=="sync"){
   syncEntered.TrySetResult();await release.Task;
   await Peer.Send(stream,new Message("sync",bid,RequestId:task.RequestId));
  }else if(task.Type=="latency-open")await LatencyProbe.Reply(stream,task,bid,default);
 });
 using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
 var accepted=listener.AcceptTcpClientAsync();
 var connect=Peer.ConnectRaw("127.0.0.1",Certificate.Fingerprint(b),a,port:((IPEndPoint)listener.LocalEndpoint).Port);
 using var socket=await accepted;
 var serving=Task.Run(async()=>{using var peer=await Peer.Accept(socket,b);await Peer.Read(peer.Stream);await MultiplexPool.Accept(peer,bid,true);});
 var raw=await connect;await Peer.Send(raw.Stream,new Message("mux",aid,Name:"service"));await Peer.Read(raw.Stream);
 var adopted=MultiplexPool.Adopt(raw,aid);
 try{
  db.ChangeRoutes(bid,_=>[new CachedRoute(bid,[aid,bid],1,App.Now,1,0,1,true)]);
  Task Invoke(string name)=>(Task)typeof(Service).GetMethod(name,BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(service,[target])!;
  var sync=Invoke("SyncNode");await syncEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
  await Invoke("CheckNode").WaitAsync(TimeSpan.FromSeconds(5));
  Assert(!sync.IsCompleted&&db.PingFrom(aid,bid) is >=0,"Slow full synchronization prevented a short ping measurement");
  release.TrySetResult();await sync.WaitAsync(TimeSpan.FromSeconds(5));
 }finally{
  release.TrySetResult();service.Stop();MultiplexPool.CloseLocal(aid);MultiplexPool.CloseLocal(bid);
  await Task.WhenAll(adopted,serving).WaitAsync(TimeSpan.FromSeconds(5));
 }
}

}
