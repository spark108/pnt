using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Pnt;

static class FtpChecks
{
    static void Assert(bool value,string text){if(!value)throw new Exception(text);}
    static async Task Denied(Func<Task> action,string text){try{await action();}catch(IOException){return;}throw new Exception(text);}
    static string Portable(string path)=>OperatingSystem.IsWindows()?"/"+path.Replace(":","").Replace('\\','/'):path;
    sealed class BreakStream(byte[] bytes,Action cut):MemoryStream(bytes)
    {
        bool broken;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default)
        {if(!broken&&Position>=2*FileService.BlockSize){broken=true;cut();}return base.ReadAsync(buffer,token);}
    }
    public static async Task Main()
    {
        var directory=Path.Combine(Path.GetTempPath(),"pnt-ftp-check-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
        Environment.SetEnvironmentVariable("PNT_DATA_DIR",directory);Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");Environment.SetEnvironmentVariable("PNT_DISABLE_QUIC","1");
        var certs=Enumerable.Range(0,4).Select(i=>Certificate.Load(Path.Combine(directory,i+".pfx"))).ToArray();var ids=certs.Select(Certificate.Id).ToArray();var config=new FtpConfig(Guid.NewGuid().ToString("N"),true,App.Now);
        var stores=Enumerable.Range(0,4).Select(own=>
        {
            var db=new Store(Path.Combine(directory,own+".db"));db.Set("self",ids[own]);db.Set("cluster","test");db.Set("key_hash",Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("ftp-test-password"))));db.PutFtp(config);
            for(var i=0;i<4;i++)db.Put(new Node(ids[i],"Узел "+i,"unreachable invalid host",Certificate.Fingerprint(certs[i]),App.Now,BehindNat:i==2,Platform:App.Platform));return db;
        }).ToArray();
        var services=stores.Select((db,i)=>new Service(db,certs[i],0)).ToArray();var links=new List<Task>();
        var register=typeof(Service).GetMethod("RegisterMultiplex",BindingFlags.NonPublic|BindingFlags.Instance)!;foreach(var service in services)register.Invoke(service,null);
        async Task Link(int left,int right)
        {
            using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var accepted=listener.AcceptTcpClientAsync();
            var outgoing=Peer.ConnectRaw("127.0.0.1",Certificate.Fingerprint(certs[right]),certs[left],port:((IPEndPoint)listener.LocalEndpoint).Port);
            var socket=await accepted;links.Add(Task.Run(async()=>{try{await (Task)typeof(Service).GetMethod("Handle",BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(services[right],[socket])!;}catch{socket.Dispose();}}));
            var peer=await outgoing;await Peer.Send(peer.Stream,new("mux",ids[left],Name:"service"));Assert((await Peer.Read(peer.Stream))?.Type=="mux-ready","Mux not accepted");links.Add(MultiplexPool.Adopt(peer,ids[left]));
        }
        void Routes()=>stores[0].ChangeRoutes(ids[2],_=>[new(ids[2],[ids[0],ids[1],ids[2]],10,App.Now,1,0,1,true),new(ids[2],[ids[0],ids[3],ids[2]],20,App.Now,1,0,1)]);
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(150));
        var gateway=new FtpGateway(stores[0],certs[0],0,49300,49331);
        try
        {
            await Link(0,1);await Link(1,2);await Link(0,3);await Link(3,2);Routes();
            var db=stores[2];var target=Path.Combine(directory,"atomic.bin");await File.WriteAllTextAsync(target,"original");var path=Portable(target);var transfer=Guid.NewGuid().ToString("N");
            FileRequest Request(string op,long offset=0,int count=0,string? hash=null)=>new(op,path,Offset:offset,Count:count,Transfer:transfer,Hash:hash,Settings:config.Id);
            var payload=Encoding.UTF8.GetBytes("new-data");var digest=Convert.ToHexString(SHA256.HashData(payload));
            await FileService.Execute(db,Request("begin"),null,stop.Token);
            await Denied(async()=>{await FileService.Execute(db,Request("write",0,payload.Length,"bad"),payload,stop.Token);},"Bad checksum accepted");
            await FileService.Execute(db,Request("write",0,payload.Length,digest),payload,stop.Token);
            Assert(await File.ReadAllTextAsync(target)=="original","Incomplete upload replaced original");
            await FileService.Execute(db,Request("write",0,payload.Length,digest),payload,stop.Token);
            await Denied(async()=>{await FileService.Execute(db,Request("commit",payload.Length,hash:"bad"),null,stop.Token);},"Bad final checksum accepted");
            var staging=Path.Combine(directory,".pnt-upload-"+transfer+".part");await File.WriteAllTextAsync(staging,"corrupt!");
            await Denied(async()=>{await FileService.Execute(db,Request("commit",payload.Length,hash:digest),null,stop.Token);},"Changed staging file accepted");await File.WriteAllBytesAsync(staging,payload);
            await FileService.Execute(db,Request("commit",payload.Length,hash:digest),null,stop.Token);await FileService.Execute(db,Request("commit",payload.Length,hash:digest),null,stop.Token);
            Assert((await File.ReadAllBytesAsync(target)).SequenceEqual(payload),"Atomic commit failed");
            await Denied(async()=>{await FileService.Execute(db,new("read",path,Count:10,Settings:"old"),null,stop.Token);},"Old config retained access");
            var changed=await FileService.Execute(db,new("read",path,Count:2,Settings:config.Id),null,stop.Token);await File.AppendAllTextAsync(target,"changed");
            await Denied(async()=>{await FileService.Execute(db,new("read",path,Count:2,Version:changed.Reply.Version,Settings:config.Id),null,stop.Token);},"Changed file accepted for resume");
            await gateway.Refresh();
            var script=Path.Combine(Directory.GetCurrentDirectory(),"tests","FtpChecks","client.py");
            var python=new ProcessStartInfo(OperatingSystem.IsWindows()?"python":"python3"){UseShellExecute=false,RedirectStandardError=true,RedirectStandardOutput=true,CreateNoWindow=true};
            foreach(var arg in new[]{script,gateway.ListeningPort.ToString(),"Узел 2 ["+ids[2]+"]",Portable(directory)})python.ArgumentList.Add(arg);
            using(var process=Process.Start(python)!){var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();await process.WaitForExitAsync(stop.Token);var output=await stdout+await stderr;Console.WriteLine(output);Assert(process.ExitCode==0,"Standard FTPS client failed");}
            Routes();var large=RandomNumberGenerator.GetBytes(5*FileService.BlockSize+73);var routedPath=Portable(Path.Combine(directory,"rerouted.bin"));
            using(var remote=new FileRemote(stores[0],certs[0],ids[2],config.Id,stop.Token))
            using(var input=new BreakStream(large,()=>MultiplexPool.CloseLocal(ids[1])))await remote.Upload(input,routedPath,0);
            Assert((await File.ReadAllBytesAsync(Path.Combine(directory,"rerouted.bin"))).SequenceEqual(large),"Route recovery corrupted upload");
            using(var remote=new FileRemote(stores[0],certs[0],ids[2],config.Id,stop.Token))
            using(var output=new MemoryStream()){await remote.Download(output,routedPath,123);Assert(output.ToArray().SequenceEqual(large.Skip(123)),"Routed download resume failed");}
            Assert(stores[0].Routes(ids[2]).Any(r=>r.Path.Contains(ids[3])&&r.Updated>0),"Backup route was not used");
            Environment.SetEnvironmentVariable("PNT_DISABLE_QUIC",null);
            if(QuicTransport.Supported)
            {
                bool Authorized(string id,string fingerprint)=>db.Resolve(id)?.Cert==fingerprint;
                using var udpStop=new CancellationTokenSource();var udp=await QuicTransport.Listen(certs[2],new IPEndPoint(IPAddress.Loopback,0),Authorized,udpStop.Token)??throw new Exception("QUIC listener missing");
                var accepting=QuicTransport.AcceptLoop(udp,ids[2],Authorized,(_,_)=>{},udpStop.Token);
                try
                {
                    using var peer=await Peer.Connect("127.0.0.1",Certificate.Fingerprint(certs[2]),certs[0],stop.Token,udp.LocalEndPoint.Port);Assert(peer.Transport=="quic","File channel did not select UDP");var requestId=Guid.NewGuid().ToString("N");
                    await Peer.Send(peer.Stream,new("file-session",ids[0],Target:ids[2],Secret:config.Id,RequestId:requestId));Assert((await Peer.Read(peer.Stream))?.Type=="file-ready","UDP file session rejected");
                    await Peer.Send(peer.Stream,new("file-request",RequestId:requestId,File:new("read",routedPath,Count:FileService.BlockSize,Settings:config.Id)));var result=await Peer.Read(peer.Stream);Assert(result?.Type=="file-result","UDP file read failed");var chunk=new byte[result!.Files!.Count];await peer.Stream.ReadExactlyAsync(chunk,stop.Token);Assert(chunk.SequenceEqual(large.Take(chunk.Length)),"UDP file data corrupted");
                    Console.WriteLine("PASS: binary file service over QUIC/UDP.");
                }
                finally{udpStop.Cancel();await udp.DisposeAsync();await accepting;}
            }
            var limited=new FtpGateway(stores[0],certs[0],0);for(var i=0;i<5;i++)Assert(!limited.Authenticate("admin","wrong",IPAddress.Loopback),"Wrong password accepted");Assert(!limited.Authenticate("admin","ftp-test-password",IPAddress.Loopback),"Rate limit bypassed");
            using var connected=new TcpClient();await connected.ConnectAsync(IPAddress.Loopback,gateway.ListeningPort,stop.Token);var wire=connected.GetStream();
            async Task<string> Line(Stream stream){var result=new StringBuilder();var one=new byte[1];while(await stream.ReadAsync(one,stop.Token)>0){if(one[0]==10)return result.ToString();result.Append((char)one[0]);}return result.ToString();}
            Assert((await Line(wire)).StartsWith("220"),"FTPS banner missing");await wire.WriteAsync(Encoding.ASCII.GetBytes("AUTH TLS\r\n"),stop.Token);Assert((await Line(wire)).StartsWith("234"),"AUTH TLS failed");
            using var secured=new SslStream(wire,false,(_,_,_,_)=>true);await secured.AuthenticateAsClientAsync("pnt-node");await secured.WriteAsync(Encoding.ASCII.GetBytes("USER admin\r\n"),stop.Token);Assert((await Line(secured)).StartsWith("331"),"USER failed");await secured.WriteAsync(Encoding.ASCII.GetBytes("PASS ftp-test-password\r\n"),stop.Token);Assert((await Line(secured)).StartsWith("230"),"PASS failed");
            var disabled=config with{Id=Guid.NewGuid().ToString("N"),Enabled=false,Version=App.Now+1};stores[0].PutFtp(disabled);await gateway.Refresh();Assert(gateway.ListeningPort==0,"Disabled listener remains open");
            try{var closing=await Line(secured).WaitAsync(TimeSpan.FromSeconds(3));Assert(closing.Length==0||closing.StartsWith("421"),"Unexpected disable response");if(closing.StartsWith("421"))Assert((await Line(secured).WaitAsync(TimeSpan.FromSeconds(3))).Length==0,"Disabled authenticated session remains open");}catch(IOException){}
            db.PutFtp(disabled);await Denied(async()=>{await FileService.Execute(db,new("stat",path,Settings:config.Id),null,stop.Token);},"Disabled backend retained access");
            Console.WriteLine("PASS: explicit FTPS interoperability, TLS-only auth/data, virtual nodes, Unicode, list/stat/upload/download/resume/rename/delete, SHA-256, atomic writes, stale-file rejection, relay/NAT routes, interrupted-route recovery, rate limits and disable.");
        }
        finally
        {
            await gateway.Stop();foreach(var service in services)service.Stop();foreach(var id in ids)MultiplexPool.CloseLocal(id);try{await Task.WhenAll(links).WaitAsync(TimeSpan.FromSeconds(5));}catch{}foreach(var db in stores)db.Dispose();foreach(var cert in certs)cert.Dispose();
        }
    }
}
