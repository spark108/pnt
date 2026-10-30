using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Pnt;

static class VpnChecks
{
    static void Assert(bool value,string message){if(!value)throw new Exception(message);}
    public static async Task Main()
    {
        var sample=new VpnStatistics(1000,10,20,true);
        var direct=VpnConnections.Observe("server","client",sample,1100);
        Assert(direct.Connected==true&&direct.Mode=="direct","Fresh direct handshake missing");
        using(var relay=new VpnConnections.Relay("server","client"))
        {
            Assert(VpnConnections.Observe("server","client",sample,1100).Mode=="direct","Idle standby was counted as transport");
            relay.Touch();
            Assert(VpnConnections.Observe("server","client",sample,1100).Mode=="relay","Active relay missing");
            Assert(VpnConnections.Observe("other","client",sample,1100).Mode=="direct","Relay activity leaked between servers");
            Assert(VpnConnections.Observe("server","other",sample,1100).Mode=="direct","Relay activity leaked between clients");
        }
        Assert(VpnConnections.Observe("server","client",sample,1100).Mode=="direct","Closed relay retained transport state");
        Assert(VpnConnections.Observe("server","client",sample,1181).Connected==false,"Stale handshake reported connected");
        Assert(VpnConnections.Observe("server","client",sample with{Handshake=0},1100).Connected==false,"No handshake reported connected");
        Assert(VpnConnections.Observe("server","client",sample with{Exists=false},1100).Connected==false,"Missing peer reported connected");
        Assert(VpnConnections.Summary([direct,null]).Status=="подключён","Unreachable server hid a connected session");
        Assert(VpnConnections.Summary([null]).Status=="неизвестно","Unreachable server was reported disconnected");
        Assert(VpnConnections.Summary([direct with{Connected=false,Mode=null}]).Status=="отключён","Disconnected status missing");
        var configuration=new VpnServerConfiguration(new string('a',24),"native","awg0","/etc/amnezia/amneziawg/awg0.conf",true,true,"","10.8.0.1/24",51820,null);
        Assert(VpnServerInstaller.Choose([],new StringReader(""),TextWriter.Null)=="new","Empty inventory did not select a new installation");
        Assert(VpnServerInstaller.Choose([configuration],new StringReader("1\n"),TextWriter.Null)==configuration.Id,"Existing configuration selection failed");
        Assert(VpnServerInstaller.Choose([configuration],new StringReader("0\n"),TextWriter.Null)=="new","New configuration selection failed");
        Assert(VpnServerInstaller.Choose([configuration with{Supported=false}],new StringReader("1\n0\n"),TextWriter.Null)=="new","Unsupported configuration was selectable");
        try{VpnServerInstaller.Choose([configuration],new StringReader(""),TextWriter.Null);throw new Exception("Missing selection was accepted");}catch(IOException){}
        var directory=Path.Combine(Path.GetTempPath(),"pnt-vpn-check-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);Environment.SetEnvironmentVariable("PNT_DATA_DIR",directory);
        Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");
        using var cert=Certificate.Load(Path.Combine(directory,"node.pfx"));
        using var db=new Store(Path.Combine(directory,"pnt.db"));var self=Certificate.Id(cert);
        db.Set("self",self);db.Set("cluster","test-cluster");db.Put(new Node(self,"local","127.0.0.1",Certificate.Fingerprint(cert),App.Now));
        db.PutVpn(new VpnServer(self,"Test VPN",App.Now));
        var registered=db.VpnServers().Single();
        db.PutVpn(registered with{Removed=true,Version=registered.Version+1});
        db.PutVpn(registered with{Version=registered.Version+2});
        Assert(!db.VpnServers().Single().Removed,"Explicit server re-registration failed");
        var output=Path.Combine(directory,"client.pnt");
        await VpnControl.Command(db,cert,["client","create","Alice","--servers","local","--out",output]);
        var profile=VpnClientAgent.Validate(await File.ReadAllTextAsync(output));
        Assert(profile.ClientId==db.VpnClients().Single().Id,"Client identity mismatch");
        Assert(!db.Nodes().Any(n=>n.Id==profile.ClientId),"Client added to cluster topology");
        Assert(!File.ReadAllText(Path.Combine(directory,"pnt.db")).Contains(profile.Identity),"Private client identity persisted to registry");
        try{VpnClientAgent.Validate(JsonSerializer.Serialize(profile with{ClientId=self},App.Json));throw new Exception("Tampered profile accepted");}catch(ArgumentException){}
        using var identity=X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(profile.Identity),null,X509KeyStorageFlags.Exportable);
        var service=new Service(db,cert,0);var running=service.Run();
        async Task<Message> Request(Message request)
        {
            using var peer=await Peer.ConnectRaw("127.0.0.1",Certificate.Fingerprint(cert),identity,port:service.ControlPort);
            await Peer.Send(peer.Stream,request);
            return await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(10))??throw new Exception("No reply");
        }
        try
        {
            var catalog=await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"));
            Assert(catalog.Type=="vpn-result"&&catalog.VpnServers?.Single().Id==self,"Authorized catalog missing");
            Assert((await Request(new Message("vpn-client",self,Name:"catalog"))).Type=="error","Forged client ID accepted");
            Assert((await Request(new Message("exec",profile.ClientId,Target:self,Command:"echo forbidden"))).Type=="error","Client obtained member privileges");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"exec",Target:self))).Type=="error","Client API accepted exec");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"inventory",Target:self))).Type=="error","Unprivileged VPN client obtained installation inventory");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"clients",Target:self))).Type=="error","Unprivileged VPN client obtained other clients' statistics");
            var client=db.VpnClients().Single();db.PutVpn(client with{Servers=[],Version=client.Version+1});
            VpnControl.Merge(db,new Message("sync",VpnClients:[client with{Cert=new string('0',64),Version=client.Version+10}]));
            Assert(db.VpnClients().Single().Cert==client.Cert,"Client certificate changed through replication");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"))).VpnServers?.Length==0,"Denied server remains visible");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"ensure",Target:self))).Type=="error","Denied server issued a VPN profile");
            db.PutVpn(client with{Removed=true,Version=client.Version+2});
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"))).Type=="error","Revoked client authenticated");
            db.PutVpn(client with{Version=client.Version+3});Assert(db.VpnClients().Single().Removed,"Revoked client resurrected");
            await using var memory=new MemoryStream();
            var bytes=Enumerable.Range(0,65000).Select(i=>(byte)i).ToArray();
            await VpnDatagrams.Write(memory,bytes,default);await VpnDatagrams.Write(memory,new byte[]{7,8},default);memory.Position=0;
            Assert((await VpnDatagrams.Read(memory,default)).SequenceEqual(bytes),"Large UDP packet corrupted");
            Assert((await VpnDatagrams.Read(memory,default)).SequenceEqual(new byte[]{7,8}),"UDP packet boundaries lost");
            using(var unnegotiated=new MemoryStream(new byte[]{0,0}))
            {
                try{await VpnDatagrams.Read(unnegotiated,default);throw new Exception("Legacy tunnel accepted a heartbeat frame");}catch(IOException){}
            }
            using var echo=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
            try
            {
                using var input=new TcpClient();var accepting=listener.AcceptTcpClientAsync();await input.ConnectAsync(IPAddress.Loopback,((IPEndPoint)listener.LocalEndpoint).Port);
                using var exit=await accepting;using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var exiting=VpnDatagrams.Exit(exit.GetStream(),"127.0.0.1",((IPEndPoint)echo.Client.LocalEndPoint!).Port,()=>true,stop.Token);
                await VpnDatagrams.Write(input.GetStream(),Encoding.UTF8.GetBytes("through-pnt"),stop.Token);
                var packet=await echo.ReceiveAsync(stop.Token);await echo.SendAsync(packet.Buffer,packet.RemoteEndPoint,stop.Token);
                Assert(Encoding.UTF8.GetString(await VpnDatagrams.Read(input.GetStream(),stop.Token))=="through-pnt","UDP tunnel roundtrip failed");
                stop.Cancel();try{await exiting;}catch(OperationCanceledException){}
            }
            finally{listener.Stop();}
            using var heartbeatListener=new TcpListener(IPAddress.Loopback,0);heartbeatListener.Start();
            using(var input=new TcpClient())
            {
                var accepting=heartbeatListener.AcceptTcpClientAsync();await input.ConnectAsync(IPAddress.Loopback,((IPEndPoint)heartbeatListener.LocalEndpoint).Port);
                using var exit=await accepting;using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var activity=0;
                var exiting=VpnDatagrams.Exit(exit.GetStream(),"127.0.0.1",((IPEndPoint)echo.Client.LocalEndPoint!).Port,()=>true,stop.Token,()=>activity++,true);
                await VpnDatagrams.WriteFrame(input.GetStream(),new VpnDatagrams.Frame(0,[]),stop.Token);
                var pong=await VpnDatagrams.ReadFrame(input.GetStream(),stop.Token,true);
                Assert(pong.Size==ushort.MaxValue&&activity==0&&!echo.Client.Poll(1000,SelectMode.SelectRead),"Heartbeat leaked into VPN traffic or activity");
                await VpnDatagrams.Write(input.GetStream(),new byte[]{4,5},stop.Token);
                var packet=await echo.ReceiveAsync(stop.Token);await echo.SendAsync(packet.Buffer,packet.RemoteEndPoint,stop.Token);
                Assert((await VpnDatagrams.ReadFrame(input.GetStream(),stop.Token,true)).Data.SequenceEqual(new byte[]{4,5}),"Data framing broke after heartbeat");
                var echoes=Task.Run(async()=>
                {
                    for(var i=0;i<10;i++){var received=await echo.ReceiveAsync(stop.Token);await echo.SendAsync(received.Buffer,received.RemoteEndPoint,stop.Token);}
                });
                for(var i=0;i<10;i++)
                {
                    await VpnDatagrams.Write(input.GetStream(),new byte[]{(byte)i},stop.Token);
                    await VpnDatagrams.WriteFrame(input.GetStream(),new VpnDatagrams.Frame(0,[]),stop.Token);
                }
                var dataFrames=0;var heartbeats=0;
                for(var i=0;i<20;i++)
                {
                    var frame=await VpnDatagrams.ReadFrame(input.GetStream(),stop.Token,true);
                    if(frame.Size==ushort.MaxValue)heartbeats++;
                    else{Assert(frame.Data.Length==1&&frame.Data[0]==dataFrames,"Concurrent heartbeat and data writes interleaved");dataFrames++;}
                }
                Assert(dataFrames==10&&heartbeats==10,"Heartbeat/data frames were lost");await echoes;
                stop.Cancel();try{await exiting;}catch(OperationCanceledException){}
            }
            Console.WriteLine("PASS: signed profiles, client identity, ACL catalog, member isolation, revoke tombstones, UDP framing and real UDP roundtrip.");
        }
        finally{service.Stop();await running;}
    }
}
