using System.Security.Cryptography;
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
        if(OperatingSystem.IsWindows())
        {
            var name="PNT binding test "+Guid.NewGuid().ToString("N");
            try
            {
                using var first=VpnDeviceIdentity.Windows(name);using var second=VpnDeviceIdentity.Windows(name);
                Assert(first.ExportSubjectPublicKeyInfo().SequenceEqual(second.ExportSubjectPublicKeyInfo()),"Device key changed across helper restarts");
                try{first.ExportPkcs8PrivateKey();throw new Exception("Windows device key was exportable");}catch(CryptographicException){}
            }
            finally{if(OperatingSystem.IsWindows()){using var key=CngKey.Open(name,CngProvider.MicrosoftSoftwareKeyStorageProvider);key.Delete();}}
        }
        var sample=new VpnStatistics(1000,10,20,true,Address:"10.8.0.3");
        var direct=VpnConnections.Observe("server","client",sample,1100);
        Assert(direct.Connected==true&&direct.Mode=="direct","Fresh direct handshake missing");
        Assert(direct.Route!.SequenceEqual(["server"])&&direct.Address=="10.8.0.3","Direct connection details missing");
        using(var relay=new VpnConnections.Relay("server","client",["entry","transit","server"]))
        {
            Assert(VpnConnections.Observe("server","client",sample,1100).Mode=="direct","Idle standby was counted as transport");
            relay.Touch();
            Assert(VpnConnections.Observe("server","client",sample,1100).Mode=="relay","Active relay missing");
            var observed=VpnConnections.Observe("server","client",sample,1100);
            Assert(observed.Route!.SequenceEqual(["entry","transit","server"]),"Data tunnel route missing");
            var restored=JsonSerializer.Deserialize<VpnStatistics>(JsonSerializer.Serialize(observed,App.Json),App.Json)!;
            Assert(restored.Address=="10.8.0.3"&&restored.Route!.SequenceEqual(observed.Route!),"Connection details lost in protocol");
            Assert(VpnConnections.Observe("other","client",sample,1100).Mode=="direct","Relay activity leaked between servers");
            Assert(VpnConnections.Observe("server","other",sample,1100).Mode=="direct","Relay activity leaked between clients");
        }
        Assert(VpnConnections.Observe("server","client",sample,1100).Mode=="direct","Closed relay retained transport state");
        Assert(VpnConnections.Observe("server","client",sample,1100).Route!.SequenceEqual(["server"]),"Closed transport retained its route");
        Assert(VpnConnections.Observe("server","client",sample,1181).Route is null,"Disconnected client retained an active route");
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
        db.Set("self",self);db.Set("cluster","test-cluster");db.Set("key_hash",new string('1',64));db.Put(new Node(self,"local","127.0.0.1",Certificate.Fingerprint(cert),App.Now));
        db.PutVpn(new VpnServer(self,"Test VPN",App.Now));
        var originalOutput=Console.Out;
        try
        {
            using var report=new StringWriter();Console.SetOut(report);
            VpnControl.PrintServerStatus(db,db.Self()!,[configuration with{Selected=true}],new(){["direct"]=direct,["relay"]=direct with{Mode="relay"}},null);
            Assert(report.ToString().Contains("awg0")&&report.ToString().Contains("51820")&&report.ToString().Contains("2\t2\t1\t1"),"Status omitted selected configuration or connection modes");
            report.GetStringBuilder().Clear();
            VpnControl.PrintServerStatus(db,db.Self()!,[configuration with{Active=false,Selected=true}],null,null);
            Assert(report.ToString().Contains("остановлен")&&report.ToString().Contains("Статистика клиентов недоступна"),"Stopped server was reported as healthy with zero clients");
            report.GetStringBuilder().Clear();
            VpnControl.PrintServerStatus(db,db.Self()!,[configuration],null,"status-timeout");
            Assert(report.ToString().Contains("status-timeout"),"Statistics failure was hidden");
        }
        finally{Console.SetOut(originalOutput);}
        var registered=db.VpnServers().Single();
        db.PutVpn(registered with{Removed=true,Version=registered.Version+1});
        db.PutVpn(registered with{Version=registered.Version+2});
        Assert(!db.VpnServers().Single().Removed,"Explicit server re-registration failed");
        var beforeRename=db.VpnServers().Single();
        await VpnControl.Command(db,cert,["server","rename","local"," Нидерланды #1 "]);
        var renamed=db.VpnServers().Single();
        Assert(renamed.Id==beforeRename.Id&&renamed.Name=="Нидерланды #1"&&renamed.Version>beforeRename.Version&&db.Self()!.Name=="local","VPN rename changed identity or cluster name");
        foreach(var bad in new[]{" ",new string('a',65),"bad\nname"})
        {
            try{await VpnControl.Command(db,cert,["server","rename",self,bad]);throw new Exception("Invalid VPN display name accepted");}catch(ArgumentException){}
        }
        var output=Path.Combine(directory,"client.pnt");
        await VpnControl.Command(db,cert,["client","create","Alice","--servers","local","--out",output]);
        var profile=VpnClientAgent.Validate(await File.ReadAllTextAsync(output));
        Assert(profile.ClientId==db.VpnClients().Single().Id,"Client identity mismatch");
        Assert(!db.Nodes().Any(n=>n.Id==profile.ClientId),"Client added to cluster topology");
        var savedClient=db.VpnClients().Single();
        Assert(savedClient.ProtectedIdentity is not null&&!savedClient.ProtectedIdentity.Contains(profile.Identity),"Client archive is missing or unencrypted");
        async Task<string> CaptureGet(params string[] args)
        {
            using var capture=new StringWriter();Console.SetOut(capture);
            try{await VpnControl.Command(db,cert,args);return capture.ToString();}
            finally{Console.SetOut(originalOutput);}
        }
        var consoleProfile=VpnClientAgent.Validate(await CaptureGet("client","get","Alice"));
        Assert(consoleProfile.Identity==profile.Identity&&consoleProfile.ClientId==profile.ClientId,"Console export rotated client identity");
        var exported=Path.Combine(directory,"export.pnt");
        await CaptureGet("client","get",savedClient.Id,"--out",exported);
        Assert(VpnClientAgent.Validate(await File.ReadAllTextAsync(exported)).Identity==profile.Identity,"File export changed identity");
        var unchanged=await File.ReadAllTextAsync(exported);
        try{await CaptureGet("client","get","Alice","--out",exported);throw new Exception("Existing file overwritten");}catch(IOException){}
        Assert(await File.ReadAllTextAsync(exported)==unchanged,"Existing profile modified on failure");
        foreach(var bad in new[]{savedClient with{Removed=true},savedClient with{ProtectedIdentity=null},savedClient with{Id=self},savedClient with{Cert=new string('0',64)},savedClient with{Servers=[]}})
        {
            try{VpnProfiles.Export(db,cert,bad);throw new Exception("Invalid/unavailable client exported");}
            catch(Exception e) when(e is ArgumentException or IOException or System.Security.Cryptography.CryptographicException){}
        }
        using(var otherCert=Certificate.Load(Path.Combine(directory,"other.pfx")))
        using(var otherDb=new Store(Path.Combine(directory,"other.db")))
        {
            var otherId=Certificate.Id(otherCert);
            otherDb.Set("cluster","test-cluster");otherDb.Set("key_hash",new string('1',64));otherDb.Set("self",otherId);
            foreach(var node in db.Nodes())otherDb.Put(node);
            otherDb.Put(new Node(otherId,"other","127.0.0.2",Certificate.Fingerprint(otherCert),App.Now));
            VpnControl.Merge(otherDb,new Message("sync",VpnClients:[savedClient],VpnServers:db.VpnServers().ToArray()));
            var remoteProfile=VpnClientAgent.Validate(JsonSerializer.Serialize(VpnProfiles.Export(otherDb,otherCert,otherDb.VpnClients().Single()),App.Json));
            Assert(remoteProfile.Identity==profile.Identity,"Profile unavailable after cluster synchronization");
            otherDb.PutVpn(savedClient with{ProtectedIdentity=null,DeviceAuthority=null,Version=savedClient.Version+1});
            Assert(otherDb.VpnClients().Single().ProtectedIdentity==savedClient.ProtectedIdentity&&otherDb.VpnClients().Single().DeviceAuthority==self,"Older node update erased saved identity/authority");
            VpnControl.Merge(otherDb,new Message("sync",VpnClients:[savedClient with{DeviceAuthority=otherId,Version=savedClient.Version+2}]));
            Assert(otherDb.VpnClients().Single().DeviceAuthority==self,"Synchronization moved binding authority");
            otherDb.Set("key_hash",new string('2',64));
            try{VpnProfiles.Export(otherDb,otherCert,savedClient);throw new Exception("Wrong cluster key decrypted identity");}catch(System.Security.Cryptography.CryptographicException){}
        }

        Assert(!File.ReadAllText(Path.Combine(directory,"pnt.db")).Contains(profile.Identity),"Private client identity persisted to registry");
        try{VpnClientAgent.Validate(JsonSerializer.Serialize(profile with{ClientId=self},App.Json));throw new Exception("Tampered profile accepted");}catch(ArgumentException){}
        using var identity=X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(profile.Identity),null,X509KeyStorageFlags.Exportable);
        var service=new Service(db,cert,0);var running=service.Run();
        using var deviceA=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var deviceB=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var deviceAKey=Convert.ToBase64String(deviceA.ExportSubjectPublicKeyInfo());
        var deviceBKey=Convert.ToBase64String(deviceB.ExportSubjectPublicKeyInfo());
        async Task<Message> Request(Message request,ECDsa? device=null,bool badProof=false)
        {
            using var peer=await Peer.ConnectRaw("127.0.0.1",Certificate.Fingerprint(cert),identity,port:service.ControlPort);
            await Peer.Send(peer.Stream,request);
            var response=await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(10))??throw new Exception("No reply");
            if(response.Type=="vpn-device-challenge")
            {
                device??=deviceA;
                var proof=new VpnDeviceProof(Convert.ToBase64String(device.ExportSubjectPublicKeyInfo()),Convert.ToBase64String(device.SignData(VpnDevices.Payload(badProof?"replayed":response.VpnPayload!,request),HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence)));
                await Peer.Send(peer.Stream,new Message("vpn-device-proof",VpnPayload:JsonSerializer.Serialize(proof,App.Json)));
                response=await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(10))??throw new Exception("No authenticated reply");
            }
            return response;
        }
        try
        {
            var catalog=await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"));
            Assert(catalog.Type=="vpn-result"&&catalog.VpnServers?.Single().Id==self,"Authorized catalog missing");
            Assert(savedClient.DeviceAuthority==self,"Client has no stable binding authority");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"),deviceB)).Type=="vpn-result","Unbound profile rejected a device before connection");
            try{db.DeviceAccess(profile.ClientId,deviceAKey,"check-device");throw new Exception("Catalog bound a device");}catch(UnauthorizedAccessException){}
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"),badProof:true)).Name=="vpn-device-denied","Replayed challenge was accepted");
            var proofRequest=new Message("vpn-client",profile.ClientId,Name:"catalog");
            var signed=new VpnDeviceProof(deviceAKey,Convert.ToBase64String(deviceA.SignData(VpnDevices.Payload("challenge",proofRequest),HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence)));
            Assert(VpnDevices.Verify("challenge",proofRequest,signed)==deviceAKey,"Valid device signature failed");
            foreach(var altered in new[]{proofRequest with{Name="ensure"},proofRequest with{Target=self},proofRequest with{Id=self},proofRequest with{DeviceEpoch="different"}})
            {
                try{VpnDevices.Verify("challenge",altered,signed);throw new Exception("Device proof transferred to another task");}catch(UnauthorizedAccessException){}
            }
            var state=await VpnDevices.Access(db,cert,savedClient,deviceAKey,"bind-device");
            Assert(state.Key==deviceAKey&&state.Epoch.Length==32,"First connection did not bind device");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"),deviceB)).Name=="vpn-device-denied","Copied profile authenticated on second device");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"))).Type=="vpn-result","Bound device lost access");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"stats",Target:self))).Name=="vpn-device-denied","Session without epoch was accepted");
            var operation=new VpnOperation("ensure",profile.ClientId,savedClient.Cert,DeviceKey:deviceAKey,DeviceEpoch:state.Epoch);
            await VpnDevices.VerifyOperation(db,cert,operation,default);
            var reset=await VpnDevices.Access(db,cert,savedClient,null,"unbind-device");
            Assert(reset.Key is null&&reset.Epoch!=state.Epoch,"Unbind retained old device authorization");
            try{await VpnDevices.VerifyOperation(db,cert,operation,default);throw new Exception("Old session survived unbind");}catch(UnauthorizedAccessException){}
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"stats",Target:self))).Name=="vpn-device-denied","Revoked session did not receive explicit deauthorization");
            var rebound=await VpnDevices.Access(db,cert,savedClient,deviceBKey,"bind-device");
            Assert(rebound.Key==deviceBKey&&rebound.Epoch!=reset.Epoch,"New device did not bind after unbind");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"catalog"))).Name=="vpn-device-denied","Old device retained access after rebinding");
            await VpnDevices.Access(db,cert,savedClient,null,"unbind-device");
            await VpnDevices.Access(db,cert,savedClient,deviceAKey,"bind-device");
            try{await VpnDevices.VerifyOperation(db,cert,operation,default);throw new Exception("Old epoch survived rebinding to the same device");}catch(UnauthorizedAccessException){}
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"stats",Target:self,DeviceEpoch:state.Epoch))).Name=="vpn-device-denied","Old epoch fetched statistics after rebind");
            Assert((await Request(new Message("vpn-client",profile.ClientId,Name:"ensure",Target:self,DeviceEpoch:state.Epoch))).Name=="vpn-device-denied","Old session refreshed itself after unbind");
            var race=await Task.WhenAll(new[]{deviceAKey,deviceBKey}.Select(key=>Task.Run(()=>{
                using var connection=new Store(Path.Combine(directory,"pnt.db"));
                try{connection.DeviceAccess("0123456789abcdef",key,"bind-device");return true;}catch(UnauthorizedAccessException){return false;}
            })));
            Assert(race.Count(won=>won)==1,"Two simultaneous devices both acquired the same profile");
            using(var reopened=new Store(Path.Combine(directory,"pnt.db")))
                Assert(reopened.DeviceAccess(profile.ClientId,deviceAKey,"check-device").Key==deviceAKey,"Binding lost on database reopen");

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
                var sessionAllowed=true;
                var exiting=VpnDatagrams.Exit(exit.GetStream(),"127.0.0.1",((IPEndPoint)echo.Client.LocalEndPoint!).Port,()=>sessionAllowed,stop.Token);
                await VpnDatagrams.Write(input.GetStream(),Encoding.UTF8.GetBytes("through-pnt"),stop.Token);
                var packet=await echo.ReceiveAsync(stop.Token);await echo.SendAsync(packet.Buffer,packet.RemoteEndPoint,stop.Token);
                Assert(Encoding.UTF8.GetString(await VpnDatagrams.Read(input.GetStream(),stop.Token))=="through-pnt","UDP tunnel roundtrip failed");
                sessionAllowed=false;await Task.Delay(1100);
                await VpnDatagrams.Write(input.GetStream(),new byte[]{9},stop.Token);
                try{await exiting.WaitAsync(stop.Token);throw new Exception("Deauthorized transport remained open");}catch(UnauthorizedAccessException){}
                Assert(!echo.Client.Poll(1000,SelectMode.SelectRead),"Deauthorized transport forwarded a packet");
                stop.Cancel();
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
            Console.WriteLine("PASS: challenge proof, copied-profile rejection, atomic first bind, unbind/session revocation, device rebind, repeatable encrypted profile exports, cross-node export, no-clobber output, signed profiles, client identity, ACL catalog, member isolation, revoke tombstones, UDP framing and real UDP roundtrip.");
        }
        finally{service.Stop();await running;}
    }
}
