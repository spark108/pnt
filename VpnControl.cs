using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Pnt;

record VpnServer(string Id,string Name,long Version,bool Removed=false);
record VpnClient(string Id,string Name,string Cert,string[] Servers,long Version,bool Removed=false);
record VpnProfile(int Format,string Cluster,string ClientId,string Identity,Node[] Entrypoints,VpnServer[] Servers,string Issuer,string Signature);
record VpnOperation(string Action,string? Client=null,string? Fingerprint=null,bool KeepAlive=false);
record VpnConfiguration(string Config,string Host,int Port,string LocalHost,int LocalPort);
record VpnStatistics(long Handshake,long Received,long Sent,bool Exists,bool? Connected=null,string? Mode=null,string? Address=null,string[]? Route=null);

static class VpnControl
{
    static bool Key(string? value)=>value is {Length:16}&&value.All(Uri.IsHexDigit);
    public static bool Valid(VpnServer value)=>Key(value.Id)&&value.Name.Length is >0 and <=64&&value.Version>0;
    public static bool Valid(VpnClient value)=>Key(value.Id)&&value.Name.Length is >0 and <=64&&value.Cert.Length==64&&value.Cert.All(Uri.IsHexDigit)&&value.Servers.Length<=1024&&value.Servers.All(Key)&&value.Version>0;
    public static VpnClient FindClient(Store db,string name)
    {
        var clients=db.VpnClients();var exact=clients.FirstOrDefault(c=>c.Id==name);if(exact!=null)return exact;
        var matches=clients.Where(c=>c.Name.Equals(name,StringComparison.OrdinalIgnoreCase)).ToArray();
        var active=matches.Where(c=>!c.Removed).ToArray();
        return active.Length==1?active[0]:matches.Length==1?matches[0]:throw new ArgumentException("VPN-клиент не найден или имя неоднозначно; укажите ID.");
    }
    static Node FindNode(Store db,string name)=>db.Resolve(name)??throw new ArgumentException("Узел не найден.");
    static VpnServer FindServer(Store db,string name)
    {
        var node=FindNode(db,name);return db.VpnServers().FirstOrDefault(s=>s.Id==node.Id&&!s.Removed)??throw new ArgumentException("На узле не разрешено использование VPN.");
    }
    public static bool Permitted(Store db,VpnClient client,string server)=>!client.Removed&&client.Servers.Contains(server)&&db.VpnServers().Any(s=>s.Id==server&&!s.Removed)&&db.Resolve(server)!=null&&db.Get("left")!="1"&&db.Self()?.Removed==false;
    public static async Task Command(Store db,X509Certificate2 cert,string[] args)
    {
        if(db.Self() is null||db.Get("left")=="1")throw new Exception("Сначала присоединитесь к кластеру.");
        switch(args)
        {
            case ["server","install",var nodeName]:
                var registeredNode=FindNode(db,nodeName);
                if(registeredNode.Platform=="windows")throw new PlatformNotSupportedException("Сервер AmneziaWG устанавливается на Debian Linux.");
                var old=db.VpnServers().FirstOrDefault(s=>s.Id==registeredNode.Id);
                var displayName=old?.Name??registeredNode.Name[..Math.Min(64,registeredNode.Name.Length)];
                var inventory=JsonSerializer.Deserialize<VpnServerConfiguration[]>(await Query(db,cert,registeredNode.Id,new("inventory")),App.Json)??[];
                var selection=VpnServerInstaller.Choose(inventory,Console.In,Console.Out);
                var exit=registeredNode.Id==db.Self()!.Id?await VpnServerInstaller.Setup(selection)
                    :await RemoteCommands.Run(db,cert,registeredNode.Id,"/usr/local/bin/pnt _vpn-server-setup "+selection);
                if(exit!=0)throw new IOException("Установка AmneziaWG завершилась с ошибкой. Узел не добавлен в каталог VPN.");
                await Query(db,cert,registeredNode.Id,new("probe"));
                db.PutVpn(new VpnServer(registeredNode.Id,displayName.Trim(),Math.Max(App.Now,(old?.Version??0)+1)));
                Console.WriteLine("VPN-сервер разрешён: "+displayName);break;
            case ["server","remove",var name]:
                var server=FindServer(db,name);db.PutVpn(server with{Removed=true,Version=Math.Max(App.Now,server.Version+1)});
                await ReconcileRemote(db,cert,server.Id);Console.WriteLine("Сервер удалён из каталога VPN.");break;
            case ["server","list"]:
                CliOutput.Table(["ID","Узел","Название"],db.VpnServers().Where(s=>!s.Removed)
                    .Select(s=>new CliCell[]{s.Id,db.Resolve(s.Id)?.Name??"—",s.Name}));break;
            case ["client","create",var name,"--servers",var servers,"--out",var output]:
                if(string.IsNullOrWhiteSpace(name)||name.Length>64||name.Any(char.IsControl))throw new ArgumentException("Имя клиента: от 1 до 64 символов.");
                if(db.VpnClients().Any(c=>!c.Removed&&c.Name.Equals(name,StringComparison.OrdinalIgnoreCase)))throw new ArgumentException("Имя клиента уже занято.");
                var allowed=servers.Split(',',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).Select(n=>FindServer(db,n).Id).Distinct().ToArray();
                if(allowed.Length==0)throw new ArgumentException("Укажите хотя бы один VPN-сервер.");
                using(var key=ECDsa.Create(ECCurve.NamedCurves.nistP256))
                {
                    var req=new CertificateRequest("CN=pnt-vpn-client",key,HashAlgorithmName.SHA256);
                    using var identity=req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddYears(5));
                    var createdClient=new VpnClient(Certificate.Id(identity),name.Trim(),Certificate.Fingerprint(identity),allowed,App.Now);
                    var profile=new VpnProfile(1,db.Get("cluster")!,createdClient.Id,Convert.ToBase64String(identity.Export(X509ContentType.Pkcs12)),db.Nodes().Where(n=>!n.Removed).ToArray(),db.VpnServers().Where(s=>allowed.Contains(s.Id)&&!s.Removed).ToArray(),Convert.ToBase64String(cert.RawData),"");
                    using var signer=cert.GetECDsaPrivateKey()!;
                    profile=profile with{Signature=Convert.ToBase64String(signer.SignData(JsonSerializer.SerializeToUtf8Bytes(profile,App.Json),HashAlgorithmName.SHA256))};
                    var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};
                    if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
                    using(var file=new FileStream(output,options))
                    {
                        if(OperatingSystem.IsWindows())ProtectExport(output);
                        await JsonSerializer.SerializeAsync(file,profile,App.Json);
                    }
                    db.PutVpn(createdClient);Console.WriteLine($"Клиент создан: {createdClient.Id}. Профиль: {output}");
                }
                break;
            case ["client","list"]:
                await ListClients(db,cert);break;
            case ["client","show",var name]:Console.WriteLine(JsonSerializer.Serialize(FindClient(db,name),App.Json));break;
            case ["client",var action,var name,var node] when action is "allow" or "deny":
                var client=FindClient(db,name);if(client.Removed)throw new ArgumentException("Клиент отозван.");
                var target=action=="allow"?FindServer(db,node).Id:FindNode(db,node).Id;
                db.PutVpn(client with{Servers=action=="allow"?client.Servers.Append(target).Distinct().ToArray():client.Servers.Where(s=>s!=target).ToArray(),Version=Math.Max(App.Now,client.Version+1)});
                if(action=="deny")await ReconcileRemote(db,cert,target);
                Console.WriteLine("Права клиента обновлены.");break;
            case ["client","revoke",var name]:
                var revoked=FindClient(db,name);db.PutVpn(revoked with{Removed=true,Version=Math.Max(App.Now,revoked.Version+1)});
                foreach(var id in revoked.Servers)await ReconcileRemote(db,cert,id);
                Console.WriteLine("Клиент отозван.");break;
            case ["client","handshake",var name,..var targets] when targets.Length<=1:
                var requested=FindClient(db,name);
                var ids=targets.Length==1?new[]{FindNode(db,targets[0]).Id}:requested.Servers;
                var handshakeRows=new List<CliCell[]>();
                foreach(var id in ids)
                {
                    var serverName=db.VpnServers().FirstOrDefault(s=>s.Id==id)?.Name??id;
                    try
                    {
                        var result=await Query(db,cert,id,new("stats",requested.Id,requested.Cert));var stats=JsonSerializer.Deserialize<VpnStatistics>(result,App.Json)!;
                        handshakeRows.Add([serverName,new(!stats.Exists?"профиль не создан":stats.Handshake==0?"рукопожатий не было":DateTimeOffset.FromUnixTimeSeconds(stats.Handshake).ToString("u"),stats.Connected==true?"green":"grey"),$"{stats.Received} Б",$"{stats.Sent} Б"]);
                    }
                    catch(Exception e){handshakeRows.Add([serverName,new("недоступен: "+e.Message,"red"),"—","—"]);}
                }
                CliOutput.Table(["Сервер","Рукопожатие (UTC)","Принято","Отправлено"],handshakeRows);
                break;
            default:throw new ArgumentException("Неверная команда. pnt vpn server install|list|remove; pnt vpn client create|list|show|allow|deny|revoke|handshake");
        }
    }
    static async Task ListClients(Store db,X509Certificate2 cert)
    {
        var clients=db.VpnClients();
        var servers=clients.Where(c=>!c.Removed).SelectMany(c=>c.Servers).Distinct()
            .Where(id=>db.VpnServers().Any(s=>s.Id==id&&!s.Removed)&&db.Resolve(id)!=null).ToArray();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
        using var gate=new SemaphoreSlim(8);
        var reports=await Task.WhenAll(servers.Select(async id=>
        {
            Dictionary<string,VpnStatistics>? stats=null;
            try
            {
                await gate.WaitAsync(timeout.Token);
                try { stats=JsonSerializer.Deserialize<Dictionary<string,VpnStatistics>>(await Query(db,cert,id,new("clients"),timeout.Token),App.Json); }
                finally { gate.Release(); }
            }
            catch { }
            return (Id:id,Stats:stats);
        }));
        var rows=new List<CliCell[]>();
        foreach(var client in clients)
        {
            var state=client.Removed?(Status:"отключён",Mode:"—"):VpnConnections.Summary(reports.Where(r=>client.Servers.Contains(r.Id))
                .Select(r=>r.Stats is null?null:r.Stats.GetValueOrDefault(client.Id)??new VpnStatistics(0,0,0,false,false)));
            var active=client.Removed?[]:reports.Where(r=>client.Servers.Contains(r.Id)&&r.Stats?.GetValueOrDefault(client.Id)?.Connected==true)
                .Select(r=>(r.Id,Stats:r.Stats![client.Id])).ToArray();
            if(active.Length==0)
                rows.Add([client.Id,client.Name,CliOutput.Status(client.Removed?"отозван":"активен"),client.Servers.Length.ToString(),CliOutput.Status(state.Status),CliOutput.Mode(state.Mode),"—","—","—","—"]);
            foreach(var connection in active)
            {
                var stats=connection.Stats;
                var route=stats.Mode=="direct"?"клиент → "+(db.Resolve(connection.Id)?.Name??connection.Id)
                    :stats.Route is {Length:>0}?string.Join(" → ",stats.Route.Select(id=>db.Resolve(id)?.Name??id)):"неизвестен";
                rows.Add([client.Id,client.Name,CliOutput.Status("активен"),client.Servers.Length.ToString(),CliOutput.Status("подключён"),CliOutput.Mode(stats.Mode=="relay"?"транспорт":"прямое"),
                    connection.Id,db.VpnServers().FirstOrDefault(s=>s.Id==connection.Id)?.Name??db.Resolve(connection.Id)?.Name??connection.Id,stats.Address??"—",new(route,stats.Mode=="relay"?"cyan":"green")]);
            }
        }
        CliOutput.Table(["ID","Имя","Доступ","Серверов","Состояние","Подключение","ID узла","Название узла","Внутренний IP","Маршрут"],rows);
    }
    static async Task ReconcileRemote(Store db,X509Certificate2 cert,string id)
    {
        try{await Query(db,cert,id,new("reconcile"));}
        catch(Exception e){Console.WriteLine("Отзыв на "+id+" ожидает выполнения: "+e.Message);}
    }
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    static void ProtectExport(string path)
    {
        using var identity=System.Security.Principal.WindowsIdentity.GetCurrent();
        var acl=new System.Security.AccessControl.FileSecurity();acl.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{identity.User!,new System.Security.Principal.SecurityIdentifier("S-1-5-18")})
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(acl);
    }
    public static async Task<string> Query(Store db,X509Certificate2 cert,string target,VpnOperation operation,CancellationToken token=default)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(45));
        using var peer=await new RouteTransport(db,cert).Connect(target,cancellation:timeout.Token);
        var task=await RouteTransport.SendTask(peer,new Message("vpn-admin",Certificate.Id(cert),Target:target,VpnPayload:JsonSerializer.Serialize(operation,App.Json),VpnServers:db.VpnServers().ToArray(),VpnClients:db.VpnClients().ToArray())).WaitAsync(timeout.Token);
        var reply=await RouteTransport.ReadResult(peer,task.RequestId,TimeSpan.FromSeconds(40),timeout.Token);
        if(reply.Type!="vpn-result")throw new IOException(reply.Error??"VPN-сервис не ответил.");
        return reply.VpnPayload??"{}";
    }
    public static void Merge(Store db,Message request)
    {
        foreach(var s in request.VpnServers??[])if(Valid(s))db.PutVpn(s);
        foreach(var c in request.VpnClients??[])if(Valid(c)&&!db.VpnClients().Any(old=>old.Id==c.Id&&old.Cert!=c.Cert))db.PutVpn(c);
    }
    public static async Task Execute(Store db,X509Certificate2 cert,Stream stream,Message request,CancellationToken token)
    {
        try
        {
            Merge(db,request);
            var operation=JsonSerializer.Deserialize<VpnOperation>(request.VpnPayload??"{}",App.Json)??throw new ArgumentException("Нет операции.");
            if(operation.Action=="udp")
            {
                var config=await Prepare(db,operation,token);
                await Peer.Send(stream,new Message("vpn-result",Name:operation.KeepAlive?"vpn-keepalive-v1":null,VpnPayload:"{}",RequestId:request.RequestId));
                using var relay=new VpnConnections.Relay(Certificate.Id(cert),operation.Client!,(request.Hops??[]).Append(Certificate.Id(cert)).ToArray());
                await VpnDatagrams.Exit(stream,config.LocalHost,config.LocalPort,()=>Allowed(db,operation),token,relay.Touch,operation.KeepAlive);return;
            }
            var output=operation.Action switch
            {
                "inventory"=>await VpnServerInstaller.Inventory(token),
                "probe"=>await VpnAdapter.Run("probe",null,[],token),
                "ensure"=>JsonSerializer.Serialize(await Prepare(db,operation,token),App.Json),
                "stats"=>JsonSerializer.Serialize(VpnConnections.Observe(Certificate.Id(cert),operation.Client!,JsonSerializer.Deserialize<VpnStatistics>(await VpnAdapter.Run("stats",operation.Client,[],token),App.Json)!,DateTimeOffset.UtcNow.ToUnixTimeSeconds()),App.Json),
                "clients"=>JsonSerializer.Serialize((JsonSerializer.Deserialize<Dictionary<string,VpnStatistics>>(await VpnAdapter.Run("clients",null,[],token),App.Json)??[])
                    .ToDictionary(p=>p.Key,p=>VpnConnections.Observe(Certificate.Id(cert),p.Key,p.Value,DateTimeOffset.UtcNow.ToUnixTimeSeconds())),App.Json),
                "reconcile"=>await VpnAdapter.Run("reconcile",null,AllowedIds(db),token),
                _=>throw new ArgumentException("Неизвестная операция VPN.")
            };
            await Peer.Send(stream,new Message("vpn-result",VpnPayload:output,RequestId:request.RequestId));
        }
        catch(Exception e){await Peer.Send(stream,new Message("error",Error:e.Message,RequestId:request.RequestId));}
    }
    static string[] AllowedIds(Store db)=>db.VpnClients().Where(c=>Permitted(db,c,db.Get("self")!)).Select(c=>c.Id).ToArray();
    static bool Allowed(Store db,VpnOperation operation)=>db.VpnClients().Any(c=>c.Id==operation.Client&&c.Cert==operation.Fingerprint&&Permitted(db,c,db.Get("self")!));
    static async Task<VpnConfiguration> Prepare(Store db,VpnOperation operation,CancellationToken token)
    {
        if(!Allowed(db,operation))throw new UnauthorizedAccessException("Нет доступа к VPN-серверу.");
        var output=await VpnAdapter.Run("ensure",operation.Client,[],token);
        var config=JsonSerializer.Deserialize<VpnConfiguration>(output,App.Json)!;
        return config with{Host=db.Self()!.Ip,Config=config.Config.Replace("PNT_ENDPOINT",db.Self()!.Ip+":"+config.Port)};
    }
    public static async Task ClientRequest(Store db,X509Certificate2 cert,Peer peer,Message request,CancellationToken token)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(50));
        try
        {
            var client=db.VpnClients().FirstOrDefault(c=>c.Id==peer.RemoteId&&c.Cert==peer.RemoteFingerprint&&!c.Removed);
            if(client==null||request.Id!=client.Id||db.Get("left")=="1"||db.Self()?.Removed!=false)throw new UnauthorizedAccessException("Профиль клиента не разрешён или отозван.");
            if(request.Name=="catalog")
            {
                var servers=db.VpnServers().Where(s=>Permitted(db,client,s.Id)).ToArray();
                await Peer.Send(peer.Stream,new Message("vpn-result",VpnServers:servers,Nodes:db.Nodes().Where(n=>servers.Any(s=>s.Id==n.Id)).ToArray()));return;
            }
            if(request.Target is null||!Permitted(db,client,request.Target))throw new UnauthorizedAccessException("Сервер не разрешён клиенту.");
            if(request.Name is not ("ensure" or "udp" or "stats"))throw new UnauthorizedAccessException("Операция не разрешена клиенту.");
            var op=new VpnOperation(request.Name,client.Id,client.Cert,request.Name=="udp"&&request.Command=="vpn-keepalive-v1");
            if(request.Name=="udp")
            {
                using var outgoing=await new RouteTransport(db,cert).Connect(request.Target,cancellation:timeout.Token);
                var task=await RouteTransport.SendTask(outgoing,new Message("vpn-admin",Certificate.Id(cert),Target:request.Target,VpnPayload:JsonSerializer.Serialize(op,App.Json),VpnServers:db.VpnServers().ToArray(),VpnClients:db.VpnClients().ToArray()));
                var response=await RouteTransport.ReadResult(outgoing,task.RequestId,TimeSpan.FromSeconds(40));
                if(response.Type!="vpn-result")throw new IOException(response.Error??"Нет VPN-туннеля.");
                var keepAlive=op.KeepAlive&&response.Name=="vpn-keepalive-v1";
                await Peer.Send(peer.Stream,new Message("vpn-result",Name:keepAlive?"vpn-keepalive-v1":null,Hops:outgoing.RouteReady?.Hops));
                await VpnDatagrams.Relay(peer.Stream,outgoing.Stream,()=>Permitted(db,client,request.Target)&&db.VpnClients().Any(c=>c.Id==client.Id&&!c.Removed&&c.Servers.Contains(request.Target)),token,keepAlive);return;
            }
            var result=await Query(db,cert,request.Target,op,timeout.Token);
            await Peer.Send(peer.Stream,new Message("vpn-result",VpnPayload:result));
        }
        catch(Exception e){await Peer.Send(peer.Stream,new Message("error",Error:e.Message));}
    }
    public static async Task Reconcile(Store db,CancellationToken token)
    {
        if(!OperatingSystem.IsLinux()||!db.VpnServers().Any(s=>s.Id==db.Get("self")))return;
        await VpnAdapter.Run("reconcile",null,AllowedIds(db),token);
    }
}

static class VpnAdapter
{
    static readonly SemaphoreSlim gate=new(1,1);
    public static async Task<string> Run(string action,string? client,string[] allowed,CancellationToken token)
    {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("Сервер AmneziaWG поддерживается на Debian/Linux, напрямую или в Docker.");
        await gate.WaitAsync(token);
        try
        {
            var assembly=typeof(VpnAdapter).Assembly;
            using var resource=assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n=>n.EndsWith(".deploy.vpn_adapter.py")))!;
            using var reader=new StreamReader(resource);
            using var process=new Process{StartInfo=new ProcessStartInfo("python3"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true}};
            process.StartInfo.ArgumentList.Add("-c");process.StartInfo.ArgumentList.Add(await reader.ReadToEndAsync(token));
            process.StartInfo.Environment["PNT_VPN_DATA"]=Path.Combine(App.Dir,"vpn");
            process.Start();
            var output=process.StandardOutput.ReadToEndAsync(token);var error=process.StandardError.ReadToEndAsync(token);
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new{action,client,allowed},App.Json));process.StandardInput.Close();
            try{await process.WaitForExitAsync(token);}catch{process.Kill(true);throw;}
            if(process.ExitCode!=0)throw new IOException("AmneziaWG: "+(await error).Trim());
            return (await output).Trim();
        }
        finally{gate.Release();}
    }
}

static class VpnDatagrams
{
    internal readonly record struct Frame(ushort Size,byte[] Data);
    internal static async Task<Frame> ReadFrame(Stream stream,CancellationToken token,bool keepAlive)
    {
        var header=new byte[2];await stream.ReadExactlyAsync(header,token);var size=BinaryPrimitives.ReadUInt16BigEndian(header);
        if(keepAlive&&size is 0 or ushort.MaxValue)return new Frame(size,[]);
        if(size is 0 or >65507)throw new IOException("Некорректная UDP-датаграмма.");
        var packet=new byte[size];await stream.ReadExactlyAsync(packet,token);return new Frame(size,packet);
    }
    internal static async Task WriteFrame(Stream stream,Frame frame,CancellationToken token)
    {
        var header=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(header,frame.Size);
        await stream.WriteAsync(header,token);
        if(frame.Data.Length>0)await stream.WriteAsync(frame.Data,token);
        await stream.FlushAsync(token);
    }
    public static async Task<byte[]> Read(Stream stream,CancellationToken token)
    {
        return (await ReadFrame(stream,token,false)).Data;
    }
    public static async Task Write(Stream stream,ReadOnlyMemory<byte> packet,CancellationToken token)
    {
        if(packet.Length is 0 or >65507)throw new IOException("Некорректная UDP-датаграмма.");
        var header=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(header,(ushort)packet.Length);
        await stream.WriteAsync(header,token);await stream.WriteAsync(packet,token);await stream.FlushAsync(token);
    }
    public static async Task Relay(Stream input,Stream output,Func<bool> allowed,CancellationToken token,bool keepAlive=false)
    {
        allowed=CachedPermission(allowed);
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);var t=stop.Token;
        async Task Copy(Stream a,Stream b){while(!t.IsCancellationRequested){var packet=await ReadFrame(a,t,keepAlive);if(!allowed())throw new UnauthorizedAccessException("VPN-доступ отозван.");await WriteFrame(b,packet,t);}}
        var tasks=new[]{Copy(input,output),Copy(output,input)};
        try{await await Task.WhenAny(tasks);}finally{stop.Cancel();try{await Task.WhenAll(tasks);}catch{}}
    }
    public static async Task Exit(Stream stream,string host,int port,Func<bool> allowed,CancellationToken token,Action? activity=null,bool keepAlive=false)
    {
        allowed=CachedPermission(allowed);
        using var udp=new UdpClient();udp.Connect(host,port);
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);var t=stop.Token;
        using var writer=new SemaphoreSlim(1,1);
        async Task Reply(Frame frame){await writer.WaitAsync(t);try{await WriteFrame(stream,frame,t);}finally{writer.Release();}}
        async Task Send()
        {
            while(!t.IsCancellationRequested)
            {
                var frame=await ReadFrame(stream,t,keepAlive);if(!allowed())throw new UnauthorizedAccessException("VPN-доступ отозван.");
                if(frame.Size==0){await Reply(new Frame(ushort.MaxValue,[]));continue;}
                if(frame.Size==ushort.MaxValue)throw new IOException("Unexpected VPN heartbeat response.");
                await udp.SendAsync(frame.Data,t);activity?.Invoke();
            }
        }
        async Task Receive(){while(!t.IsCancellationRequested){var packet=await udp.ReceiveAsync(t);if(!allowed())throw new UnauthorizedAccessException("VPN-доступ отозван.");await Reply(new Frame((ushort)packet.Buffer.Length,packet.Buffer));}}
        var tasks=new[]{Send(),Receive()};try{await await Task.WhenAny(tasks);}finally{stop.Cancel();try{await Task.WhenAll(tasks);}catch{}}
    }
    static Func<bool> CachedPermission(Func<bool> check)
    {
        var gate=new object();long next=0;bool value=false;
        return ()=>{lock(gate){if(Environment.TickCount64>=next){value=check();next=Environment.TickCount64+1000;}return value;}};
    }
}
