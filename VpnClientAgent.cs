using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Pnt;

static class VpnClientAgent
{
    static int relayCursor;
    public static VpnProfile Validate(string json)
    {
        if(json.Length>1_048_576)throw new ArgumentException("Профиль слишком большой.");
        var profile=JsonSerializer.Deserialize<VpnProfile>(json,App.Json)??throw new ArgumentException("Некорректный профиль PNT.");
        if(profile.Format!=1||profile.Entrypoints.Length is 0 or >1024||profile.Servers.Length is 0 or >1024||profile.Entrypoints.Any(n=>!IPAddress.TryParse(n.Ip,out _)||n.Cert.Length!=64))throw new ArgumentException("Неподдерживаемый профиль PNT.");
        using var issuer=X509CertificateLoader.LoadCertificate(Convert.FromBase64String(profile.Issuer));
        if(!profile.Entrypoints.Any(n=>n.Cert==Certificate.Fingerprint(issuer)))throw new ArgumentException("Издатель отсутствует среди доверенных узлов.");
        using var key=issuer.GetECDsaPublicKey();
        if(key is null||!key.VerifyData(JsonSerializer.SerializeToUtf8Bytes(profile with{Signature=""},App.Json),Convert.FromBase64String(profile.Signature),HashAlgorithmName.SHA256))throw new ArgumentException("Подпись профиля PNT недействительна.");
        using var identity=Identity(profile);
        if(!identity.HasPrivateKey||Certificate.Id(identity)!=profile.ClientId||identity.NotAfter.ToUniversalTime()<DateTime.UtcNow)throw new ArgumentException("Ключ клиента недействителен или истёк.");
        return profile;
    }
    static X509Certificate2 Identity(VpnProfile profile)=>X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(profile.Identity),null,OperatingSystem.IsWindows()?X509KeyStorageFlags.Exportable:X509KeyStorageFlags.EphemeralKeySet);
    static void Output(object value)=>Console.WriteLine(JsonSerializer.Serialize(value,App.Json));
    public static async Task<int> Run(string[] args)
    {
        Console.InputEncoding=System.Text.Encoding.UTF8;Console.OutputEncoding=new System.Text.UTF8Encoding(false);
        try
        {
            var line=await Console.In.ReadLineAsync()??throw new ArgumentException("Нет запроса клиента.");
            if(line.Length>1_100_000)throw new ArgumentException("Запрос слишком большой.");
            using var input=JsonDocument.Parse(line);var root=input.RootElement;var action=root.GetProperty("action").GetString();
            var profile=Validate(root.GetProperty("profile").GetRawText());
            if(action=="import"){Output(new{ok=true,clientId=profile.ClientId});return 0;}
            using var identity=Identity(profile);
            if(action=="catalog")
            {
                var result=await Request(profile,identity,"catalog",null);
                Output(new{ok=true,servers=result.VpnServers,nodes=result.Nodes,clientId=profile.ClientId});return 0;
            }
            if(action!="connect")throw new ArgumentException("Неизвестная операция клиента.");
            var target=root.GetProperty("server").GetString()??throw new ArgumentException("Сервер не выбран.");
            var reply=await Request(profile,identity,"ensure",target);
            var config=JsonSerializer.Deserialize<VpnConfiguration>(reply.VpnPayload!,App.Json)!;
            var epoch=reply.DeviceEpoch??throw new IOException("Сервер не вернул поколение сессии устройства.");
            var initial=await Request(profile,identity,"stats",target,epoch:epoch);
            var baseline=JsonSerializer.Deserialize<VpnStatistics>(initial.VpnPayload!,App.Json)!.Handshake;
            using var local=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            using var direct=new UdpClient();direct.Connect(config.Host,config.Port);
            using var stop=new CancellationTokenSource();
            IPEndPoint? consumer=null;byte[]? lastPacket=null;
            var relay=new VpnRelay(async(avoid,ct)=>
            {
                if(!profile.Entrypoints.Any(n=>!n.Removed&&n.Id!=avoid))return null;
                return await Open(profile,identity,"udp",target,ct,avoid,epoch);
            },peer=>Output(new{status="routing",mode="relay",route=peer.RouteReady?.Hops,server=target}));
            long lastTraffic=0;
            var token=stop.Token;
            async Task Upload()
            {
                while(!token.IsCancellationRequested)
                {
                    var packet=await local.ReceiveAsync(token);
                    if(consumer!=null&&!consumer.Equals(packet.RemoteEndPoint))continue;
                    consumer??=packet.RemoteEndPoint;lastPacket=packet.Buffer;
                    if(relay.Enabled)relay.Send(packet.Buffer);
                    else try{await direct.SendAsync(packet.Buffer,token);}catch(SocketException){}
                }
            }
            async Task DirectDownload()
            {
                while(!token.IsCancellationRequested)
                {
                    try{var packet=await direct.ReceiveAsync(token);if(consumer!=null&&!relay.Enabled){Volatile.Write(ref lastTraffic,Environment.TickCount64);await local.SendAsync(packet.Buffer,consumer,token);}}
                    catch(SocketException){await Task.Delay(500,token);}
                }
            }
            async Task Monitor()
            {
                await Task.Delay(10_000,token);
                while(!token.IsCancellationRequested)
                {
                    try
                    {
                        var statsReply=await Request(profile,identity,"stats",target,token,epoch);
                        var stats=JsonSerializer.Deserialize<VpnStatistics>(statsReply.VpnPayload!,App.Json)!;
                        Output(new{status="statistics",handshake=stats.Handshake});
                        var healthy=stats.Handshake>baseline&&Environment.TickCount64-Volatile.Read(ref lastTraffic)<60_000;
                        if(!relay.Enabled&&!healthy)relay.Enable(lastPacket);
                        if(healthy)Output(new{status="connected",mode=relay.Enabled?"relay":"direct",server=target});
                    }
                    catch(UnauthorizedAccessException){throw;}
                    catch(Exception)when(!token.IsCancellationRequested)
                    {
                        if(Environment.TickCount64-Volatile.Read(ref lastTraffic)>60_000)relay.Enable(lastPacket);
                    }
                    await Task.Delay(15_000,token);
                }
            }
            var endpoint=(IPEndPoint)local.Client.LocalEndPoint!;
            var native=Regex.Replace(config.Config,@"(?m)^Endpoint\s*=.*$","Endpoint = 127.0.0.1:"+endpoint.Port);
            Output(new{ok=true,config=native,server=target,host=config.Host,mode="direct",entrypoints=profile.Entrypoints.Select(n=>n.Ip).Distinct().ToArray()});
            var tasks=new[]{Upload(),DirectDownload(),Monitor(),relay.Run(async packet=>
            {
                Volatile.Write(ref lastTraffic,Environment.TickCount64);
                if(consumer!=null)await local.SendAsync(packet,consumer,token);
            },token)};
            var inputTask=Console.In.ReadLineAsync();
            try
            {
                var finished=await Task.WhenAny(tasks.Append(inputTask));
                if(finished!=inputTask)await finished;
            }
            finally{stop.Cancel();try{await Task.WhenAll(tasks);}catch{}}
            return 0;
        }
        catch(Exception e){Output(new{error=e.Message});return 1;}
    }
    static async Task<Message> Request(VpnProfile profile,X509Certificate2 identity,string action,string? target,CancellationToken token=default,string? epoch=null)
    {
        using var peer=await Open(profile,identity,action,target,token,epoch:epoch);return peer.RouteReady!;
    }
    static async Task<Peer> Open(VpnProfile profile,X509Certificate2 identity,string action,string? target,CancellationToken token,string? exclude=null,string? epoch=null)
    {
        Exception? failure=null;
        var candidates=profile.Entrypoints.Where(n=>!n.Removed&&n.Id!=exclude).OrderBy(n=>n.Id!=target).ToArray();
        var offset=action=="udp"&&candidates.Length>0?(int)((uint)Interlocked.Increment(ref relayCursor)%(uint)candidates.Length):0;
        foreach(var node in candidates.Skip(offset).Concat(candidates.Take(offset)))
        {
            Peer? peer=null;
            try
            {
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(50));
                peer=await Peer.ConnectRaw(node.Ip,node.Cert,identity,timeout.Token);
                if(action=="udp")peer.EnableKeepAlive();
                await Peer.Send(peer.Stream,new Message("vpn-client",profile.ClientId,Name:action,Target:target,DeviceEpoch:epoch)).WaitAsync(timeout.Token);
                var reply=await Peer.Read(peer.Stream).WaitAsync(timeout.Token);
                if(reply?.Name=="vpn-device-denied")throw new UnauthorizedAccessException(reply.Error);
                if(reply?.Type!="vpn-device-challenge"||reply.VpnPayload is null)throw new IOException(reply?.Error??"Обновите узел PNT: сервер не поддерживает привязку устройства.");
                using(var device=VpnDeviceIdentity.Load())
                {
                    var request=new Message("vpn-client",profile.ClientId,Name:action,Target:target,DeviceEpoch:epoch);
                    var proof=new VpnDeviceProof(Convert.ToBase64String(device.ExportSubjectPublicKeyInfo()),Convert.ToBase64String(device.SignData(VpnDevices.Payload(reply.VpnPayload,request),HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence)));
                    await Peer.Send(peer.Stream,new Message("vpn-device-proof",VpnPayload:JsonSerializer.Serialize(proof,App.Json))).WaitAsync(timeout.Token);
                }
                reply=await Peer.Read(peer.Stream).WaitAsync(timeout.Token);
                if(reply?.Name=="vpn-device-denied")throw new UnauthorizedAccessException(reply.Error);
                if(reply?.Type!="vpn-result")throw new IOException(reply?.Error??"Нет ответа PNT.");
                peer.RouteReady=reply;return peer;
            }
            catch(UnauthorizedAccessException){peer?.Dispose();throw;}
            catch(Exception e)when(!token.IsCancellationRequested){peer?.Dispose();failure=e;}
        }
        throw new IOException("Входные узлы PNT недоступны: "+failure?.Message,failure);
    }
}
