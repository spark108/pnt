using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Pnt;

static class VpnClientAgent
{
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
            var initial=await Request(profile,identity,"stats",target);
            var baseline=JsonSerializer.Deserialize<VpnStatistics>(initial.VpnPayload!,App.Json)!.Handshake;
            using var local=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
            using var direct=new UdpClient();direct.Connect(config.Host,config.Port);
            using var stop=new CancellationTokenSource();
            Peer? relay=null;IPEndPoint? consumer=null;byte[]? lastPacket=null;
            var transportGate=new SemaphoreSlim(1,1);long lastTraffic=0;
            var token=stop.Token;
            async Task Upload()
            {
                while(!token.IsCancellationRequested)
                {
                    var packet=await local.ReceiveAsync(token);
                    if(consumer!=null&&!consumer.Equals(packet.RemoteEndPoint))continue;
                    consumer??=packet.RemoteEndPoint;lastPacket=packet.Buffer;
                    await transportGate.WaitAsync(token);
                    try{if(relay is null){try{await direct.SendAsync(packet.Buffer,token);}catch(SocketException){}}else await VpnDatagrams.Write(relay.Stream,packet.Buffer,token);}
                    finally{transportGate.Release();}
                }
            }
            async Task DirectDownload()
            {
                while(!token.IsCancellationRequested)
                {
                    try{var packet=await direct.ReceiveAsync(token);if(consumer!=null&&relay is null){Volatile.Write(ref lastTraffic,Environment.TickCount64);await local.SendAsync(packet.Buffer,consumer,token);}}
                    catch(SocketException){await Task.Delay(500,token);}
                }
            }
            async Task Monitor()
            {
                await Task.Delay(10_000,token);
                while(!token.IsCancellationRequested)
                {
                    var statsReply=await Request(profile,identity,"stats",target,token);
                    var stats=JsonSerializer.Deserialize<VpnStatistics>(statsReply.VpnPayload!,App.Json)!;
                    Output(new{status="statistics",handshake=stats.Handshake});
                    if(stats.Handshake>baseline&&Environment.TickCount64-Volatile.Read(ref lastTraffic)<60_000)
                    {Output(new{status="connected",mode=relay is null?"direct":"relay",server=target});await Task.Delay(15_000,token);continue;}
                    if(relay is null)
                    {
                        await transportGate.WaitAsync(token);
                        try
                        {
                            relay=await Open(profile,identity,"udp",target,token);
                            if(lastPacket!=null)await VpnDatagrams.Write(relay.Stream,lastPacket,token);
                            Output(new{status="routing",mode="relay",route=relay.RouteReady?.Hops,server=target});
                        }
                        finally{transportGate.Release();}
                        _=Task.Run(async()=>{try{while(!token.IsCancellationRequested){var packet=await VpnDatagrams.Read(relay.Stream,token);Volatile.Write(ref lastTraffic,Environment.TickCount64);if(consumer!=null)await local.SendAsync(packet,consumer,token);}}catch(Exception e){if(!token.IsCancellationRequested)Output(new{error="VPN-транспорт: "+e.Message});stop.Cancel();}},token);
                    }
                    await Task.Delay(15_000,token);
                }
            }
            var endpoint=(IPEndPoint)local.Client.LocalEndPoint!;
            var native=Regex.Replace(config.Config,@"(?m)^Endpoint\s*=.*$","Endpoint = 127.0.0.1:"+endpoint.Port);
            Output(new{ok=true,config=native,server=target,host=config.Host,mode="direct",entrypoints=profile.Entrypoints.Select(n=>n.Ip).Distinct().ToArray()});
            var tasks=new[]{Upload(),DirectDownload(),Monitor()};
            var inputTask=Console.In.ReadLineAsync();
            try
            {
                var finished=await Task.WhenAny(tasks.Append(inputTask));
                if(finished!=inputTask)await finished;
            }
            finally{stop.Cancel();relay?.Dispose();try{await Task.WhenAll(tasks);}catch{}transportGate.Dispose();}
            return 0;
        }
        catch(Exception e){Output(new{error=e.Message});return 1;}
    }
    static async Task<Message> Request(VpnProfile profile,X509Certificate2 identity,string action,string? target,CancellationToken token=default)
    {
        using var peer=await Open(profile,identity,action,target,token);return peer.RouteReady!;
    }
    static async Task<Peer> Open(VpnProfile profile,X509Certificate2 identity,string action,string? target,CancellationToken token)
    {
        Exception? failure=null;
        foreach(var node in profile.Entrypoints.Where(n=>!n.Removed))
        {
            Peer? peer=null;
            try
            {
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(50));
                peer=await Peer.ConnectRaw(node.Ip,node.Cert,identity,timeout.Token);
                await Peer.Send(peer.Stream,new Message("vpn-client",profile.ClientId,Name:action,Target:target)).WaitAsync(timeout.Token);
                var reply=await Peer.Read(peer.Stream).WaitAsync(timeout.Token);
                if(reply?.Type!="vpn-result")throw new IOException(reply?.Error??"Нет ответа PNT.");
                peer.RouteReady=reply;return peer;
            }
            catch(Exception e)when(!token.IsCancellationRequested){peer?.Dispose();failure=e;}
        }
        throw new IOException("Входные узлы PNT недоступны: "+failure?.Message,failure);
    }
}
