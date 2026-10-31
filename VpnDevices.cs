using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

record VpnDeviceState(string Epoch,string? Key);
record VpnDeviceProof(string Key,string Signature);

static class VpnDevices
{
    static readonly System.Collections.Concurrent.ConcurrentDictionary<string,SemaphoreSlim> profileGates=new();
    internal static SemaphoreSlim Gate(string client)=>profileGates.GetOrAdd(client,_=>new(1,1));
    internal static byte[] Payload(string nonce,Message request)=>Encoding.UTF8.GetBytes("PNT device binding v1\n"+nonce+"\n"+request.Id+"\n"+request.Name+"\n"+request.Target+"\n"+request.DeviceEpoch);
    internal static string Verify(string nonce,Message request,VpnDeviceProof proof)
    {
        if(proof.Key.Length>256||proof.Signature.Length>256)throw new UnauthorizedAccessException("Некорректный ключ устройства.");
        using var key=ECDsa.Create();var encoded=Convert.FromBase64String(proof.Key);
        key.ImportSubjectPublicKeyInfo(encoded,out var consumed);
        if(consumed!=encoded.Length||key.KeySize!=256||key.ExportParameters(false).Curve.Oid.Value!=ECCurve.NamedCurves.nistP256.Oid.Value||
            !key.VerifyData(Payload(nonce,request),Convert.FromBase64String(proof.Signature),HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence))
            throw new UnauthorizedAccessException("Не подтверждён ключ устройства.");
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }
    internal static async Task<string> Challenge(Stream stream,Message request,CancellationToken token)
    {
        var nonce=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await Peer.Send(stream,new Message("vpn-device-challenge",VpnPayload:nonce)).WaitAsync(token);
        var response=await Peer.Read(stream).WaitAsync(token);
        if(response?.Type!="vpn-device-proof"||response.VpnPayload is null)throw new UnauthorizedAccessException("Обновите VPN-клиент: требуется подтверждение устройства.");
        var proof=JsonSerializer.Deserialize<VpnDeviceProof>(response.VpnPayload,App.Json)??throw new UnauthorizedAccessException("Нет подтверждения устройства.");
        return Verify(nonce,request,proof);
    }
    internal static VpnDeviceState Local(Store db,VpnOperation operation)
    {
        var client=db.VpnClients().SingleOrDefault(c=>c.Id==operation.Client&&!c.Removed&&c.Cert==operation.Fingerprint)
            ??throw new UnauthorizedAccessException("Клиент не разрешён.");
        if(client.DeviceAuthority!=db.Get("self"))throw new UnauthorizedAccessException("Этот узел не управляет привязкой клиента.");
        return db.DeviceAccess(client.Id,operation.DeviceKey,operation.Action);
    }
    internal static async Task<VpnDeviceState> Access(Store db,X509Certificate2 cert,VpnClient client,string? key,string action,CancellationToken token=default)
    {
        if(client.DeviceAuthority is null)throw new IOException("Для старого профиля администратор должен выполнить pnt vpn client unbind "+client.Id+".");
        var op=new VpnOperation(action,client.Id,client.Cert,DeviceKey:key);
        return client.DeviceAuthority==db.Get("self")?Local(db,op):
            JsonSerializer.Deserialize<VpnDeviceState>(await VpnControl.Query(db,cert,client.DeviceAuthority,op,token),App.Json)??throw new IOException("Нет ответа узла привязки.");
    }
    internal static async Task VerifyOperation(Store db,X509Certificate2 cert,VpnOperation operation,CancellationToken token)
    {
        var client=db.VpnClients().Single(c=>c.Id==operation.Client&&!c.Removed);
        var state=await Access(db,cert,client,operation.DeviceKey,"check-device",token);
        if(state.Epoch!=operation.DeviceEpoch)throw new UnauthorizedAccessException("Привязка устройства сброшена. Подключитесь заново.");
    }
    internal static async Task ResetServer(Store db,X509Certificate2 cert,VpnClient client,string? expectedEpoch,CancellationToken token)
    {
        var gate=Gate(client.Id);await gate.WaitAsync(token);
        try
        {
            var state=await Access(db,cert,client,null,"state-device",token);
            if(expectedEpoch is not null&&state.Epoch!=expectedEpoch)return;
            if(db.Get("vpn_profile_epoch:"+client.Id)==state.Epoch)return;
            db.Set("vpn_device_epoch:"+client.Id,state.Epoch);
            await VpnAdapter.Run("reset",client.Id,[],token);
            db.Set("vpn_profile_epoch:"+client.Id,state.Epoch);
        }
        finally{gate.Release();}
    }
    internal static async Task Unbind(Store db,X509Certificate2 cert,VpnClient client)
    {
        if(client.Removed)throw new ArgumentException("Клиент отозван.");
        if(client.DeviceAuthority is null)
        {
            client=client with{DeviceAuthority=db.Get("self"),Version=Math.Max(App.Now,client.Version+1)};
            db.PutVpn(client);await App.Broadcast(db,cert);
        }
        var reset=await Access(db,cert,client,null,"unbind-device");
        using var slots=new SemaphoreSlim(4);
        await Task.WhenAll(db.VpnServers().Where(s=>!s.Removed).Select(async server=>
        {
            await slots.WaitAsync();
            try{await VpnControl.Query(db,cert,server.Id,new("reset-device",client.Id,client.Cert,DeviceEpoch:reset.Epoch));}
            catch(Exception e){Console.Error.WriteLine("Сброс VPN-профиля на "+server.Id+" ожидает выполнения: "+e.Message);}
            finally{slots.Release();}
        }));
        Console.WriteLine("Привязка сброшена. При следующем подключении будет зарегистрировано устройство: "+client.Id);
    }
}
