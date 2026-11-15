using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

record VpnDeviceState(string Epoch,string? Key);
record VpnDeviceProof(string Key,string Signature);
record VpnDeviceReplica(string Client, string Fingerprint, string Epoch, string? Key, long Version)
{
    internal bool Valid() =>
        Client is { Length: 16 } && Client.All(Uri.IsHexDigit) &&
        Fingerprint is { Length: 64 } && Fingerprint.All(Uri.IsHexDigit) &&
        Version is >= 0 and < long.MaxValue &&
        (Guid.TryParseExact(Epoch, "N", out _) || (Version == 0 && Epoch == "" && Key is null)) &&
        (Key is null or { Length: > 0 and <= 256 });
}

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
    internal static VpnDeviceState Access(Store db,VpnClient client,string? key,string action)
    {
        if(client.Removed)throw new UnauthorizedAccessException("Клиент не разрешён.");
        return db.DeviceAccess(client.Id,key,action,client.DeviceAuthority is not null&&client.DeviceAuthority==db.Get("self"));
    }
    internal static void VerifyOperation(Store db,VpnOperation operation)
    {
        var client=db.VpnClients().SingleOrDefault(c=>c.Id==operation.Client&&c.Cert==operation.Fingerprint&&!c.Removed)
            ??throw new UnauthorizedAccessException("Клиент не разрешён.");
        var state=Access(db,client,operation.DeviceKey,"check-device");
        if(state.Epoch!=operation.DeviceEpoch)throw new UnauthorizedAccessException("Привязка устройства сброшена. Подключитесь заново.");
    }
    internal static async Task ResetServer(Store db,VpnClient client,string? expectedEpoch,CancellationToken token)
    {
        var gate=Gate(client.Id);await gate.WaitAsync(token);
        try
        {
            var state=Access(db,client,null,"state-device");
            if(state.Epoch.Length==0)return;
            if(expectedEpoch is not null&&state.Epoch!=expectedEpoch)return;
            if(db.Get("vpn_profile_epoch:"+client.Id)==state.Epoch)return;
            await VpnAdapter.Run("reset",client.Id,[],token);
            db.Set("vpn_profile_epoch:"+client.Id,state.Epoch);
        }
        finally{gate.Release();}
    }
    internal static async Task Unbind(Store db,X509Certificate2 cert,VpnClient client)
    {
        if(client.Removed)throw new ArgumentException("Клиент отозван.");
        var reset=Access(db,client,null,"unbind-device");
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
