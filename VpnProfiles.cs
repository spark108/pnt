using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Pnt;

static class VpnProfiles
{
    static byte[] Key(Store db)
    {
        var secret=db.Get("key_hash")??throw new IOException("Отсутствует ключ кластера для хранения профилей VPN.");
        return HMACSHA256.HashData(Convert.FromHexString(secret),Encoding.UTF8.GetBytes("PNT VPN profile storage v1"));
    }
    static byte[] Context(Store db,VpnClient client)=>Encoding.UTF8.GetBytes(db.Get("cluster")+":"+client.Id+":"+client.Cert);
    internal static string Protect(Store db,VpnClient client,byte[] identity)
    {
        var key=Key(db);
        try
        {
            var nonce=RandomNumberGenerator.GetBytes(12);var tag=new byte[16];var encrypted=new byte[identity.Length];
            using var aes=new AesGcm(key,16);
            aes.Encrypt(nonce,identity,encrypted,tag,Context(db,client));
            return Convert.ToBase64String([..nonce,..tag,..encrypted]);
        }
        finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(identity);}
    }
    internal static VpnProfile Export(Store db,X509Certificate2 cert,VpnClient client)
    {
        if(client.Removed)throw new ArgumentException("Клиент отозван.");
        if(client.ProtectedIdentity is null)throw new IOException("Закрытый ключ этого клиента не сохранён в кластере. Используйте исходный .pnt-файл; повторная выгрузка доступна для клиентов, созданных после обновления.");
        var encrypted=Convert.FromBase64String(client.ProtectedIdentity);
        if(encrypted.Length<=28)throw new IOException("Повреждён сохранённый ключ клиента.");
        var key=Key(db);var identity=new byte[encrypted.Length-28];
        try
        {
            using var aes=new AesGcm(key,16);
            aes.Decrypt(encrypted.AsSpan(0,12),encrypted.AsSpan(28),encrypted.AsSpan(12,16),identity,Context(db,client));
            using var credential=X509CertificateLoader.LoadPkcs12(identity,null,X509KeyStorageFlags.EphemeralKeySet);
            if(!credential.HasPrivateKey||Certificate.Id(credential)!=client.Id||Certificate.Fingerprint(credential)!=client.Cert)
                throw new IOException("Сохранённый ключ не соответствует клиенту.");
            if(credential.NotAfter.ToUniversalTime()<DateTime.UtcNow)throw new IOException("Срок действия ключа клиента истёк.");
            var nodes=db.Nodes().Where(n=>!n.Removed).ToArray();
            var servers=db.VpnServers().Where(s=>!s.Removed&&client.Servers.Contains(s.Id)&&nodes.Any(n=>n.Id==s.Id)).ToArray();
            if(servers.Length==0)throw new ArgumentException("У клиента нет доступных VPN-серверов.");
            var profile=new VpnProfile(1,db.Get("cluster")!,client.Id,Convert.ToBase64String(identity),nodes,servers,Convert.ToBase64String(cert.RawData),"");
            using var signer=cert.GetECDsaPrivateKey()!;
            return profile with{Signature=Convert.ToBase64String(signer.SignData(JsonSerializer.SerializeToUtf8Bytes(profile,App.Json),HashAlgorithmName.SHA256))};
        }
        finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(identity);}
    }
    internal static async Task Write(string path,VpnProfile profile)
    {
        var options=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        using var file=new FileStream(path,options);
        if(OperatingSystem.IsWindows())VpnControl.ProtectExport(path);
        await JsonSerializer.SerializeAsync(file,profile,App.Json);
    }
}
