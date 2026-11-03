using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Pnt;

// These documents travel only over the installer-owned authenticated SSH channel.
record ProvisionIdentity(string Certificate,string Name,string Ip,string Platform);
record ProvisionBundle(string Cluster,string KeyHash,string Entry,Node Source,Node Target,Message State);

static class Provisioning
{
    internal static ProvisionIdentity Identity(Store db,X509Certificate2 cert)
    {
        if(db.Get("cluster") is not null)throw new IOException("Узел уже состоит в кластере.");
        return new(Convert.ToBase64String(cert.RawData),Environment.MachineName,App.OwnIp,App.Platform);
    }

    internal static ProvisionBundle Export(Store db,ProvisionIdentity identity)
    {
        var source=db.Self();
        if(source is not {Removed:false}||db.Get("left")=="1"||db.Get("cluster") is not string cluster||db.Get("key_hash") is not string key)
            throw new IOException("Нет активного кластера.");
        using var certificate=X509CertificateLoader.LoadCertificate(Convert.FromBase64String(identity.Certificate));
        if(identity.Name.Length is <1 or >64||!IPAddress.TryParse(identity.Ip,out var ip)||ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||identity.Platform is not ("linux" or "windows"))
            throw new IOException("Некорректная идентичность нового узла.");
        var id=Certificate.Id(certificate);var fingerprint=Certificate.Fingerprint(certificate);
        var previous=db.Nodes().FirstOrDefault(n=>n.Id==id);
        if(id==source.Id||previous is not null&&(previous.Removed||previous.Cert!=fingerprint))throw new IOException("Идентичность узла уже использована или исключена.");
        var target=previous??new Node(id,identity.Name,ip.ToString(),fingerprint,App.Now,BehindNat:Enrollment.Private(identity.Ip),Platform:identity.Platform);
        db.Put(target);
        return new(cluster,key,source.Ip,source,target,new Message("welcome",source.Id,Nodes:db.Nodes().ToArray(),Rules:db.Rules().ToArray(),Web:db.Web(),Update:db.Update(),Cesium:db.Cesium(),Ftp:db.Ftp()));
    }

    internal static void Import(Store db,X509Certificate2 cert,ProvisionBundle bundle)
    {
        if(db.Get("cluster") is not null)throw new IOException("Узел уже состоит в кластере.");
        if(bundle.Target.Id!=Certificate.Id(cert)||bundle.Target.Cert!=Certificate.Fingerprint(cert)||bundle.Target.Removed||bundle.Source.Removed||
            bundle.Cluster.Length!=32||!bundle.Cluster.All(Uri.IsHexDigit)||bundle.KeyHash.Length!=64||!bundle.KeyHash.All(Uri.IsHexDigit)||
            !IPAddress.TryParse(bundle.Entry,out _)||bundle.State.Nodes?.Contains(bundle.Target)!=true||bundle.State.Nodes.Contains(bundle.Source)!=true)
            throw new IOException("Параметры подключения не соответствуют этому узлу.");
        foreach(var node in bundle.State.Nodes)db.Put(node);
        foreach(var rule in bundle.State.Rules??[])db.Put(rule);
        if(bundle.State.Web is not null)db.PutWeb(bundle.State.Web);
        if(bundle.State.Ftp is not null)db.PutFtp(bundle.State.Ftp);
        if(bundle.State.Cesium is not null)db.PutCesium(bundle.State.Cesium);
        if(bundle.State.Update is not null){db.PutUpdate(bundle.State.Update);db.Set("update_applied",bundle.State.Update.Id);}
        db.Set("self",bundle.Target.Id);db.Set("key_hash",bundle.KeyHash);
        db.Set("bootstrap_host",bundle.Entry);db.Set("bootstrap_peer_cert",bundle.Source.Cert);
        db.Set("bootstrap_pin:"+bundle.Entry,bundle.Source.Cert);db.Set("left","0");
        // Set membership last: the service must not observe partially imported state.
        db.Set("cluster",bundle.Cluster);
    }

    internal static async Task Run(Store db,X509Certificate2 cert,string action)
    {
        LocalAccess.DemandAdministrator();
        if(action=="identity")Console.WriteLine(JsonSerializer.Serialize(Identity(db,cert),App.Json));
        else if(action=="export")
        {
            var identity=JsonSerializer.Deserialize<ProvisionIdentity>(await Console.In.ReadToEndAsync(),App.Json)??throw new IOException("Нет идентичности узла.");
            Console.WriteLine(JsonSerializer.Serialize(Export(db,identity),App.Json));
        }
        else if(action=="import")Import(db,cert,JsonSerializer.Deserialize<ProvisionBundle>(await Console.In.ReadToEndAsync(),App.Json)??throw new IOException("Нет параметров подключения."));
        else throw new ArgumentException("Неизвестная операция установки.");
    }
}
