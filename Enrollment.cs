using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

static class Enrollment
{
    public static IEnumerable<JoinRequest> Requests(Store db)=>db.JoinRequests().Where(r=>r.Created>App.Now-600_000);
    public static bool Private(string ip)
    {
        if(!IPAddress.TryParse(ip,out var address)||address.AddressFamily!=AddressFamily.InterNetwork)return false;
        var b=address.GetAddressBytes();
        return b[0]==10||b[0]==127||b[0]==192&&b[1]==168||b[0]==172&&b[1]>=16&&b[1]<=31||b[0]==100&&b[1]>=64&&b[1]<=127||b[0]==169&&b[1]==254;
    }
    public static void Approve(Store db,string id)
    {
        if(db.Self()?.Removed!=false||db.Get("left")=="1")throw new Exception("Нет активного кластера.");
        var request=Requests(db).FirstOrDefault(r=>r.Id==id&&r.Status=="pending")??throw new Exception("Активная заявка не найдена.");
        if(db.Nodes().Any(n=>n.Id==id))throw new Exception("ID уже использован. Для исключённого узла создайте новую идентичность.");
        db.Put(new Node(id,request.Name,request.Ip,request.Cert,App.Now,BehindNat:request.BehindNat||Private(request.Ip)&&request.Ip!=request.ObservedIp,Platform:request.Platform));
        db.PutJoin(request with{Status="accepted"});
    }
    public static void Reject(Store db,string id)
    {
        var request=Requests(db).FirstOrDefault(r=>r.Id==id&&r.Status=="pending")??throw new Exception("Заявка не найдена.");
        db.PutJoin(request with{Status="rejected"});
    }

    public static async Task Receive(Store db,X509Certificate2 cert,Peer peer,Message request,CancellationToken token)
    {
        if(db.Get("cluster") is null || db.Self()?.Removed!=false || db.Get("left")=="1" || request.Id!=peer.RemoteId || request.Cert!=peer.RemoteFingerprint ||
            request.Name is not {Length:>0 and <=64} || request.Platform is not ("windows" or "linux") || !IPAddress.TryParse(request.Ip,out var ip) || ip.AddressFamily!=AddressFamily.InterNetwork)
        {await Peer.Send(peer.Stream,new Message("error",Error:"Заявка недопустима или кластер неактивен."));return;}
        var old=db.JoinRequests().FirstOrDefault(r=>r.Id==request.Id);
        var member=db.Nodes().FirstOrDefault(n=>n.Id==request.Id);
        if(member?.Removed==true || member is not null && member.Cert!=request.Cert)
        {await Peer.Send(peer.Stream,new Message("error",Error:"Идентичность исключена или сертификат изменён."));return;}
        if(member is null)
        {
            if(old?.Status=="rejected") {await Peer.Send(peer.Stream,new Message("error",Error:"Заявка отклонена."));return;}
            if(Requests(db).Count(r=>r.Status=="pending")>=64 && old is null)return;
            db.PutJoin(new JoinRequest(request.Id!,request.Name!,ip.ToString(),peer.RemoteAddress?.MapToIPv4().ToString()??ip.ToString(),request.Cert!,request.Platform??"linux",App.Now,BehindNat:request.BehindNat));
        }
        await Peer.Send(peer.Stream,new Message("enroll-pending",Target:request.Id,Cert:Certificate.Fingerprint(cert)));
        for(var count=0;count<60 && member is null;count++)
        {
            await Task.Delay(1000,token);
            if(db.JoinRequests().Any(r=>r.Id==request.Id&&r.Status=="rejected"))return;
            member=db.Nodes().FirstOrDefault(n=>n.Id==request.Id&&!n.Removed);
        }
        if(member is null)return;
        await Peer.Send(peer.Stream,new Message("welcome",Certificate.Id(cert),Host:db.Get("cluster"),KeyHash:db.Get("key_hash"),Nodes:db.Nodes().ToArray(),Rules:db.Rules().ToArray(),Web:db.Web(),Update:db.Update()));
        var mux=await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(10),token);
        if(mux?.Type=="mux" && mux.Id==member.Id)await MultiplexPool.Accept(peer,Certificate.Id(cert),true);
    }

    public static async Task Connect(Store db,X509Certificate2 cert,CancellationToken token)
    {
        var host=db.Get("bootstrap_host");if(host is null||db.Get("cluster") is not null)return;
        var pin=db.Get("bootstrap_pin:"+host);
        using var peer=await Peer.ConnectRaw(host,pin,cert,token);
        if(pin is null) {db.Set("bootstrap_pin:"+host,peer.RemoteFingerprint);Console.WriteLine("pnt: bootstrap certificate: "+peer.RemoteFingerprint);}
        var self=Certificate.Id(cert);
        var advertised=db.Get("bootstrap_ip")??App.OwnIp;
        await Peer.Send(peer.Stream,new Message("enroll",self,Name:db.Get("bootstrap_name")??Environment.MachineName,Ip:advertised,Cert:Certificate.Fingerprint(cert),Platform:App.Platform,
            BehindNat:Private(advertised)||!Forwarding.Interfaces().Any(i=>i.Address==advertised)));
        var pending=await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(10),token);
        if(pending?.Type!="enroll-pending")throw new IOException(pending?.Error??"Заявка не принята.");
        var reply=await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(70),token);
        if(reply?.Type!="welcome")return;
        if(reply.KeyHash is not {Length:64} || reply.Host is not {Length:32} ||
            reply.Nodes?.Any(n=>n.Id==self&&n.Cert==Certificate.Fingerprint(cert)&&!n.Removed)!=true)throw new IOException("Некорректное подтверждение.");
        db.Set("self",self);db.Set("key_hash",reply.KeyHash);
        db.Set("bootstrap_peer_cert",peer.RemoteFingerprint);
        MultiplexPool.SetAddress(self,peer.RemoteFingerprint,host);
        foreach(var n in reply.Nodes)db.Put(n);
        foreach(var rule in reply.Rules??[])db.Put(rule);
        if(reply.Web is not null)db.PutWeb(reply.Web);
        if(reply.Update is not null){db.PutUpdate(reply.Update);db.Set("update_applied",reply.Update.Id);}
        db.Set("cluster",reply.Host);
        Console.WriteLine("pnt: joined cluster through outbound channel to "+host);
        await Peer.Send(peer.Stream,new Message("mux",self,Name:"service"));
        var ready=await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(10),token);
        if(ready?.Type=="mux-ready")await MultiplexPool.Adopt(peer,self);
    }
}
