using System.Security.Cryptography.X509Certificates;

namespace Pnt;

static class NodeManagement
{
    internal static Node Leave(Store db)
    {
        var self=db.Self()??throw new Exception("Узел не состоит в кластере.");
        var departed=self with{Removed=true,Version=Math.Max(App.Now,self.Version+1)};
        db.Put(departed);db.Set("left","1");return departed;
    }

    internal static void ApplyDeparture(Store db,Node target,Message reply)
    {
        var departed=reply.Nodes?.SingleOrDefault();
        if(reply.Type!="node-left"||reply.Id!=target.Id||reply.Target!=target.Id||departed is null||
            departed.Id!=target.Id||departed.Cert!=target.Cert||!departed.Removed||departed.Version<=target.Version)
            throw new IOException(reply.Error??"Узел не подтвердил добровольный выход; принудительное исключение не выполнено.");
        db.Put(departed);
    }

    internal static async Task Kick(Store db,X509Certificate2 cert,string destination)
    {
        var target=db.Resolve(destination)??throw new Exception("Узел не найден.");
        if(target.Id==db.Get("self"))throw new Exception("Для текущего узла используйте pnt node leave.");
        using(var peer=await new RouteTransport(db,cert).Connect(target.Id,message=>Console.Error.WriteLine(message)))
        {
            var task=await RouteTransport.SendTask(peer,new Message("node-leave",db.Get("self"),Target:target.Id));
            Message reply;
            try{reply=await RouteTransport.ReadResult(peer,task.RequestId,TimeSpan.FromSeconds(15));}
            catch(Exception e){throw new IOException("Подтверждение выхода не получено; проверьте pnt node list. Задача повторно не отправлена.",e);}
            ApplyDeparture(db,target,reply);
        }
        Console.WriteLine("Узел подтвердил добровольный выход. Изменение отправлено кластеру: "+await App.Broadcast(db,cert));
    }
}
