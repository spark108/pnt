using System.Security.Cryptography.X509Certificates;

namespace Pnt;

static class NodeManagement
{
    static readonly SemaphoreSlim rebootGate=new(1,1);
    static bool Active(Store db)=>db.Get("cluster") is not null&&db.Get("left")!="1"&&db.Self() is {Removed:false};
    internal static Node SetRelay(Store db,string? selector,bool enabled)
    {
        if(!Active(db))throw new IOException("Узел не состоит в активном кластере.");
        var node=db.Resolve(selector??db.Get("self")!)??throw new ArgumentException("Узел не найден.");
        if(node.RelayEnabled==enabled)return node;
        var updated=node with{RelayEnabled=enabled,Version=Math.Max(App.Now,node.Version+1)};db.Put(updated);return updated;
    }
    internal static async Task Relay(Store db,X509Certificate2 cert,string action,string[] args)
    {
        if(!Active(db))throw new IOException("Узел не состоит в активном кластере.");
        if(args.Length>1||action is not ("enable" or "disable" or "status"))throw new ArgumentException("pnt node relay enable|disable|status [node]");
        var selector=args.FirstOrDefault();
        var node=action=="status"?db.Resolve(selector??db.Get("self")!)??throw new ArgumentException("Узел не найден."):SetRelay(db,selector,action=="enable");
        CliOutput.Table(["ID","Узел","Транзит"],[[node.Id,node.Name,new(node.RelayEnabled?"включён":"только резерв",node.RelayEnabled?"green":"yellow")]]);
        if(action!="status")Console.WriteLine("Настройка отправлена кластеру: "+await App.Broadcast(db,cert)+". Новые маршруты предпочитают обычные реле; открытые потоки не разрываются.");
    }
    internal static bool ConfirmReboot(Node target,bool force,TextReader input,TextWriter output)
    {
        output.WriteLine((force?"Принудительная перезагрузка ОС":"Полная перезагрузка ОС")+": "+CliOutput.Clean(target.Name)+" ("+target.Id+").");
        output.Write("Введите ID узла для подтверждения: ");output.Flush();
        return string.Equals(input.ReadLine()?.Trim(),target.Id,StringComparison.OrdinalIgnoreCase);
    }
    internal static async Task Reboot(Store db,X509Certificate2 cert,string destination,bool force,bool selectionConfirmed=false)
    {
        var target=db.Resolve(destination)??throw new Exception("Узел не найден.");
        if(target.Platform is not ("linux" or "windows"))throw new PlatformNotSupportedException("Перезагрузка поддерживается на Linux и Windows.");
        if(Console.IsInputRedirected)throw new IOException("Для подтверждения перезагрузки нужен интерактивный терминал.");
        if(!selectionConfirmed&&!ConfirmReboot(target,force,Console.In,Console.Out)){Console.WriteLine("Перезагрузка отменена.");return;}
        using var peer=await new RouteTransport(db,cert).Connect(target.Id,message=>Console.Error.WriteLine(message));
        Message reply;
        try
        {
            var task=await RouteTransport.SendTask(peer,new Message("node-reboot",db.Get("self"),Target:target.Id,Force:force));
            reply=await RouteTransport.ReadResult(peer,task.RequestId,TimeSpan.FromSeconds(20));
        }
        catch(Exception e){throw new IOException("Подтверждение перезагрузки не получено; задача повторно не отправлялась. "+e.Message);}
        if(reply.Type!="node-reboot-scheduled"||reply.Id!=target.Id||reply.Target!=target.Id||reply.Force!=force)
            throw new IOException(reply.Error??"Узел не подтвердил запрошенный режим перезагрузки.");
        Console.WriteLine("Узел подтвердил "+(force?"принудительную перезагрузку":"перезагрузку")+" ОС через 5 секунд.");
    }
    internal static async Task ReceiveReboot(Store db,string self,Stream stream,Message request,Func<string,bool,Task> schedule)
    {
        if(request.Target!=self||request.RequestId is not {Length:32}||!request.RequestId.All(Uri.IsHexDigit)||
            request.Deadline<=App.Now||request.Deadline>App.Now+60_000||db.Self()?.Removed!=false||db.Get("left")=="1"||
            request.Id is null||db.Resolve(request.Id) is null)
        {
            await Peer.Send(stream,new Message("error",Error:"Недопустимый или просроченный запрос перезагрузки.",RequestId:request.RequestId));return;
        }
        await rebootGate.WaitAsync();
        try
        {
            var previous=db.Get("last_reboot_request");
            var operation=request.RequestId+":"+request.Force;
            if(previous?.StartsWith(request.RequestId+":",StringComparison.Ordinal)==true&&previous!=operation)
                throw new IOException("Повторный запрос изменяет режим перезагрузки.");
            if(previous!=operation)
            {
                await schedule(request.RequestId,request.Force);
                db.Set("last_reboot_request",operation);
            }
            await Peer.Send(stream,new Message("node-reboot-scheduled",self,Target:self,RequestId:request.RequestId,Force:request.Force));
        }
        catch(Exception e){await Peer.Send(stream,new Message("error",Error:"Не удалось запланировать перезагрузку: "+e.Message,RequestId:request.RequestId));}
        finally{rebootGate.Release();}
    }
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
