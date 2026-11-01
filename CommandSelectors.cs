using System.Net;

namespace Pnt;

static class CommandSelectors
{
    enum Kind { Node, OtherNode, VpnServer, LinuxNode, Client, PendingNode }
    record Position(int Index,Kind Kind,bool Endpoint=false);
    record Choice(string Value,string Label);
    record Slot(int Index,Choice[] Values);
    internal sealed record Plan(Func<IEnumerable<string[]>> Commands,long Count,string[] Targets,Func<string[],string>? Describe=null,string Action="");

    internal static Plan? Create(Store db,string[] args)
    {
        if(args is ["sh","*","--interactive",..])throw new ArgumentException("--interactive нельзя использовать с селектором *. Укажите один конкретный узел.");
        if(args is ["nodes","*",..])throw new ArgumentException("В node list селектор * не применяется. Для списка всех узлов: pnt node list [--interactive].");
        if(args is ["vpn","client","get","*",..])throw new ArgumentException("Для выгрузки профиля укажите конкретного клиента: pnt vpn client get <client> [--out=file.pnt].");
        var positions=new List<Position>();
        var aggregate=-1;
        switch(args)
        {
            case ["sh",_,..]: positions.Add(new(1,Kind.Node));break;
            case ["routes",_]: positions.Add(new(1,Kind.OtherNode));break;
            case ["node",_,"reboot",..]: positions.Add(new(1,Kind.Node));break;
            case ["node","kick",_]: positions.Add(new(2,Kind.OtherNode));break;
            case ["cluster","remove",_]: positions.Add(new(2,Kind.OtherNode));break;
            case ["cluster",var action,_] when action is "accept" or "reject": positions.Add(new(2,Kind.PendingNode));break;
            case ["vpn",var action,_] when action is "status" or "start" or "stop" or "restart":
                positions.Add(new(2,action=="status"?Kind.LinuxNode:Kind.VpnServer));break;
            case ["vpn","server",var action,_,..] when action is "install" or "rename" or "remove":
                positions.Add(new(3,action=="install"?Kind.LinuxNode:Kind.VpnServer));break;
            case ["vpn","client","create",_,..]:
                aggregate=Array.IndexOf(args,"--servers")+1;
                if(aggregate==0)aggregate=-1;
                break;
            case ["vpn","client",var action,_,..] when action is "rename" or "show" or "allow" or "deny" or "unbind" or "revoke" or "handshake":
                positions.Add(new(3,Kind.Client));
                if(action is "allow" or "deny" or "handshake"&&args.Length>4)
                    positions.Add(new(4,action=="deny"?Kind.Node:Kind.VpnServer));
                break;
            case ["forward","add",..]:
                foreach(var option in new[]{"--listen","--to","--via"})
                {
                    var index=Array.IndexOf(args,option);
                    if(index>=0&&index+1<args.Length)positions.Add(new(index+1,Kind.Node,option!="--via"));
                }
                break;
        }
        string Host(Position p)=>p.Endpoint&&args[p.Index].LastIndexOf(':') is var colon&&colon>=0?args[p.Index][..colon]:args[p.Index];
        var stars=positions.Where(p=>Host(p)=="*").ToArray();
        var aggregateStar=aggregate>=0&&aggregate<args.Length&&args[aggregate].Split(',',StringSplitOptions.TrimEntries).Contains("*");
        if(stars.Length==0&&!aggregateStar)return null;
        if(db.Get("cluster") is null||db.Get("left")=="1"||db.Self()?.Removed!=false)throw new ArgumentException("Узел не состоит в активном кластере.");

        Choice[] Choices(Kind kind)
        {
            if(kind==Kind.Client)return db.VpnClients().Where(c=>!c.Removed).OrderBy(c=>c.Id).Select(c=>new Choice(c.Id,"Клиент: "+c.Name+" ("+c.Id+")")).ToArray();
            if(kind==Kind.PendingNode)return Enrollment.Requests(db).Where(r=>r.Status=="pending").OrderBy(r=>r.Id).Select(r=>new Choice(r.Id,"Заявка узла: "+r.Name+" ("+r.Id+")")).ToArray();
            var servers=db.VpnServers().Where(s=>!s.Removed).Select(s=>s.Id).ToHashSet();
            var nodes=db.Nodes().Where(n=>!n.Removed&&(kind!=Kind.OtherNode||n.Id!=db.Get("self"))&&
                (kind!=Kind.LinuxNode||n.Platform=="linux")&&(kind!=Kind.VpnServer||servers.Contains(n.Id)));
            if(args is ["node",_,"reboot",..])nodes=nodes.OrderBy(n=>n.Id==db.Get("self")).ThenBy(n=>n.Id);
            else nodes=nodes.OrderBy(n=>n.Id);
            return nodes.Select(n=>new Choice(n.Id,"Узел: "+n.Name+" ("+n.Id+")")).ToArray();
        }
        string Resolve(Position position)
        {
            var value=Host(position);
            if(position.Kind==Kind.Client)return VpnControl.FindClient(db,value).Id;
            if(position.Kind==Kind.PendingNode)return Choices(position.Kind).FirstOrDefault(c=>c.Value==value)?.Value??throw new ArgumentException("Заявка не найдена.");
            var node=db.Resolve(value);
            if(node is null)
            {
                if(position.Endpoint&&args[position.Index-1]=="--to"&&IPAddress.TryParse(value,out _))return value;
                throw new ArgumentException("Узел не найден: "+CliOutput.Clean(value));
            }
            if(position.Kind==Kind.VpnServer&&!Choices(position.Kind).Any(c=>c.Value==node.Id))throw new ArgumentException("Узел не зарегистрирован как VPN-сервер.");
            return node.Id;
        }
        var template=args.ToArray();var slots=new List<Slot>();var targets=new List<string>();
        foreach(var position in positions)
        {
            var suffix="";
            if(position.Endpoint)
            {
                var colon=args[position.Index].LastIndexOf(':');
                if(colon<1||!int.TryParse(args[position.Index][(colon+1)..],out var endpointPort)||endpointPort is <1 or >65535)
                    throw new ArgumentException("Адрес должен иметь вид узел:порт или *:порт.");
                suffix=args[position.Index][colon..];
            }
            if(Host(position)=="*")
            {
                var choices=Choices(position.Kind);
                if(choices.Length==0)throw new ArgumentException("Селектор * не нашёл подходящих объектов.");
                slots.Add(new(position.Index,choices.Select(c=>c with{Value=c.Value+suffix}).ToArray()));
                targets.AddRange(choices.Select(c=>c.Label));
            }
            else
            {
                var resolved=Resolve(position);template[position.Index]=resolved+suffix;
                var label=position.Kind==Kind.Client?"Клиент: "+VpnControl.FindClient(db,resolved).Name+" ("+resolved+")":
                    "Узел: "+(db.Resolve(resolved)?.Name??resolved)+" ("+resolved+")";
                targets.Add(label);
            }
        }
        if(args is ["vpn","client","rename","*",_]&&slots.Single().Values.Length>1)throw new ArgumentException("Нельзя дать нескольким клиентам одно уникальное имя. Укажите конкретного клиента.");
        if(aggregateStar)
        {
            var choices=Choices(Kind.VpnServer);
            if(choices.Length==0)throw new ArgumentException("Нет доступных VPN-серверов.");
            var selected=args[aggregate].Split(',',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries)
                .SelectMany(value=>value=="*"?choices.Select(c=>c.Value):new[]{db.Resolve(value)?.Id??throw new ArgumentException("VPN-узел не найден.")})
                .Distinct().Order().ToArray();
            if(selected.Any(id=>!choices.Any(c=>c.Value==id)))throw new ArgumentException("Узел не зарегистрирован как VPN-сервер.");
            template[aggregate]=string.Join(',',selected);targets.AddRange(choices.Select(c=>c.Label));
        }
        IEnumerable<string[]> Expand(int index,string[] command)
        {
            if(index==slots.Count){yield return command;yield break;}
            var slot=slots[index];
            foreach(var choice in slot.Values)
            {
                var next=command.ToArray();next[slot.Index]=choice.Value;
                foreach(var expanded in Expand(index+1,next))yield return expanded;
            }
        }
        IEnumerable<string[]> Commands()=>Expand(0,template.ToArray());
        if(args is ["forward","add",..])
        {
            var inputs=new HashSet<string>();var listen=Array.IndexOf(template,"--listen")+1;
            foreach(var command in Commands())
            {
                if(!inputs.Add(command[listen]))throw new ArgumentException("Селекторы создают несколько назначений для одного входного порта. Выберите один узел назначения и один --via.");
                var colon=command[listen].LastIndexOf(':');
                if(colon<0||!int.TryParse(command[listen][(colon+1)..],out var port)||port is <1 or >65535)throw new ArgumentException("Неверный входной порт.");
                if(FtpControl.Reserved(db,port)||port==442||port==WebPanel.Port&&db.Web()?.Enabled==true)throw new ArgumentException("Порт зарезервирован службой PNT.");
                if(db.Rules().Any(r=>!r.Removed&&r.In==command[listen][..colon]&&r.InPort==port))throw new ArgumentException("Входной порт уже занят правилом проброса.");
            }
        }
        long count=1;foreach(var slot in slots)count=checked(count*slot.Values.Length);
        var operationLabel=args switch
        {
            ["node",_,"reboot","-f"]=>"Принудительная перезагрузка ОС (-f)",
            ["node",_,"reboot"]=>"Перезагрузка ОС",
            ["nodes",..]=>"pnt node list",["routes",..]=>"pnt node routes",
            ["cluster",var operation,..]=>"pnt node "+operation,
            ["vpn",var group,..] when group is "client" or "server"=>"pnt "+string.Join(' ',args.Take(3)),
            _=>"pnt "+string.Join(' ',args.Take(args[0] is "sh" or "routes"?1:2))
        };
        return new(Commands,count,targets.Distinct().ToArray(),command=>string.Join(" · ",slots.Select(slot=>slot.Values.First(c=>c.Value==command[slot.Index]).Label)),operationLabel);
    }

    internal static async Task<int> Run(Plan plan,Func<string[],Task<int>> execute,TextReader input,TextWriter output,bool interactive)
    {
        output.WriteLine(plan.Action);
        foreach(var target in plan.Targets)output.WriteLine(CliOutput.Clean(target));
        output.WriteLine("Операций: "+plan.Count);
        if(!interactive)throw new IOException("Для подтверждения селектора * нужен интерактивный терминал.");
        while(true)
        {
            output.Write("Выполнить для выбранных объектов? [Y/N]: ");output.Flush();
            var answer=input.ReadLine()?.Trim();
            if(answer is null||answer.Length==0||answer.Equals("N",StringComparison.OrdinalIgnoreCase)){output.WriteLine("Отменено.");return 1;}
            if(answer.Equals("Y",StringComparison.OrdinalIgnoreCase))break;
            output.WriteLine("Введите Y или N.");
        }
        long succeeded=0,failed=0;
        foreach(var command in plan.Commands())
        {
            output.WriteLine("Операция "+(succeeded+failed+1)+"/"+plan.Count+" · "+CliOutput.Clean(plan.Describe?.Invoke(command)??""));
            try{if(await execute(command)==0)succeeded++;else failed++;}
            catch(Exception e){failed++;output.WriteLine("Ошибка: "+CliOutput.Clean(e.GetBaseException().Message));}
        }
        output.WriteLine("Успешно: "+succeeded+"; ошибок: "+failed);return failed==0?0:1;
    }
}
