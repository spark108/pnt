namespace Pnt;
static class SelectorChecks
{
    static void Assert(bool value,string message){if(!value)throw new Exception(message);}
    static CommandSelectors.Plan Plan(Store db,params string[] args)=>CommandSelectors.Create(db,args)??throw new Exception("Selector not detected");
    public static async Task Main()
    {
        var directory=Path.Combine(Path.GetTempPath(),"pnt-selectors-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
        using var certificate=Certificate.Load(Path.Combine(directory,"node.pfx"));
        using var db=new Store(Path.Combine(directory,"pnt.db"));var self=Certificate.Id(certificate);
        db.Set("self",self);db.Set("cluster","selector-test");db.Set("key_hash",new string('1',64));
        db.Put(new Node(self,"self","192.0.2.1",Certificate.Fingerprint(certificate),App.Now));
        const string linux="2222222222222222",windows="3333333333333333",removed="4444444444444444";
        db.Put(new Node(linux,"linux","192.0.2.2",new string('A',64),App.Now));
        db.Put(new Node(windows,"windows","192.0.2.3",new string('B',64),App.Now,Platform:"windows"));
        db.Put(new Node(removed,"removed","192.0.2.4",new string('C',64),App.Now,Removed:true));
        foreach(var node in new[]{self,linux,removed})db.PutVpn(new VpnServer(node,"vpn",App.Now));
        var alice=new VpnClient("aaaaaaaaaaaaaaaa","Alice",new string('D',64),[],App.Now);
        var bob=new VpnClient("bbbbbbbbbbbbbbbb","Bob",new string('E',64),[],App.Now);
        db.PutVpn(alice);db.PutVpn(bob);db.PutVpn(new VpnClient("cccccccccccccccc","Revoked",new string('F',64),[],App.Now,Removed:true));
        foreach(var ordinaryList in new[]{new[]{"nodes"},new[]{"nodes","--interactive"},new[]{"nodes",linux},new[]{"nodes",linux,"--interactive"}})
            Assert(CommandSelectors.Create(db,ordinaryList) is null,"Single-source node list or --interactive treated as selector");
        try{Plan(db,"nodes","*");throw new Exception("Node list accepted a selector");}catch(ArgumentException error){Assert(error.Message.StartsWith("В node list можно указать только один исходный узел."),"Node-list error text has a damaged source encoding");}
        Assert(Plan(db,"vpn","server","status","*").Commands().All(a=>a[3]!=windows&&a[3]!=removed),"VPN server status selector included unsuitable nodes");
        var all=Plan(db,"vpn","client","allow","*","*");
        Assert(all.Count==4&&all.Commands().Count()==4,"Client/server Cartesian product failed");
        Assert(all.Commands().All(a=>a[3] is "aaaaaaaaaaaaaaaa" or "bbbbbbbbbbbbbbbb"&&new[]{self,linux}.Contains(a[4])),"Removed or non-VPN node selected");
        var exceptAlice=Plan(db,"vpn","client","allow","*,-"+alice.Id,"*");
        Assert(exceptAlice.Count==2&&exceptAlice.Commands().All(a=>a[3]==bob.Id)&&!exceptAlice.Targets.Any(t=>t.Contains("Alice")),"Client exclusion or confirmation preview failed");
        var selected=Plan(db,"vpn","client","allow",alice.Id+","+bob.Id,"*,-"+self);
        Assert(selected.Count==2&&selected.Commands().All(a=>a[4]==linux),"Client list and server exclusion failed");
        var deduplicated=Plan(db,"vpn","client","allow",alice.Id+","+alice.Id+",Bob,-Bob",linux);
        Assert(deduplicated.Count==1&&deduplicated.Commands().Single()[3]==alice.Id,"Deduplication, name selection or order-independent exclusion failed");
        foreach(var invalid in new[]{"*,-unknown",alice.Id+",",alice.Id+",,"+bob.Id,"*,-",alice.Id+",-"+alice.Id,"-"+bob.Id})
        {try{Plan(db,"vpn","client","allow",invalid,"*");throw new Exception("Invalid selector accepted: "+invalid);}catch(ArgumentException){}catch(Exception e)when(e.Message.Contains("Клиент не найден")){} }
        var createExcluded=Plan(db,"vpn","client","create","Excluded","--servers","*,-"+self,"--out","ignored.pnt");
        Assert(createExcluded.Count==1&&createExcluded.Commands().Single()[5]==linux,"Create server exclusions failed");
        var listCalls=0;await CommandSelectors.Run(selected,_=>{listCalls++;return Task.FromResult(0);},new StringReader("N\n"),new StringWriter(),true);Assert(listCalls==0,"List/exclusion ran before confirmation");
        Assert(Plan(db,"node","relay","disable","*,-"+self).Count==2,"Relay selector omitted nodes or included excluded self");
        var later=new VpnClient("dddddddddddddddd","Later",new string('A',64),[],App.Now);
        db.PutVpn(later);Assert(all.Commands().Count()==4,"Confirmation selection changed after new client appeared");
        db.PutVpn(later with{Removed=true,Version=later.Version+1});
        var calls=0;
        foreach(var reply in new[]{"N\n","n\n","","\n","yes\nN\n"})
        {
            Assert(await CommandSelectors.Run(all,_=>{calls++;return Task.FromResult(0);},new StringReader(reply),new StringWriter(),true)==1,"Missing/negative confirmation succeeded");
            Assert(calls==0,"Selection executed before Y");
        }
        try{await CommandSelectors.Run(all,_=>{calls++;return Task.FromResult(0);},new StringReader("Y\n"),new StringWriter(),false);throw new Exception("Redirected confirmation accepted");}catch(IOException){}
        Assert(calls==0,"Redirected confirmation executed a task");
        var granted=await CommandSelectors.Run(all,async args=>{calls++;await VpnControl.Command(db,certificate,args.Skip(1).ToArray());return 0;},new StringReader("bad\ny\n"),new StringWriter(),true);
        Assert(granted==0&&calls==4&&db.VpnClients().Where(c=>!c.Removed).All(c=>c.Servers.Order().SequenceEqual(new[]{self,linux}.Order())),"Confirmed bulk allow did not grant all VPN servers");
        try{await VpnControl.Command(db,certificate,["client","rename",alice.Id,"bOB"]);throw new Exception("Duplicate client name accepted");}catch(ArgumentException){}
        Assert(VpnControl.FindClient(db,alice.Id).Name=="Alice","Failed rename changed client name");
        try{Plan(db,"vpn","client","rename","*","Shared");throw new Exception("Mass rename created duplicate names");}catch(ArgumentException){}
        var create=Plan(db,"vpn","client","create","NewClient","--servers","*","--out",Path.Combine(directory,"new.pnt"));
        Assert(create.Count==1&&create.Commands().Single()[5].Split(',').Order().SequenceEqual(new[]{self,linux}.Order()),"All-server aggregate created multiple clients or included non-VPN nodes");
        await CommandSelectors.Run(create,async args=>{await VpnControl.Command(db,certificate,args.Skip(1).ToArray());return 0;},new StringReader("Y\n"),new StringWriter(),true);
        Assert(db.VpnClients().Count(c=>c.Name=="NewClient")==1,"Create selector created multiple clients");
        var shell=Plan(db,"sh","*","echo","*.log");
        Assert(shell.Count==3&&shell.Commands().All(a=>a[^1]=="*.log")&&shell.Commands().Select(a=>a[1]).Contains(windows),"Shell wildcard altered command text or omitted a platform");
        Assert(CommandSelectors.Create(db,["sh",linux,"echo","*"]) is null,"Remote shell literal was treated as selector");
        Assert(CommandSelectors.Create(db,["name","*"]) is null&&CommandSelectors.Create(db,["create","cluster","*"]) is null,"Names or keys were expanded");
        Assert(Plan(db,"node","kick","*").Count==2&&Plan(db,"cluster","remove","*").Commands().All(a=>a[2]!=self),"Mass removal selected current node");
        var reboot=Plan(db,"node","*","reboot","-f");
        Assert(reboot.Count==3&&reboot.Commands().Last()[1]==self&&reboot.Commands().All(a=>a[^1]=="-f"),"Reboot did not preserve force or schedule self last");
        foreach(var command in new[]{new[]{"vpn","status","*"},new[]{"vpn","start","*"},new[]{"vpn","stop","*"},new[]{"vpn","restart","*"},new[]{"vpn","server","install","*"},new[]{"vpn","server","remove","*"},new[]{"vpn","server","rename","*","Shared"}})
            Assert(Plan(db,command).Count==2,"Wrong VPN node selection: "+string.Join(' ',command));
        foreach(var unsupported in new[]{new[]{"sh","*","--interactive","bash"},new[]{"sh",self+","+linux,"--interactive","bash"},new[]{"nodes","*"},new[]{"nodes","*","--interactive"},new[]{"nodes",self+","+linux},new[]{"vpn","client","get","*"},new[]{"vpn","client","get",alice.Id+","+bob.Id},new[]{"vpn","client","get","*","--out","clients.pnt"}})
        {
            try{Plan(db,unsupported);throw new Exception("Unnecessary selector remained supported");}catch(ArgumentException){}
        }
        db.PutJoin(new JoinRequest("5555555555555555","pending","192.0.2.5","192.0.2.5",new string('A',64),"linux",App.Now));
        Assert(Plan(db,"cluster","accept","*").Commands().Single()[2]=="5555555555555555"&&Plan(db,"cluster","reject","*").Count==1,"Pending enrollment not selected");
        var forward=Plan(db,"forward","add","--listen","*:8080","--to",linux+":80");
        Assert(forward.Count==3&&forward.Commands().All(a=>a[3].EndsWith(":8080")&&a[5]==linux+":80"),"Forward endpoint expansion failed");
        try{Plan(db,"forward","add","--listen",linux+":8080","--to","*:80");throw new Exception("Conflicting port destinations accepted");}catch(ArgumentException){}
        try{Plan(db,"forward","add","--listen","*","--to",linux+":80");throw new Exception("Endpoint without port accepted");}catch(ArgumentException){}
        var attempted=0;
        Assert(await CommandSelectors.Run(shell,_=>{if(++attempted==1)throw new IOException("unreachable");return Task.FromResult(0);},new StringReader("Y\n"),new StringWriter(),true)==1&&attempted==3,"Batch failure skipped later nodes or returned success");
        const string third="6666666666666666";db.Put(new Node(third,"third","192.0.2.6",new string('F',64),App.Now));db.PutVpn(new VpnServer(third,"third VPN",App.Now));
        var twoExclusions=Plan(db,"vpn","client","allow",alice.Id+","+bob.Id,"*,-"+self+",-"+linux);
        Assert(twoExclusions.Count==2&&twoExclusions.Commands().All(a=>a[4]==third),"Two distinct server exclusions failed");
        await CommandSelectors.Run(twoExclusions,async a=>{await VpnControl.Command(db,certificate,a.Skip(1).ToArray());return 0;},new StringReader("Y\n"),new StringWriter(),true);
        Assert(VpnControl.FindClient(db,alice.Id).Servers.Contains(third)&&VpnControl.FindClient(db,bob.Id).Servers.Contains(third)&&!db.VpnClients().Single(c=>c.Name=="NewClient").Servers.Contains(third),"Explicit client list granted an unselected client or missed a selected client");
        foreach(var client in db.VpnClients().Where(c=>!c.Removed))db.PutVpn(client with{Removed=true,Version=App.Now+10});
        try{Plan(db,"vpn","client","show","*");throw new Exception("Empty selection accepted");}catch(ArgumentException){}
        Console.WriteLine("PASS: selector scope, mandatory Y/N, no side effects on cancellation, bulk ACL/create, shell literals, endpoint conflicts, explicit exclusions for list/export and failure reporting. No real remote tasks or reboots executed.");
    }
}
