using System.Reflection;

namespace Pnt;
static class NodeChecks
{
    static void Assert(bool condition,string message){if(!condition)throw new Exception(message);}
    public static async Task Main()
    {
        var folder=Path.Combine(Path.GetTempPath(),"pnt-node-check-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
        Environment.SetEnvironmentVariable("PNT_DATA_DIR",folder);Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");
        using var cert=Certificate.Load(Path.Combine(folder,"node.pfx"));
        var id=Certificate.Id(cert);using var target=new Store(Path.Combine(folder,"target.db"));using var requester=new Store(Path.Combine(folder,"requester.db"));
        var member=new Node(id,"target","127.0.0.1",Certificate.Fingerprint(cert),App.Now+60000);
        target.Set("self",id);target.Set("cluster","test");target.Put(member);requester.Put(member);
        var service=new Service(target,cert);var dispatch=typeof(Service).GetMethod("Dispatch",BindingFlags.NonPublic|BindingFlags.Instance)!;
        async Task<Message> Send(string destination)
        {
            using var stream=new MemoryStream();
            await (Task)dispatch.Invoke(service,[stream,new Message("node-leave","requester",Target:destination,RequestId:"kick-test"),true])!;
            stream.Position=0;return (await Peer.Read(stream))!;
        }
        var wrong=await Send("other");Assert(wrong.Type=="error"&&!target.Self()!.Removed&&target.Get("left") is null,"Wrong destination removed the node");
        var reply=await Send(id);Assert(reply.Type=="node-left"&&reply.RequestId=="kick-test"&&target.Self()!.Removed&&target.Get("left")=="1","Remote node did not voluntarily leave before confirmation");
        Assert(reply.Nodes![0].Version>member.Version,"Clock skew prevented departure propagation");
        foreach(var invalid in new[]{reply with{Id="other"},reply with{Type="error",Nodes=null},reply with{Nodes=[member]},reply with{Nodes=[reply.Nodes![0] with{Cert="wrong"}]}})
        {
            try{NodeManagement.ApplyDeparture(requester,member,invalid);throw new Exception("Invalid confirmation accepted");}catch(IOException){}
            Assert(!requester.Nodes().Single().Removed,"Target removed without valid confirmation");
        }
        NodeManagement.ApplyDeparture(requester,member,reply);Assert(requester.Nodes().Single().Removed,"Confirmed node not removed from cluster state");
        Console.WriteLine("PASS: voluntary departure, addressed tasks, confirmation validation, clock skew and removal only after acknowledgement.");
    }
}
