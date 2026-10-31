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
        var scheduled=0;
        async Task<Message> Reboot(Message request,bool fail=false)
        {
            using var stream=new MemoryStream();
            await NodeManagement.ReceiveReboot(target,id,stream,request,(key,force)=>{
                if(fail)throw new IOException("test scheduler failure");
                Assert(key==request.RequestId&&force==request.Force,"Scheduler arguments differ");
                scheduled++;return Task.CompletedTask;
            });
            stream.Position=0;return (await Peer.Read(stream))!;
        }
        var request=new Message("node-reboot",id,Target:id,RequestId:Guid.NewGuid().ToString("N"),Deadline:App.Now+20000);
        var ack=await Reboot(request);
        Assert(ack.Type=="node-reboot-scheduled"&&ack.Id==id&&ack.Target==id&&ack.RequestId==request.RequestId&&!ack.Force&&scheduled==1,"Normal reboot acknowledgement failed");
        Assert((await Reboot(request)).Type=="node-reboot-scheduled"&&scheduled==1,"Duplicate reboot scheduled twice");
        Assert((await Reboot(request with{Force=true})).Type=="error"&&scheduled==1,"Duplicate request changed reboot mode");
        var forced=request with{RequestId=Guid.NewGuid().ToString("N"),Force=true};
        Assert((await Reboot(forced)).Force&&scheduled==2,"Forced reboot was not forwarded");
        foreach(var invalid in new[]{request with{Target="other"},request with{Id="outsider"},request with{RequestId="bad"},request with{Deadline=App.Now-1},request with{Deadline=App.Now+120000}})
            Assert((await Reboot(invalid)).Type=="error"&&scheduled==2,"Invalid reboot reached scheduler");
        var failure=request with{RequestId=Guid.NewGuid().ToString("N")};
        Assert((await Reboot(failure,true)).Type=="error"&&target.Get("last_reboot_request")==forced.RequestId+":True","Scheduler failure persisted success");
        Assert(!target.Self()!.Removed&&target.Get("left") is null,"Reboot changed cluster membership");
        foreach(var force in new[]{false,true})
        {
            foreach(var input in new[]{"","wrong\n","\n"})
                Assert(!NodeManagement.ConfirmReboot(member,force,new StringReader(input),new StringWriter()),"Missing/wrong confirmation accepted");
            using var prompt=new StringWriter();
            Assert(NodeManagement.ConfirmReboot(member,force,new StringReader(id.ToUpperInvariant()+"\n"),prompt),"Valid ID confirmation rejected");
            Assert(!force||prompt.ToString().Contains("Принудительная"),"Forced reboot prompt omitted force");
            var linux=HostReboot.Plan(false,force,request.RequestId!);
            Assert(!linux.UseShellExecute&&linux.FileName=="/usr/bin/systemd-run"&&linux.ArgumentList.Contains("--on-active=5s")&&linux.ArgumentList.Contains("/usr/bin/systemctl")&&linux.ArgumentList.Contains("reboot")&&linux.ArgumentList.Contains("--force")==force,"Unsafe Linux reboot plan");
            var windows=HostReboot.Plan(true,force,request.RequestId!);
            var command=windows.ArgumentList.Last();
            Assert(windows.CreateNoWindow&&!windows.UseShellExecute&&windows.ArgumentList.Contains("Hidden")&&command.Contains("Start-Sleep -Seconds 5")&&command.Contains("/r /t 0")&&command.Contains(" /f")==force,"Unsafe Windows reboot plan");
        }
        try{HostReboot.Plan(false,true,"bad;reboot");throw new Exception("Invalid scheduler ID accepted");}catch(ArgumentException){}
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
        Console.WriteLine("PASS: reboot confirmation, validation, deduplication, OS scheduling plans (no actual reboot); voluntary departure, addressed tasks, confirmation validation, clock skew and removal only after acknowledgement.");
    }
}
