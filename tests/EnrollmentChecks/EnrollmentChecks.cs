using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;

namespace Pnt;
static class EnrollmentChecks
{
    static void Assert(bool ok,string message){if(!ok)throw new Exception(message);}
    public static async Task Main(string[] args)
    {
        if(OperatingSystem.IsWindows())
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Console.OutputEncoding=Encoding.GetEncoding(866);
            Console.InputEncoding=Encoding.GetEncoding(866);
        }
        if(args.Contains("--encoding-only"))
        {
            var testDir=Path.Combine(Path.GetTempPath(),"pnt-encoding-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(testDir);
            await File.WriteAllTextAsync(Path.Combine(testDir,"проверка.txt"),"test");
            var command=OperatingSystem.IsWindows()?"dir /b & echo Привет & echo Ошибка 1>&2":"ls; printf 'Привет'; printf 'Ошибка' >&2";
            var info=ShellProcess.Create(command,false,testDir);
            using var process=new System.Diagnostics.Process{StartInfo=info};
            process.Start();var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            var text=await stdout;var error=await stderr;
            Assert(text.Contains("проверка.txt")&&text.Contains("Привет")&&error.Contains("Ошибка"),"Cyrillic stdout/stderr corrupted under OEM console encoding");
            Console.WriteLine("PASS: Cyrillic stdout and stderr under OEM parent console");return;
        }
        var directory=Path.Combine(Path.GetTempPath(),"pnt-nat-check-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
        Environment.SetEnvironmentVariable("PNT_DATA_DIR",directory);Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");
        using var a=Certificate.Load(Path.Combine(directory,"a.pfx"));using var b=Certificate.Load(Path.Combine(directory,"b.pfx"));
        using var serverDb=new Store(Path.Combine(directory,"a.db"));using var natDb=new Store(Path.Combine(directory,"b.db"));
        var aid=Certificate.Id(a);var bid=Certificate.Id(b);
        serverDb.Set("self",aid);serverDb.Set("cluster",Guid.NewGuid().ToString("N"));serverDb.Set("key_hash",new string('A',64));
        serverDb.Put(new Node(aid,"public","127.0.0.2",Certificate.Fingerprint(a),App.Now,Platform:App.Platform));
        natDb.Set("bootstrap_host","127.0.0.2");natDb.Set("bootstrap_name","nat-node");natDb.Set("bootstrap_ip","10.99.0.10");
        var server=new Service(serverDb,a);var nat=new Service(natDb,b);
        typeof(Service).GetMethod("RegisterMultiplex",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(nat,null);
        var listener=new TcpListener(IPAddress.Parse("127.0.0.2"),442);listener.Start();
        var sockets=0;
        _=Task.Run(async()=>{try{while(true){var socket=await listener.AcceptTcpClientAsync();Interlocked.Increment(ref sockets);_=Task.Run(async()=>{try{await(Task)typeof(Service).GetMethod("Handle",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(server,[socket])!;}catch{socket.Dispose();}});}}catch{}});
        using var stop=new CancellationTokenSource();
        var joining=Enrollment.Connect(natDb,b,stop.Token);
        try
        {
            for(var i=0;!Enrollment.Requests(serverDb).Any(r=>r.Id==bid)&&i<50;i++)await Task.Delay(100);
            Assert(natDb.Get("cluster") is null && serverDb.Resolve(bid) is null,"Enrollment joined without approval");
            Enrollment.Approve(serverDb,bid);
            for(var i=0;natDb.Get("cluster") is null&&i<50;i++)await Task.Delay(100);
            Assert(natDb.Get("cluster")==serverDb.Get("cluster"),"Approval not received");
            Assert(serverDb.Resolve(bid)?.BehindNat==true,"NAT status missing");
            await Task.Delay(200);
            var interfaces=await Forwarding.GetInterfaces(serverDb,a,bid);
            Assert(interfaces.Length>0,"Cannot reach NAT node on outbound connection");
            using(var peer=await new RouteTransport(serverDb,a).Connect(bid))
            {
                var command=OperatingSystem.IsWindows()?"echo NAT-reverse-ok & echo Привет & echo Ошибка 1>&2 & if not exist \"%ProgramFiles%\" exit /b 8":"echo NAT-reverse-ok";
                var task=await RouteTransport.SendTask(peer,new Message("exec",aid,Target:bid,Command:command));
                var output=new StringBuilder();
                while(true){var reply=await RouteTransport.ReadResult(peer,task.RequestId,TimeSpan.FromSeconds(10));if(reply.Type=="exec-output")output.Append(reply.Output);else if(reply.Type=="exec-exit"){Assert(reply.ExitCode==0,"Remote command failed");break;}}
                Assert(output.ToString().Contains("NAT-reverse-ok"),"Wrong remote output");
                if(OperatingSystem.IsWindows())Assert(output.ToString().Contains("Привет")&&output.ToString().Contains("Ошибка"),"Cyrillic stdout/stderr corrupted under OEM console encoding");
            }
            Assert(sockets==1,"Reverse task opened another network connection instead of reusing the NAT channel");
            MultiplexPool.CloseLocal(bid);await joining.WaitAsync(TimeSpan.FromSeconds(5));
            using(var reconnect=await Peer.Connect("127.0.0.2",Certificate.Fingerprint(a),b))
            {await Peer.Send(reconnect.Stream,new Message("route-info",bid));Assert((await Peer.Read(reconnect.Stream))?.Type=="route-info","Reconnect failed");}
            Assert((await Forwarding.GetInterfaces(serverDb,a,bid)).Length>0,"Reverse channel not restored after reconnect");
            var chosen=RouteCache.Apply([],bid,[(new[]{aid,"relay",bid},1.0),(new[]{aid,bid},100.0)]);
            Assert(chosen.Single(r=>r.Primary).Path.Length==2,"Direct route did not get priority");
            var natRoutes=RouteCache.Apply([],bid,[(new[]{aid,"nat",bid},1.0),(new[]{aid,"normal",bid},100.0)],n=>n=="nat");
            Assert(natRoutes.Single(r=>r.Primary).Path[1]=="normal","NAT transit did not get lower priority");
            Console.WriteLine("PASS: explicit approval, NAT reverse RPC, command execution, one outbound connection, reconnect, route priorities");
        }
        finally{stop.Cancel();MultiplexPool.CloseLocal(aid);MultiplexPool.CloseLocal(bid);listener.Stop();}
    }
}
