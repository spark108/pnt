namespace Pnt;
static class TerminalChecks
{
    static void Assert(bool value,string message){if(!value)throw new Exception(message);}
    static string Key(ConsoleKey key,char value='\0',bool shift=false,bool alt=false,bool ctrl=false)=>TerminalKeyboard.Encode(new ConsoleKeyInfo(value,key,shift,alt,ctrl));
    public static async Task Main()
    {
        var state=Path.Combine(Path.GetTempPath(),"pnt-terminal-state-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(state);
        Environment.SetEnvironmentVariable("PNT_DATA_DIR",state);
        Assert(Key(ConsoleKey.LeftArrow)=="\u001b[D"&&Key(ConsoleKey.RightArrow)=="\u001b[C","Arrow encoding failed");
        Assert(Key(ConsoleKey.UpArrow)=="\u001b[A"&&Key(ConsoleKey.DownArrow)=="\u001b[B","History keys failed");
        Assert(Key(ConsoleKey.Home)=="\u001b[H"&&Key(ConsoleKey.End)=="\u001b[F"&&Key(ConsoleKey.Delete)=="\u001b[3~","Line editing failed");
        Assert(Key(ConsoleKey.LeftArrow,ctrl:true)=="\u001b[1;5D"&&Key(ConsoleKey.RightArrow,ctrl:true)=="\u001b[1;5C","Word navigation failed");
        Assert(Key(ConsoleKey.C,ctrl:true)=="\u0003"&&Key(ConsoleKey.D,ctrl:true)=="\u0004"&&Key(ConsoleKey.L,ctrl:true)=="\u000c","Control combinations failed");
        Assert(Key(ConsoleKey.B,'b',alt:true)=="\u001bb"&&Key(ConsoleKey.Tab,shift:true)=="\u001b[Z","Alt/Shift combinations failed");
        Assert(Key(ConsoleKey.F7)=="\u001b[18~"&&Key(ConsoleKey.Enter)=="\r"&&Key(ConsoleKey.Backspace)=="\u007f","Terminal special keys failed");
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var session=ShellSession.Start(OperatingSystem.IsWindows()?"cmd.exe /d /q":"bash --noprofile --norc -i",true,Path.GetTempPath(),100,30);
        var text=session.Output.ReadToEndAsync(timeout.Token);
        var stderr=session.Error?.ReadToEndAsync(timeout.Token)??Task.FromResult("");
        session.Resize(120,40);
        await session.Input!.WriteAsync("echo PNT_ABCD"+Key(ConsoleKey.LeftArrow)+Key(ConsoleKey.LeftArrow)+"X\r");
        await session.Input.WriteAsync(Key(ConsoleKey.UpArrow)+"\r");
        await session.Input.WriteAsync(OperatingSystem.IsWindows()?"prompt $E[32mPNT_COLOR$E[0m$G\r":"printf '\\033[32mPNT_COLOR\\033[0m\\n'\r");
        await session.Input.WriteAsync("echo Привет_PNT\r");
        await session.Input.WriteAsync(OperatingSystem.IsWindows()?"ping -n 30 127.0.0.1 >nul\r":"sleep 30\r");
        await session.Input.FlushAsync();await Task.Delay(350);
        await session.Input.WriteAsync(Key(ConsoleKey.C,ctrl:true));await Task.Delay(100);
        await session.Input.WriteAsync("echo PNT_DONE\r");
        await session.Input.WriteAsync("exit 0\r");await session.Input.FlushAsync();
        try{await session.WaitForExit().WaitAsync(timeout.Token);}
        catch{session.Kill();throw;}
        var output=await text+await stderr;
        File.WriteAllText(Path.Combine(Path.GetTempPath(),"pnt-terminal-check.txt"),output);
        Assert(output.Contains("PNT_ABXCD"),"PTY did not apply cursor editing");
        Assert(output.Split("PNT_ABXCD").Length>=3,"Session history did not recall previous command");
        Assert(output.Contains("PNT_DONE")&&output.Contains("\u001b["),"ANSI output lost or shell did not finish");
        Assert(output.Contains("Привет_PNT"),"Interactive Unicode was corrupted");
        Assert(session.ExitCode==0,"Interactive shell exited with error");
        var folder=Path.Combine(Path.GetTempPath(),"pnt-terminal-rpc-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
        using var cert=Certificate.Load(Path.Combine(folder,"node.pfx"));using var db=new Store(Path.Combine(folder,"node.db"));
        db.Set("self",Certificate.Id(cert));
        var service=new Service(db,cert);
        using var listener=new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback,0);listener.Start();
        using var client=new System.Net.Sockets.TcpClient();var accepting=listener.AcceptTcpClientAsync();
        await client.ConnectAsync(System.Net.IPAddress.Loopback,((System.Net.IPEndPoint)listener.LocalEndpoint).Port);
        using var connection=await accepting;
        var method=typeof(Service).GetMethod("Execute",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!;
        var request=new Message("exec",Certificate.Id(cert),Command:OperatingSystem.IsWindows()?"cmd.exe /d /q":"bash --noprofile --norc -i",Interactive:true,RequestId:"terminal-rpc",TerminalWidth:100,TerminalHeight:30);
        var serving=(Task)method.Invoke(service,[connection.GetStream(),request,false])!;
        var reading=Task.Run(async()=>
        {
            var result=new System.Text.StringBuilder();
            while(true)
            {
                var reply=await Peer.Read(client.GetStream()).WaitAsync(timeout.Token)??throw new Exception("Terminal stream closed early");
                Assert(reply.RequestId==request.RequestId,"Terminal response correlation lost");
                if(reply.Type=="exec-output")result.Append(reply.Output);
                else if(reply.Type=="exec-exit"){Assert(reply.ExitCode==0,"Framed terminal exit failed");return result.ToString();}
                else throw new Exception("Unexpected terminal message: "+reply.Type);
            }
        });
        await Peer.Send(client.GetStream(),new Message("exec-resize",RequestId:request.RequestId,TerminalWidth:120,TerminalHeight:40));
        await Peer.Send(client.GetStream(),new Message("exec-input",RequestId:request.RequestId,Output:"echo PNT_RPC\rexit 0\r"));
        Assert((await reading).Contains("PNT_RPC"),"Framed PTY output missing");await serving.WaitAsync(timeout.Token);
        Console.WriteLine("PASS: terminal keys, modifiers, real PTY editing/history, ANSI output, clean session exit and framed terminal RPC.");
    }
}
