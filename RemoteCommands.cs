using System.Security.Cryptography.X509Certificates;

namespace Pnt;

static class RemoteCommands
{
    public static async Task<int> Run(Store db, X509Certificate2 cert, string destination, string command, bool interactive = false)
    {
        if (db.Get("cluster") is null || db.Get("left") == "1" || db.Self()?.Removed == true)
            throw new Exception("Узел не состоит в активном кластере.");
        var target = db.Resolve(destination) ?? throw new Exception("Узел не найден.");
        if (command.Length is < 1 or > 16_384) throw new Exception("Длина команды должна быть от 1 до 16384 символов.");
        var self = db.Self()!;
        var routing = new RouteTransport(db, cert);
        using var peer = await routing.Connect(target.Id, message => Console.Error.WriteLine(message));
        try
        {
            using var terminal=interactive?new InteractiveTerminal():null;
            var dimensions=TerminalKeyboard.Size();
            var task = await RouteTransport.SendTask(peer, new Message("exec", self.Id, Target: target.Id,
                Command: command, Interactive: interactive,TerminalWidth:dimensions.Width,TerminalHeight:dimensions.Height));
                using var inputStop = new CancellationTokenSource();
                var input=interactive?Task.Run(async () =>
                {
                    while(!inputStop.IsCancellationRequested)
                    {
                        var size=TerminalKeyboard.Size();
                        if(size!=dimensions)
                        {
                            dimensions=size;
                            await Peer.Send(peer.Stream,new Message("exec-resize",RequestId:task.RequestId,TerminalWidth:size.Width,TerminalHeight:size.Height)).WaitAsync(inputStop.Token);
                        }
                        if(!Console.KeyAvailable){await Task.Delay(30,inputStop.Token);continue;}
                        var text=TerminalKeyboard.Encode(Console.ReadKey(true));
                        if(text.Length>0)await Peer.Send(peer.Stream,new Message("exec-input",Output:text,RequestId:task.RequestId)).WaitAsync(inputStop.Token);
                    }
                }):Task.CompletedTask;
                try { while (true)
                {
                    var response=RouteTransport.ReadResult(peer,task.RequestId,TimeSpan.FromDays(1));
                    if(interactive&&await Task.WhenAny(response,input)==input)await input;
                    var message=await response;
                    if (message.Type == "exec-output")
                    {
                        var writer = message.Stderr ? Console.Error : Console.Out;
                        writer.Write(message.Output);
                        writer.Flush();
                    }
                    else if (message.Type == "exec-exit") return message.ExitCode;
                    else if (message.Type == "error") throw new Exception(message.Error ?? "Ошибка выполнения команды.");
                }
                } finally { inputStop.Cancel();try{await input;}catch(OperationCanceledException){} }
        }
        catch (Exception e)
        {
            throw new Exception("Ошибка после выбора маршрута; задача повторно не отправляется. " + e.Message);
        }
    }
}
