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
        var candidates = target.Id == self.Id ? [target] : RoutePlanner.Candidates(db, self.Id, target.Id, []).ToArray();
        foreach (var node in candidates)
        {
            Console.Error.WriteLine(node.Id == target.Id
                ? $"Соединение с {node.Name} ({node.Id}) напрямую..."
                : $"Соединение через {node.Name} ({node.Id}) к {target.Name}...");
            var sent = false;
            try
            {
                using var peer = await Peer.Connect(node.Id == self.Id ? "127.0.0.1" : node.Ip, node.Cert, cert);
                // After a request is sent, a lost acknowledgement does not prove that the command was not run.
                // Never retry it through another relay in that case.
                sent = true;
                await Peer.Send(peer.Stream, new Message("exec", self.Id, Target: target.Id,
                    Hops: [self.Id], Command: command, Interactive: interactive)).WaitAsync(TimeSpan.FromSeconds(10));
                var answer = await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(15));
                if (answer?.Type == "error")
                {
                    Console.Error.WriteLine($"Маршрут через {node.Name} недоступен: {answer.Error ?? "нет ответа"}");
                    continue;
                }
                if (answer?.Type != "ready") throw new IOException("Не получено подтверждение запуска команды.");
                if (answer.Hops is { Length: > 1 } path)
                    Console.Error.WriteLine("Маршрут: " + string.Join(" → ", path.Select(x =>
                        db.Nodes().FirstOrDefault(n => n.Id == x)?.Name ?? x)));
                using var inputStop = new CancellationTokenSource();
                if (interactive) _ = Task.Run(async () =>
                {
                    try
                    {
                        while (!inputStop.IsCancellationRequested)
                        {
                            if (!Console.KeyAvailable) { await Task.Delay(30); continue; }
                            var key = Console.ReadKey(true);
                            var text = key.Key == ConsoleKey.Enter ? "\n" : key.Key == ConsoleKey.Backspace ? "\u007f" : key.KeyChar.ToString();
                            await Peer.Send(peer.Stream, new Message("exec-input", Output: text));
                        }
                    }
                    catch { }
                });
                try { while (true)
                {
                    var message = await Peer.Read(peer.Stream) ?? throw new IOException("Соединение оборвалось до завершения команды.");
                    if (message.Type == "exec-output")
                    {
                        var writer = message.Stderr ? Console.Error : Console.Out;
                        writer.Write(message.Output);
                        writer.Flush();
                    }
                    else if (message.Type == "exec-exit") return message.ExitCode;
                    else if (message.Type == "error") throw new Exception(message.Error ?? "Ошибка выполнения команды.");
                }
                } finally { inputStop.Cancel(); }
            }
            catch (Exception e)
            {
                if (sent) throw new Exception("Связь потеряна после отправки команды; повторный запуск не выполняется. " + e.GetBaseException().Message, e);
                Console.Error.WriteLine($"Нет связи через {node.Name}: {e.GetBaseException().Message}");
            }
        }
        throw new Exception("Маршрут к узлу не найден.");
    }
}
