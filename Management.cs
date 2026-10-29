using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

static class Management
{
    public static async Task<int> Local(string action)
    {
        if(OperatingSystem.IsWindows())return await Windows(action);
        RequireLinux();
        var source = File.Exists("/etc/pnt/source-dir")
            ? File.ReadAllText("/etc/pnt/source-dir").Trim() : Directory.GetCurrentDirectory();
        var script = Path.Combine(source, "pnt.sh");
        if (!File.Exists(script)) throw new Exception("Не найден pnt.sh. Запустите команду из каталога исходников PNT.");
        using var process = new Process { StartInfo = new ProcessStartInfo("/bin/sh") { UseShellExecute = false } };
        process.StartInfo.ArgumentList.Add(script);
        process.StartInfo.ArgumentList.Add(action);
        process.Start();
        await process.WaitForExitAsync();
        return process.ExitCode;
    }

    public static async Task<int> Remote(Store db, X509Certificate2 cert, string host)
    {
        if (!host.StartsWith("root@", StringComparison.Ordinal) || !IPAddress.TryParse(host[5..], out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork) throw new Exception("Используйте root@IPv4.");
        if (Console.IsInputRedirected) throw new Exception("Для SSH авторизации нужен интерактивный терминал.");
        var self = db.Self();
        if (self is null || self.Removed || db.Get("left") == "1") throw new Exception("Сначала создайте кластер или присоединитесь к нему.");
        var ip = address.ToString();
        Console.WriteLine($"Проверка доступности SSH {ip}:22 с узлов кластера...");
        var routing = new RouteTransport(db, cert);
        var results = await Task.WhenAll(db.Nodes().Where(n => !n.Removed && n.Platform!="windows")
            .Select(n => ExternalPing.Query(db, cert, self, n, ip, true, routing)));
        foreach (var result in results)
            Console.WriteLine($"{result.Node.Name} ({result.Node.Id}): " +
                (result.Measurement.Ms is double ms ? $"SSH доступен, {ms:0.0} ms" : result.Measurement.Error));
        var best = results.Where(r => r.Measurement.Ms.HasValue).OrderBy(r => r.Measurement.Ms).FirstOrDefault()
            ?? throw new Exception("SSH порт 22 недоступен со всех опрошенных узлов.");
        Console.WriteLine($"Установка с узла {best.Node.Name} ({best.Node.Id}). SSH запросит авторизацию при необходимости.");
        if (best.Node.Id == self.Id) return await LocalRemote(host);
        // Only the validated IPv4 literal is inserted into the shell command.
        var command = "source_dir=$(cat /etc/pnt/source-dir) && exec /bin/sh \"$source_dir/pnt.sh\" install -r root@" + ip;
        return await RemoteCommands.Run(db, cert, best.Node.Id, command, true);
    }

    static async Task<int> Windows(string action)
    {
        var sourceFile=Path.Combine(App.ConfigDir,"source-dir");
        var source=File.Exists(sourceFile)?File.ReadAllText(sourceFile).Trim():Directory.GetCurrentDirectory();
        var script=Path.Combine(source,"deploy","pnt.ps1");
        if(!File.Exists(script))throw new Exception("Не найден deploy/pnt.ps1. Запустите команду из каталога исходников.");
        using var process=new Process{StartInfo=new ProcessStartInfo("powershell.exe"){UseShellExecute=false}};
        foreach(var arg in new[]{"-NoProfile","-ExecutionPolicy","Bypass","-File",script,"-Action",action})process.StartInfo.ArgumentList.Add(arg);
        process.Start();await process.WaitForExitAsync();return process.ExitCode;
    }

    static async Task<int> LocalRemote(string host)
    {
        var source = File.Exists("/etc/pnt/source-dir") ? File.ReadAllText("/etc/pnt/source-dir").Trim() : Directory.GetCurrentDirectory();
        var script = Path.Combine(source, "pnt.sh");
        if (!File.Exists(script)) throw new Exception("Не найден pnt.sh в каталоге исходников.");
        using var process = new Process { StartInfo = new ProcessStartInfo("/bin/sh") { UseShellExecute = false } };
        foreach (var argument in new[] { script, "install", "-r", host }) process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        await process.WaitForExitAsync();
        return process.ExitCode;
    }

    public static async Task<ExternalPingMeasurement> CheckSsh(string ip)
    {
        try
        {
            if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
                return new(ip, null, "Ожидается IPv4 адрес.");
            using var tcp = new TcpClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var timer = Stopwatch.StartNew();
            await tcp.ConnectAsync(address, 22, timeout.Token);
            return new(ip, timer.Elapsed.TotalMilliseconds, null);
        }
        catch { return new(ip, null, "SSH порт 22 недоступен"); }
    }

    static void RequireLinux()
    {
        if (!OperatingSystem.IsLinux()) throw new Exception("Установка поддерживается на Debian Linux.");
    }
}
