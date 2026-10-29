using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Pnt;

static class Firewall
{
    public static void Open(int port)
    {
        if(Environment.GetEnvironmentVariable("PNT_MANAGE_FIREWALL")=="0")return;
        if(OperatingSystem.IsWindows()) {WindowsRule(port,true);return;}
        if (!OperatingSystem.IsLinux()) return;
        try
        {
            var chain = Run("nft", "list", "chain", "inet", "filter", "input");
            if (chain.code == 0)
            {
                if (!chain.output.Contains($"tcp dport {port} accept", StringComparison.Ordinal))
                {
                    var added = Run("nft", "add", "rule", "inet", "filter", "input", "tcp", "dport", port.ToString(), "accept", "comment", "pnt");
                    if (added.code != 0) Console.Error.WriteLine("pnt: nftables: " + added.output);
                }
                return;
            }
        }
        catch { }
        try
        {
            if (Run("iptables", "-C", "INPUT", "-p", "tcp", "--dport", port.ToString(), "-j", "ACCEPT").code != 0)
            {
                var added = Run("iptables", "-I", "INPUT", "-p", "tcp", "--dport", port.ToString(), "-m", "comment", "--comment", "pnt", "-j", "ACCEPT");
                if (added.code != 0) Console.Error.WriteLine("pnt: iptables: " + added.output);
            }
        }
        catch (Exception e) { Console.Error.WriteLine("pnt: firewall: " + e.Message); }
    }

    public static void Close(int port)
    {
        if(Environment.GetEnvironmentVariable("PNT_MANAGE_FIREWALL")=="0")return;
        if(OperatingSystem.IsWindows()) {WindowsRule(port,false);return;}
        if (!OperatingSystem.IsLinux()) return;
        try
        {
            var chain = Run("nft", "-a", "list", "chain", "inet", "filter", "input");
            if (chain.code == 0)
            {
                foreach (var line in chain.output.Split('\n').Where(x => x.Contains($"tcp dport {port} accept") && x.Contains("pnt")))
                {
                    var match = Regex.Match(line, @"# handle (\d+)");
                    if (match.Success) Run("nft", "delete", "rule", "inet", "filter", "input", "handle", match.Groups[1].Value);
                }
                return;
            }
        }
        catch { }
        try { Run("iptables", "-D", "INPUT", "-p", "tcp", "--dport", port.ToString(), "-m", "comment", "--comment", "pnt", "-j", "ACCEPT"); }
        catch { }
    }

    static void WindowsRule(int port,bool open)
    {
        try
        {
            var command=open ? $"if (-not (Get-NetFirewallRule -Name PNT-TCP-{port} -ErrorAction SilentlyContinue)) {{ New-NetFirewallRule -Name PNT-TCP-{port} -DisplayName 'PNT TCP {port}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {port} | Out-Null }}"
                : $"Get-NetFirewallRule -Name PNT-TCP-{port} -ErrorAction SilentlyContinue | Remove-NetFirewallRule";
            var result=Run("powershell.exe","-NoProfile","-NonInteractive","-Command",command);
            if(result.code!=0)Console.Error.WriteLine("pnt: Windows firewall: "+result.output);
        }
        catch(Exception e){Console.Error.WriteLine("pnt: Windows firewall: "+e.Message);}
    }

    static (int code, string output) Run(string executable, params string[] args)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo(executable) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow=true } };
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15000)) { process.Kill(true); return (-1, "timeout"); }
        return (process.ExitCode, stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
    }
}
