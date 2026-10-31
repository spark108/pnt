using System.Diagnostics;

namespace Pnt;

static class HostReboot
{
    internal static ProcessStartInfo Plan(bool windows,bool force,string requestId)
    {
        if(requestId.Length!=32||!requestId.All(Uri.IsHexDigit))throw new ArgumentException("Неверный ID запроса перезагрузки.");
        var info=new ProcessStartInfo{UseShellExecute=false,CreateNoWindow=true};
        if(windows)
        {
            info.FileName=Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe");
            foreach(var argument in new[]{"-NoLogo","-NoProfile","-NonInteractive","-WindowStyle","Hidden","-Command",
                "Start-Sleep -Seconds 5; & (Join-Path $env:SystemRoot 'System32/shutdown.exe') /r /t 0"+(force?" /f":"")})info.ArgumentList.Add(argument);
        }
        else
        {
            info.FileName="/usr/bin/systemd-run";info.RedirectStandardOutput=true;info.RedirectStandardError=true;
            foreach(var argument in new[]{"--quiet","--collect","--unit=pnt-reboot-"+requestId,"--on-active=5s","--timer-property=AccuracySec=1s","/usr/bin/systemctl","reboot"})info.ArgumentList.Add(argument);
            if(force)info.ArgumentList.Add("--force");
        }
        return info;
    }
    internal static async Task Schedule(string requestId,bool force)
    {
        if(!OperatingSystem.IsWindows()&&!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("ОС не поддерживает перезагрузку PNT.");
        using var process=new Process{StartInfo=Plan(OperatingSystem.IsWindows(),force,requestId)};
        if(!process.Start())throw new IOException("Не удалось запустить планировщик перезагрузки.");
        if(OperatingSystem.IsWindows())return;
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try{await process.WaitForExitAsync(timeout.Token);}catch{process.Kill(true);throw;}
        await output;
        if(process.ExitCode!=0)throw new IOException((await error).Trim());
    }
}
