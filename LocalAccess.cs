using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Diagnostics;

namespace Pnt;

static class LocalAccess
{
    public static void Demand()
    {
        if(OperatingSystem.IsLinux())
        {
            if(geteuid()!=0)
            {
                var entry=getgrnam("pnt");
                if(entry==IntPtr.Zero)throw Denied();
                var gid=Marshal.PtrToStructure<Group>(entry).Gid;
                var count=getgroups(0,null);
                if(count<0 || count>65536)throw Denied();
                var groups=new uint[count];
                if(getegid()!=gid && (getgroups(count,groups)<0 || !groups.Contains(gid)))throw Denied();
            }
            umask(7); // Shared state stays writable by pnt, never by other users.
            return;
        }
        if(OperatingSystem.IsWindows()) {DemandWindows();return;}
        throw new UnauthorizedAccessException("PNT поддерживает локальную авторизацию на Linux и Windows.");
    }

    static UnauthorizedAccessException Denied()=>new("Доступ запрещён: нужен root или членство в группе pnt.");
    public static void DemandAdministrator()
    {
        if(OperatingSystem.IsLinux() && geteuid()==0)return;
        if(OperatingSystem.IsWindows() && WindowsAdministrator())return;
        throw new UnauthorizedAccessException("Установка и управление системной службой требуют root или запуска от имени администратора.");
    }
    [SupportedOSPlatform("windows")]
    static bool WindowsAdministrator()
    {
        using var identity=WindowsIdentity.GetCurrent();
        return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void Prepare()
    {
        if(OperatingSystem.IsLinux())
        {
            if(geteuid()!=0)throw new UnauthorizedAccessException("Изменение системных прав требует root.");
            if(getgrnam("pnt")==IntPtr.Zero)Run("/usr/sbin/groupadd","--system","pnt");
            Directory.CreateDirectory(App.Dir);
            Run("chown","root:pnt",App.Dir);
            Run("chmod","2770",App.Dir);
            Run("find",App.Dir,"-xdev","-type","d","-exec","chgrp","pnt","{}","+","-exec","chmod","2770","{}","+");
            Run("find",App.Dir,"-xdev","-type","f","-exec","chgrp","pnt","{}","+","-exec","chmod","g+rwX,o-rwx","{}","+");
            if(Directory.Exists(App.ConfigDir))
            {
                Run("chown","root:pnt",App.ConfigDir);Run("chmod","2750",App.ConfigDir);
                foreach(var file in new[]{"source-dir","invoker"})
                {
                    var path=Path.Combine(App.ConfigDir,file);
                    if(File.Exists(path)){Run("chown","root:pnt",path);Run("chmod","640",path);}
                }
            }
        }
        else if(OperatingSystem.IsWindows())PrepareWindows();
    }

    [SupportedOSPlatform("windows")]
    static void PrepareWindows()
    {
        using var identity=WindowsIdentity.GetCurrent();
        if(!identity.IsSystem&&!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Для настройки прав требуется запуск от имени администратора.");
        Directory.CreateDirectory(App.Dir);
        var path=App.Dir.Replace("'","''");
        var script="$ErrorActionPreference='Stop'; $g=Get-LocalGroup -Name PNTAdmin -ErrorAction SilentlyContinue; if(-not $g){$g=New-LocalGroup -Name PNTAdmin -Description 'PNT cluster administrators'}; "+
            "$sid='*'+$g.SID.Value+':(OI)(CI)M'; & icacls '"+path+"' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' $sid /T /C /L; exit $LASTEXITCODE";
        Run("powershell.exe","-NoProfile","-NonInteractive","-Command",script);
    }

    static void Run(string executable,params string[] arguments)
    {
        using var process=new Process{StartInfo=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}};
        foreach(var argument in arguments)process.StartInfo.ArgumentList.Add(argument);
        process.Start();var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        if(!process.WaitForExit(30000)){process.Kill(true);throw new IOException("Таймаут настройки прав PNT.");}
        if(process.ExitCode!=0)throw new IOException("Не удалось настроить права PNT: "+error.GetAwaiter().GetResult()+output.GetAwaiter().GetResult());
    }

    [SupportedOSPlatform("windows")]
    static void DemandWindows()
    {
        using var identity=WindowsIdentity.GetCurrent();
        var principal=new WindowsPrincipal(identity);
        if(identity.IsSystem || principal.IsInRole(WindowsBuiltInRole.Administrator))return;
        try
        {
            var group=(SecurityIdentifier)new NTAccount(Environment.MachineName,"PNTAdmin").Translate(typeof(SecurityIdentifier));
            if(principal.IsInRole(group))return;
        }
        catch(IdentityNotMappedException){}
        throw new UnauthorizedAccessException("Доступ запрещён: запустите PNT от имени администратора или добавьте пользователя в локальную группу PNTAdmin.");
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Group {public IntPtr Name,Password;public uint Gid;public IntPtr Members;}
    [DllImport("libc")]static extern uint geteuid();
    [DllImport("libc")]static extern uint getegid();
    [DllImport("libc")]static extern int getgroups(int size,[Out]uint[]? groups);
    [DllImport("libc",CharSet=CharSet.Ansi)]static extern IntPtr getgrnam(string name);
    [DllImport("libc")]static extern uint umask(uint mask);
}
