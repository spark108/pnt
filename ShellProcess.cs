using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;

namespace Pnt;

static class ShellProcess
{
    internal static ProcessStartInfo Create(string command,bool interactive,string directory)
    {
        var windows=OperatingSystem.IsWindows();
        var info=new ProcessStartInfo(windows?"cmd.exe":interactive?"/usr/bin/script":"/bin/sh")
        {
            UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,
            RedirectStandardInput=interactive,WorkingDirectory=directory
        };
        if(windows)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var codePage=(int)GetOEMCP();
            var encoding=Encoding.GetEncoding(codePage);
            info.StandardOutputEncoding=encoding;
            info.StandardErrorEncoding=encoding;
            if(interactive)info.StandardInputEncoding=encoding;
            info.WindowStyle=ProcessWindowStyle.Hidden;
            info.Arguments=$"/d /s /c \"chcp {codePage}>nul & "+command+"\"";
        }
        else
        {
            if(interactive)info.ArgumentList.Add("-qef");
            info.ArgumentList.Add("-c");info.ArgumentList.Add(command);
            if(interactive)info.ArgumentList.Add("/dev/null");
        }
        return info;
    }
    [DllImport("kernel32.dll")]
    static extern uint GetOEMCP();
}
