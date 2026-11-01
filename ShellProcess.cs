using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;

namespace Pnt;

static class ShellProcess
{
    internal static ProcessStartInfo Create(string command,bool interactive,string directory,int width=80,int height=24)
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
            info.ArgumentList.Add("-c");
            info.ArgumentList.Add(interactive?$"stty cols {Math.Clamp(width,20,500)} rows {Math.Clamp(height,5,200)}; "+command:command);
            if(interactive)
            {
                info.Environment["TERM"]="xterm-256color";info.Environment["COLORTERM"]="truecolor";
                info.Environment["HISTFILE"]="/dev/null";
                info.Environment["COLUMNS"]=Math.Clamp(width,20,500).ToString();info.Environment["LINES"]=Math.Clamp(height,5,200).ToString();
            }
            if(interactive)info.ArgumentList.Add("/dev/null");
        }
        return info;
    }
    [DllImport("kernel32.dll")]
    static extern uint GetOEMCP();
}
