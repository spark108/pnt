using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Pnt;

abstract class ShellSession:IDisposable
{
    internal abstract StreamReader Output {get;}
    internal abstract StreamReader? Error {get;}
    internal abstract StreamWriter? Input {get;}
    internal abstract int ExitCode {get;}
    internal abstract bool HasExited {get;}
    internal abstract Task WaitForExit();
    internal abstract void Kill();
    internal virtual void Resize(int width,int height){}
    public abstract void Dispose();
    internal static ShellSession Start(string command,bool interactive,string directory,int width,int height)
    {
        width=Math.Clamp(width>0?width:80,20,500);height=Math.Clamp(height>0?height:24,5,200);
        if(interactive&&OperatingSystem.IsWindows())return new WindowsTerminal(command,directory,width,height);
        var process=new Process{StartInfo=ShellProcess.Create(command,interactive,directory,width,height)};
        try{process.Start();return new PipedShell(process,interactive);}catch{process.Dispose();throw;}
    }
}

sealed class PipedShell(Process process,bool interactive):ShellSession
{
    internal override StreamReader Output=>process.StandardOutput;
    internal override StreamReader Error=>process.StandardError;
    internal override StreamWriter? Input=>interactive?process.StandardInput:null;
    internal override int ExitCode=>process.ExitCode;
    internal override bool HasExited=>process.HasExited;
    internal override Task WaitForExit()=>process.WaitForExitAsync();
    internal override void Kill(){if(!process.HasExited)process.Kill(true);}
    internal override void Resize(int width,int height)
    {
        if(!interactive||!OperatingSystem.IsLinux()||process.HasExited)return;
        try
        {
            var children=File.ReadAllText($"/proc/{process.Id}/task/{process.Id}/children").Split(' ',StringSplitOptions.RemoveEmptyEntries);
            foreach(var child in children)
            {
                if(!int.TryParse(child,out _))continue;
                var path=File.ResolveLinkTarget($"/proc/{child}/fd/0",false)?.FullName;
                if(path is null||!System.Text.RegularExpressions.Regex.IsMatch(path,@"^/dev/pts/\d+$"))continue;
                var fd=Open(path,1|0x100|0x80000);if(fd<0)continue;
                using var handle=new SafeFileHandle((IntPtr)fd,true);
                var size=new WindowSize{Rows=(ushort)Math.Clamp(height,5,200),Columns=(ushort)Math.Clamp(width,20,500)};
                Ioctl(handle,0x5414,ref size);return;
            }
        }
        catch(IOException){}catch(UnauthorizedAccessException){}
    }
    public override void Dispose(){Kill();process.Dispose();}
    [StructLayout(LayoutKind.Sequential)]struct WindowSize{internal ushort Rows,Columns,X,Y;}
    [DllImport("libc",EntryPoint="open",SetLastError=true)]static extern int Open(string path,int flags);
    [DllImport("libc",EntryPoint="ioctl",SetLastError=true)]static extern int Ioctl(SafeFileHandle fd,uint request,ref WindowSize size);
}
