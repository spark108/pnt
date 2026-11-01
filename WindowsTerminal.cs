using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Pnt;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
sealed class WindowsTerminal:ShellSession
{
    IntPtr console;
    Process process=null!;
    StreamReader output=null!;
    StreamWriter input=null!;
    internal WindowsTerminal(string command,string directory,int width,int height)
    {
        SafeFileHandle? readInput=null,writeInput=null,readOutput=null,writeOutput=null;
        IntPtr attributes=IntPtr.Zero;var attributesReady=false;ProcessInfo created=default;
        try
        {
            Check(CreatePipe(out readInput,out writeInput,IntPtr.Zero,0));
            Check(CreatePipe(out readOutput,out writeOutput,IntPtr.Zero,0));
            var hr=CreatePseudoConsole(new Coord((short)width,(short)height),readInput,writeOutput,0,out console);
            if(hr<0)Marshal.ThrowExceptionForHR(hr);
            IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);
            attributes=Marshal.AllocHGlobal(size);
            Check(InitializeProcThreadAttributeList(attributes,1,0,ref size));attributesReady=true;
            Check(UpdateProcThreadAttribute(attributes,0,(IntPtr)0x00020016,console,(IntPtr)IntPtr.Size,IntPtr.Zero,IntPtr.Zero));
            // Null standard handles prevent redirected service I/O from being inherited by the PTY.
            var startup=new StartupInfoEx{Info=new StartupInfo{Size=Marshal.SizeOf<StartupInfoEx>(),Flags=0x100},Attributes=attributes};
            var executable=Path.Combine(Environment.SystemDirectory,"cmd.exe");
            var arguments=new StringBuilder("\""+executable+"\" /d /s /c \"chcp 65001>nul & "+command+"\"");
            Check(CreateProcess(executable,arguments,IntPtr.Zero,IntPtr.Zero,false,0x00080000|0x00000400|0x00000004,IntPtr.Zero,directory,ref startup,out created));
            process=Process.GetProcessById((int)created.Id);_=process.Handle;
            readInput.Dispose();readInput=null;writeOutput.Dispose();writeOutput=null;
            input=new StreamWriter(new FileStream(writeInput,FileAccess.Write),new UTF8Encoding(false)){AutoFlush=true};writeInput=null;
            output=new StreamReader(new FileStream(readOutput,FileAccess.Read),new UTF8Encoding(false),false);readOutput=null;
            if(ResumeThread(created.Thread)==uint.MaxValue)throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        catch{Dispose();throw;}
        finally
        {
            readInput?.Dispose();writeInput?.Dispose();readOutput?.Dispose();writeOutput?.Dispose();
            if(created.Thread!=IntPtr.Zero)CloseHandle(created.Thread);if(created.Process!=IntPtr.Zero)CloseHandle(created.Process);
            if(attributes!=IntPtr.Zero){if(attributesReady)DeleteProcThreadAttributeList(attributes);Marshal.FreeHGlobal(attributes);}
        }
    }
    internal override StreamReader Output=>output;
    internal override StreamReader? Error=>null;
    internal override StreamWriter Input=>input;
    internal override int ExitCode=>process.ExitCode;
    internal override bool HasExited=>process.HasExited;
    internal override async Task WaitForExit(){await process.WaitForExitAsync();CloseConsole();}
    internal override void Kill()
    {
        if(process is null||process.HasExited)return;
        process.Kill(true);
        try{input?.Dispose();}catch(IOException){}
        output?.Dispose();
    }
    internal override void Resize(int width,int height)
    {
        var handle=console;
        if(handle!=IntPtr.Zero)ResizePseudoConsole(handle,new Coord((short)Math.Clamp(width,20,500),(short)Math.Clamp(height,5,200)));
    }
    void CloseConsole(){var handle=Interlocked.Exchange(ref console,IntPtr.Zero);if(handle!=IntPtr.Zero)ClosePseudoConsole(handle);}
    public override void Dispose()
    {
        Kill();input?.Dispose();output?.Dispose();CloseConsole();process?.Dispose();
    }
    static void Check(bool success){if(!success)throw new Win32Exception(Marshal.GetLastWin32Error());}
    [StructLayout(LayoutKind.Sequential)]readonly struct Coord(short x,short y){readonly short X=x,Y=y;}
    [StructLayout(LayoutKind.Sequential)]struct StartupInfo
    {
        internal int Size;internal IntPtr Reserved,Desktop,Title;
        internal int X,Y,XSize,YSize,XCount,YCount,Fill,Flags;
        internal short Show,ReservedSize;internal IntPtr Reserved2,Input,Output,Error;
    }
    [StructLayout(LayoutKind.Sequential)]struct StartupInfoEx{internal StartupInfo Info;internal IntPtr Attributes;}
    [StructLayout(LayoutKind.Sequential)]struct ProcessInfo{internal IntPtr Process,Thread;internal uint Id,ThreadId;}
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool CreatePipe(out SafeFileHandle read,out SafeFileHandle write,IntPtr security,uint size);
    [DllImport("kernel32.dll")]static extern int CreatePseudoConsole(Coord size,SafeFileHandle input,SafeFileHandle output,uint flags,out IntPtr console);
    [DllImport("kernel32.dll")]static extern int ResizePseudoConsole(IntPtr console,Coord size);
    [DllImport("kernel32.dll")]static extern void ClosePseudoConsole(IntPtr console);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr resultSize);
    [DllImport("kernel32.dll")]static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateProcess(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref StartupInfoEx startup,out ProcessInfo process);
    [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)]static extern uint ResumeThread(IntPtr thread);
}
