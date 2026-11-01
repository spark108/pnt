using System.Runtime.InteropServices;

namespace Pnt;

static class TerminalKeyboard
{
    internal static string Encode(ConsoleKeyInfo key)
    {
        var modifiers=1+(key.Modifiers.HasFlag(ConsoleModifiers.Shift)?1:0)+(key.Modifiers.HasFlag(ConsoleModifiers.Alt)?2:0)+(key.Modifiers.HasFlag(ConsoleModifiers.Control)?4:0);
        var cursor=key.Key switch{ConsoleKey.UpArrow=>"A",ConsoleKey.DownArrow=>"B",ConsoleKey.RightArrow=>"C",ConsoleKey.LeftArrow=>"D",ConsoleKey.Home=>"H",ConsoleKey.End=>"F",_=>null};
        if(cursor is not null)return modifiers==1?"\u001b["+cursor:"\u001b[1;"+modifiers+cursor;
        var number=key.Key switch{ConsoleKey.Insert=>2,ConsoleKey.Delete=>3,ConsoleKey.PageUp=>5,ConsoleKey.PageDown=>6,ConsoleKey.F5=>15,ConsoleKey.F6=>17,ConsoleKey.F7=>18,ConsoleKey.F8=>19,ConsoleKey.F9=>20,ConsoleKey.F10=>21,ConsoleKey.F11=>23,ConsoleKey.F12=>24,_=>0};
        if(number!=0)return "\u001b["+number+(modifiers==1?"":";"+modifiers)+"~";
        if(key.Key is >=ConsoleKey.F1 and <=ConsoleKey.F4)return modifiers==1?"\u001bO"+(char)('P'+(int)key.Key-(int)ConsoleKey.F1):"\u001b[1;"+modifiers+(char)('P'+(int)key.Key-(int)ConsoleKey.F1);
        if(key.Key==ConsoleKey.Tab&&key.Modifiers==ConsoleModifiers.Shift)return "\u001b[Z";
        var value=key.Key switch
        {
            ConsoleKey.Enter=>"\r",ConsoleKey.Backspace=>key.Modifiers.HasFlag(ConsoleModifiers.Control)?"\u0017":"\u007f",
            ConsoleKey.Escape=>"\u001b",ConsoleKey.Tab=>"\t",
            >=ConsoleKey.A and <=ConsoleKey.Z when key.Modifiers.HasFlag(ConsoleModifiers.Control)=>((char)(key.Key-ConsoleKey.A+1)).ToString(),
            ConsoleKey.Spacebar when key.Modifiers.HasFlag(ConsoleModifiers.Control)=>"\0",
            _=>key.KeyChar=='\0'?"":key.KeyChar.ToString()
        };
        return key.Modifiers.HasFlag(ConsoleModifiers.Alt)&&key.Key!=ConsoleKey.Escape?"\u001b"+value:value;
    }
    internal static (int Width,int Height) Size()
    {
        try{return (Math.Clamp(Console.WindowWidth,20,500),Math.Clamp(Console.WindowHeight,5,200));}catch{return (80,24);}
    }
}

sealed class InteractiveTerminal:IDisposable
{
    readonly bool previousControlC;
    readonly List<(IntPtr Handle,uint Mode)> modes=[];
    internal InteractiveTerminal()
    {
        if(Console.IsInputRedirected||Console.IsOutputRedirected)throw new IOException("Интерактивной оболочке нужен терминал без перенаправления ввода/вывода.");
        previousControlC=Console.TreatControlCAsInput;Console.TreatControlCAsInput=true;
        if(OperatingSystem.IsWindows())foreach(var channel in new[]{-11,-12})
        {
            var handle=GetStdHandle(channel);
            if(GetConsoleMode(handle,out var mode)&&SetConsoleMode(handle,mode|4))modes.Add((handle,mode));
        }
    }
    public void Dispose()
    {
        try{Console.Out.Write("\u001b[0m\u001b[?25h\u001b[?2004l\u001b[?9001l\u001b[?1004l\u001b[?1049l");Console.Out.Flush();}
        finally
        {
            foreach(var item in modes)SetConsoleMode(item.Handle,item.Mode);
            Console.TreatControlCAsInput=previousControlC;
        }
    }
    [DllImport("kernel32.dll")]static extern IntPtr GetStdHandle(int channel);
    [DllImport("kernel32.dll")]static extern bool GetConsoleMode(IntPtr handle,out uint mode);
    [DllImport("kernel32.dll")]static extern bool SetConsoleMode(IntPtr handle,uint mode);
}
