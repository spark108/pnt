using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Pnt;

record VpnServerConfiguration(string Id,string Kind,string Interface,string Config,bool Active,bool Supported,string Reason,string Address,int Port,string? Container,bool Selected=false);

static class VpnServerInstaller
{
    static string Source()
    {
        var assembly=typeof(VpnServerInstaller).Assembly;
        using var stream=assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n=>n.EndsWith(".deploy.vpn_server.py")))!;
        using var reader=new StreamReader(stream);return reader.ReadToEnd();
    }
    static Process Process(string source,bool capture)
    {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("Установка сервера AmneziaWG поддерживается только на Debian Linux.");
        var process=new Process{StartInfo=new ProcessStartInfo("python3"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=capture,RedirectStandardError=capture}};
        process.StartInfo.ArgumentList.Add("-u");process.StartInfo.ArgumentList.Add("-c");process.StartInfo.ArgumentList.Add(source);
        process.StartInfo.Environment["PNT_VPN_DATA"]=Path.Combine(App.Dir,"vpn");
        return process;
    }
    public static async Task<string> Inventory(CancellationToken token)
    {
        using var process=Process(Source(),true);process.Start();
        var output=process.StandardOutput.ReadToEndAsync(token);var error=process.StandardError.ReadToEndAsync(token);
        await process.StandardInput.WriteLineAsync("{\"action\":\"inventory\"}");process.StandardInput.Close();
        try{await process.WaitForExitAsync(token);}catch{process.Kill(true);throw;}
        if(process.ExitCode!=0)throw new IOException((await error).Trim());
        return (await output).Trim();
    }
    public static async Task<int> Setup(string selection)
    {
        LocalAccess.DemandAdministrator();
        if(selection!="new"&&!Regex.IsMatch(selection,"^[0-9a-f]{24}$"))throw new ArgumentException("Неверный ID конфигурации AmneziaWG.");
        var source=Source();using var process=Process(source,false);process.Start();
        await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new{action="install",selection,source},App.Json));process.StandardInput.Close();
        using var timeout=new CancellationTokenSource(TimeSpan.FromMinutes(30));
        try{await process.WaitForExitAsync(timeout.Token);}catch{process.Kill(true);throw new IOException("Истекло время установки AmneziaWG.");}
        return process.ExitCode;
    }
    public static string Choose(VpnServerConfiguration[] configurations,TextReader input,TextWriter output)
    {
        if(configurations.Length==0){output.WriteLine("Конфигураций AmneziaWG нет. Будет создана новая серверная конфигурация.");return "new";}
        output.WriteLine("Найденные конфигурации AmneziaWG:");
        for(var i=0;i<configurations.Length;i++)
        {
            var item=configurations[i];output.WriteLine($"{i+1}. {item.Interface}  {item.Kind}  {item.Container??item.Config}  {item.Address}  UDP {item.Port}  "+(item.Active?"запущен":"остановлен")+(item.Selected?"  [PNT]":"")+(item.Supported?"":"  [недоступен: "+item.Reason+"]"));
        }
        output.WriteLine("0. Создать новую конфигурацию и прикрепить её");
        var current=Array.FindIndex(configurations,c=>c.Selected&&c.Supported);
        while(true)
        {
            output.Write("Выберите номер"+(current>=0?$" [{current+1}]":"")+" или q для отмены: ");output.Flush();
            var answer=input.ReadLine()?.Trim()??throw new IOException("Выбор не получен. Установка не начата.");
            if(answer.Equals("q",StringComparison.OrdinalIgnoreCase))throw new OperationCanceledException("Установка отменена.");
            if(answer.Length==0&&current>=0)return configurations[current].Id;
            if(int.TryParse(answer,out var selected))
            {
                if(selected==0)return "new";
                if(selected>0&&selected<=configurations.Length&&configurations[selected-1].Supported)return configurations[selected-1].Id;
            }
            output.WriteLine("Укажите номер доступной серверной конфигурации или 0.");
        }
    }
}
