using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;

namespace Pnt;

[SupportedOSPlatform("windows")]
sealed class WindowsServiceHost(Store db,X509Certificate2 cert) : ServiceBase
{
    readonly Service service = new(db,cert);
    Task? running;
    StreamWriter? log;
    public static void Run(Store db,X509Certificate2 cert) => ServiceBase.Run(new WindowsServiceHost(db,cert){ServiceName="PNT",AutoLog=true,CanShutdown=true});
    protected override void OnStart(string[] args)
    {
        Directory.CreateDirectory(App.Dir);
        var logPath=Path.Combine(App.Dir,"service.log");
        if(File.Exists(logPath)&&new FileInfo(logPath).Length>10*1024*1024)File.Move(logPath,logPath+".previous",true);
        log=new StreamWriter(new FileStream(logPath,FileMode.Append,FileAccess.Write,FileShare.ReadWrite),new System.Text.UTF8Encoding(false)){AutoFlush=true};
        var writer=TextWriter.Synchronized(log);Console.SetOut(writer);Console.SetError(writer);
        running=Task.Run(service.Run);
        _=running.ContinueWith(t=>{if(t.IsFaulted){Console.Error.WriteLine(t.Exception?.GetBaseException());Environment.Exit(1);}},TaskScheduler.Default);
    }
    protected override void OnStop()
    {
        service.Stop();
        try{running?.Wait(TimeSpan.FromSeconds(15));}catch{}
        log?.Dispose();
    }
    protected override void OnShutdown()=>OnStop();
}
