using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Pnt;

sealed class FtpGateway(Store db,X509Certificate2 certificate,int port=440,int passiveFirst=44100,int passiveLast=44131)
{
    public const int Port=440,PassiveFirst=44100,PassiveLast=44131;
    readonly SemaphoreSlim gate=new(1,1),sessions=new(16,16);
    readonly ConcurrentDictionary<TcpClient,Task> clients=new();
    readonly Dictionary<string,(int Count,long Until)> attempts=new();
    readonly HashSet<int> passivePorts=new();
    TcpListener? listener;
    CancellationTokenSource? stop;
    Task? accept;
    Task cleanup=Task.CompletedTask;
    string? settings;
    long cleaned;
    bool shuttingDown;
    internal int ListeningPort {get;private set;}
    internal bool Authenticate(string user,string password,IPAddress address)
    {
        var key=address.ToString();lock(attempts)
        {
            foreach(var expired in attempts.Where(x=>x.Value.Until<App.Now).Select(x=>x.Key).ToArray())attempts.Remove(expired);
            if(attempts.TryGetValue(key,out var current)&&current.Count>=5)return false;
            var hash=db.Get("key_hash");var valid=user=="admin"&&password.Length<=4096&&hash is {Length:64}&&hash.All(Uri.IsHexDigit)&&CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(password)),Convert.FromHexString(hash));
            if(valid){attempts.Remove(key);return true;}
            if(attempts.Count>=2048&&!attempts.ContainsKey(key))return false;
            attempts[key]=(current.Count+1,current.Until>App.Now?current.Until:App.Now+60000);return false;
        }
    }
    internal TcpListener Passive()
    {
        lock(passivePorts)for(var p=passiveFirst;p<=passiveLast;p++)
        {
            if(passivePorts.Contains(p))continue;
            var socket=new TcpListener(IPAddress.Any,p);
            try{socket.Start(4);passivePorts.Add(p);return socket;}catch(SocketException){socket.Stop();}
        }
        throw new IOException("Нет свободных пассивных портов.");
    }
    internal void Release(TcpListener? socket)
    {if(socket is null)return;lock(passivePorts){try{passivePorts.Remove(((IPEndPoint)socket.LocalEndpoint).Port);}catch{}socket.Stop();}}
    void Status(string text){db.Set("ftp_listener",text);db.Set("ftp_listener_time",DateTimeOffset.UtcNow.ToString("O"));}
    internal async Task Refresh()
    {
        await gate.WaitAsync();try
        {
            if(shuttingDown)return;
            var config=db.Ftp();var enabled=config?.Enabled==true&&FtpControl.Active(db);
            if(listener is not null&&(!enabled||settings!=config!.Id))await StopCore();
            if(enabled&&listener is null)
            {
                var socket=new TcpListener(IPAddress.Any,port);socket.Start();listener=socket;ListeningPort=((IPEndPoint)socket.LocalEndpoint).Port;
                stop=new();settings=config!.Id;Firewall.Open(ListeningPort);Firewall.OpenRange(passiveFirst,passiveLast);
                Status("listening TCP "+ListeningPort);Console.WriteLine("pnt: FTPS listening on TCP "+ListeningPort+", passive "+passiveFirst+"-"+passiveLast);
                accept=Accept(socket,settings,stop.Token);
            }
            if(App.Now-cleaned>60000&&cleanup.IsCompleted){cleaned=App.Now;cleanup=Task.Run(Clean);}
        }
        catch(Exception e){Status("error: "+e.Message);throw;}
        finally{gate.Release();}
    }
    async Task Clean(){try{await FileService.Cleanup(db,CancellationToken.None);}catch(Exception e){Console.Error.WriteLine("pnt: FTPS cleanup: "+e.Message);}}
    async Task Accept(TcpListener socket,string config,CancellationToken token)
    {
        try{while(!token.IsCancellationRequested)
        {
            var client=await socket.AcceptTcpClientAsync(token);
            if(!sessions.Wait(0)){client.Dispose();continue;}
            var work=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);clients[client]=work.Task;
            _=Task.Run(async()=>{try{await new FtpSession(this,db,certificate,client,config,token).Run();}catch(Exception e)when(e is IOException or SocketException or OperationCanceledException or System.Security.Authentication.AuthenticationException or ObjectDisposedException){}catch(Exception e){Console.Error.WriteLine("pnt: FTPS session: "+e.Message);}finally{client.Dispose();sessions.Release();clients.TryRemove(client,out _);work.TrySetResult();}});
        }}catch(OperationCanceledException){}catch(ObjectDisposedException){}catch(SocketException)when(token.IsCancellationRequested){}
    }
    internal async Task Stop(){await gate.WaitAsync();try{shuttingDown=true;await StopCore();}finally{gate.Release();}}
    async Task StopCore()
    {
        stop?.Cancel();listener?.Stop();if(accept is not null)await accept;
        var work=clients.Values.ToArray();foreach(var client in clients.Keys)client.Dispose();await Task.WhenAll(work);await cleanup;
        if(listener is not null){Firewall.Close(ListeningPort);Firewall.CloseRange(passiveFirst,passiveLast);Status("stopped");}
        listener=null;accept=null;settings=null;ListeningPort=0;stop?.Dispose();stop=null;
    }
}
