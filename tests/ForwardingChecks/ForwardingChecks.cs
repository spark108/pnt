using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Pnt;

static class ForwardingChecks
{
    static void Assert(bool ok,string message){if(!ok)throw new Exception(message);}
    public static async Task Main()
    {
        var directory=Path.Combine(Path.GetTempPath(),"pnt-web-forward-check-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);Environment.SetEnvironmentVariable("PNT_DATA_DIR",directory);
        Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");
        Environment.SetEnvironmentVariable("Logging__LogLevel__Default","Warning");
        using var cert=Certificate.Load(Path.Combine(directory,"node.pfx"));
        using var db=new Store(Path.Combine(directory,"pnt.db"));var self=Certificate.Id(cert);
        db.Set("self",self);db.Set("cluster","test");db.Put(new Node(self,"local","127.0.0.1",Certificate.Fingerprint(cert),App.Now));
        var salt=RandomNumberGenerator.GetBytes(32);
        db.PutWeb(new WebConfig(Guid.NewGuid().ToString("N"),true,Convert.ToHexString(salt),
            Convert.ToHexString(Rfc2898DeriveBytes.Pbkdf2("test-password",salt,210_000,HashAlgorithmName.SHA256,32)),App.Now));
        var service=new Service(db,cert);var serviceWork=service.Run();
        using var handler=new HttpClientHandler{ServerCertificateCustomValidationCallback=HttpClientHandler.DangerousAcceptAnyServerCertificateValidator};
        using var http=new HttpClient(handler){BaseAddress=new Uri("https://127.0.0.1:8016")};
        var echo=new TcpListener(IPAddress.Loopback,0);echo.Start();
        try
        {
            for(var i=0;i<30;i++){try{using var test=await http.GetAsync("/api/state");break;}catch(HttpRequestException){await Task.Delay(100);}}
            Assert((await http.GetAsync("/api/state")).StatusCode==HttpStatusCode.Unauthorized,"API is not protected");
            http.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Basic",Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:test-password")));
            using var state=JsonDocument.Parse(await http.GetStringAsync("/api/state"));
            var csrf=state.RootElement.GetProperty("csrfToken").GetString()!;
            var inventory=await http.GetFromJsonAsync<NodeInterface[]>("/api/nodes/"+self+"/interfaces");
            var loopback=inventory!.First(i=>i.Address=="127.0.0.1");
            var reservation=new TcpListener(IPAddress.Loopback,0);reservation.Start();var port=((IPEndPoint)reservation.LocalEndpoint).Port;reservation.Stop();
            var input=new CreateForward(self,port,loopback.Address,loopback.Name,self,loopback.Address,loopback.Name,"127.0.0.1",((IPEndPoint)echo.LocalEndpoint).Port);
            Assert((await http.PostAsJsonAsync("/api/forwards",input,App.Json)).StatusCode==HttpStatusCode.Forbidden,"CSRF token not checked");
            http.DefaultRequestHeaders.Add("X-PNT-CSRF",csrf);http.DefaultRequestHeaders.Add("Origin","https://other.example");
            Assert((await http.PostAsJsonAsync("/api/forwards",input,App.Json)).StatusCode==HttpStatusCode.Forbidden,"Foreign origin accepted");
            http.DefaultRequestHeaders.Remove("Origin");http.DefaultRequestHeaders.Add("Origin","https://127.0.0.1:8016");
            Assert((await http.PostAsJsonAsync("/api/forwards",input with{InInterface="does-not-exist"},App.Json)).StatusCode==HttpStatusCode.BadRequest,"Invalid interface accepted");
            Assert((await http.PostAsJsonAsync("/api/forwards",input with{InPort=8016},App.Json)).StatusCode==HttpStatusCode.BadRequest,"Reserved port accepted");
            using var created=await http.PostAsJsonAsync("/api/forwards",input,App.Json);
            Assert(created.StatusCode==HttpStatusCode.Created,"Create failed: "+await created.Content.ReadAsStringAsync());
            var rule=await created.Content.ReadFromJsonAsync<Rule>(App.Json);Assert(rule!.InAddress=="127.0.0.1"&&rule.OutInterface==loopback.Name,"Selections were lost");
            Assert((await http.PostAsJsonAsync("/api/forwards",input,App.Json)).StatusCode==HttpStatusCode.BadRequest,"Duplicate listener accepted");
            using var client=new TcpClient();
            for(var i=0;;i++){try{await client.ConnectAsync(IPAddress.Loopback,port);break;}catch(SocketException)when(i<15){await Task.Delay(500);}}
            using var destination=await echo.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
            Assert(((IPEndPoint)destination.Client.RemoteEndPoint!).Address.Equals(IPAddress.Loopback),"Wrong exit source address");
            await client.GetStream().WriteAsync(Encoding.UTF8.GetBytes("forward-ok"));var payload=new byte[10];
            await destination.GetStream().ReadExactlyAsync(payload).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
            Assert(Encoding.UTF8.GetString(payload)=="forward-ok","Forwarding corrupted data");
            using(var other=new TcpClient())
            {
                var connected=false;try{await other.ConnectAsync(IPAddress.Parse("127.0.0.2"),port);connected=true;}catch(SocketException){}
                Assert(!connected,"Listener exposed on another address");
            }
            Assert((await http.DeleteAsync("/api/forwards/"+rule.Id)).IsSuccessStatusCode,"Delete failed");
            await Task.Delay(6000);
            using(var removed=new TcpClient())
            {
                var connected=false;try{await removed.ConnectAsync(IPAddress.Loopback,port);connected=true;}catch(SocketException){}
                Assert(!connected,"Deleted listener still accepts connections");
            }
            Assert(db.Rules().Single(r=>r.Id==rule.Id).Removed,"Removal not persisted");
            Console.WriteLine("PASS: Basic auth, CSRF, interface inventory, validation, create/delete, ingress binding, exit source binding, real TCP traffic");
        }
        finally
        {
            echo.Stop();
            ((CancellationTokenSource)typeof(Service).GetField("stop",BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(service)!).Cancel();
            await serviceWork;
        }
    }
}
