using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Pnt;

static class WebChecks
{
    static void Assert(bool condition,string message){if(!condition)throw new Exception(message);}
    sealed class GeoHandler : HttpMessageHandler
    {
        public int Calls;
        public Func<Task>? Before;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Calls++;if(Before is not null)await Before();
            return new(HttpStatusCode.OK){Content=new StringContent("{\"success\":true,\"ip\":\"8.8.8.8\",\"latitude\":52.37,\"longitude\":4.89,\"city\":\"Amsterdam\",\"country\":\"Netherlands\"}")};
        }
    }
    sealed class TileHandler : HttpMessageHandler
    {
        public int Calls;
        public string Type="image/jpeg";
        public string? Requested;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Calls++;Requested=request.RequestUri!.ToString();
            var content=new ByteArrayContent([255,216,255,217]);content.Headers.ContentType=new MediaTypeHeaderValue(Type);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=content});
        }
    }
    public static async Task Main(string[] args)
    {
        var folder=Path.Combine(Path.GetTempPath(),"pnt-web-check-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
        Environment.SetEnvironmentVariable("PNT_DATA_DIR",folder);Environment.SetEnvironmentVariable("PNT_MANAGE_FIREWALL","0");
        using var cert=Certificate.Load(Path.Combine(folder,"node.pfx"));
        using var db=new Store(Path.Combine(folder,"pnt.db"));var self=Certificate.Id(cert);db.Set("self",self);db.Set("cluster","test");
        using(var tiles=new TileHandler())
        using(var tileHttp=new HttpClient(tiles))
        using(var imagery=new NasaImagery(tileHttp))
        {
            var image=await imagery.Get(2,1,2,default);
            Assert((await imagery.Get(2,1,2,default)).SequenceEqual(image)&&tiles.Calls==1,"NASA tile cache failed");
            Assert(tiles.Requested=="https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/BlueMarble_ShadedRelief_Bathymetry/default/GoogleMapsCompatible_Level8/2/1/2.jpeg","Wrong upstream tile coordinates");
            foreach(var (z,y,x) in new[]{(-1,0,0),(9,0,0),(0,1,0),(2,-1,0),(2,0,4)})
            {
                try{await imagery.Get(z,y,x,default);throw new Exception("Invalid tile requested");}catch(ArgumentOutOfRangeException){}
            }
            Assert(tiles.Calls==1,"Invalid tiles contacted upstream");
            tiles.Type="text/html";
            try{await imagery.Get(2,1,3,default);throw new Exception("Non-image tile accepted");}catch(IOException){}
            tiles.Type="image/jpeg";await imagery.Get(2,1,3,default);Assert(tiles.Calls==3,"Failed tile was cached");
            using var cancel=new CancellationTokenSource();cancel.Cancel();
            try{await imagery.Get(3,1,2,cancel.Token);throw new Exception("Tile cancellation ignored");}catch(OperationCanceledException){}
        }
        db.Put(new Node(self,"Amsterdam","8.8.8.8",Certificate.Fingerprint(cert),App.Now));
        using var handler=new GeoHandler();using var http=new HttpClient(handler);var geo=new GeoLocations(db,http);
        Assert(!GeoLocations.Public("192.168.1.1")&&!GeoLocations.Public("100.64.0.1")&&!GeoLocations.Public("::1")&&GeoLocations.Public("8.8.8.8"),"Private IP classification failed");
        await geo.Refresh(default);Assert(handler.Calls==1&&db.Self()!.Location?.Latitude==52.37,"Automatic geo lookup failed");
        await geo.Refresh(default);Assert(handler.Calls==1,"Geolocation was not cached");
        db.Put(db.Self()! with{Location=new(10,20,true),Version=App.Now+1});
        await geo.Refresh(default);Assert(handler.Calls==1&&geo.Get(db.Self()!)?.Latitude==10,"Manual location overwritten");
        db.Set("geo:8.8.8.8","null");db.Put(db.Self()! with{Location=null,Version=App.Now+2});
        handler.Before=()=>{db.Put(db.Self()! with{Location=new(52.37,4.89,true),Version=App.Now+3});return Task.CompletedTask;};
        await geo.Refresh(default);Assert(db.Self()!.Location?.Manual==true,"In-flight lookup overwrote manual location");
        db.Put(new Node("bbbbbbbbbbbbbbbb","Frankfurt","1.1.1.1","test",App.Now,Location:new(50.11,8.68,true)));
        db.Put(new Node("cccccccccccccccc","London","9.9.9.9","test",App.Now,Location:new(51.51,-.13,true)));
        db.Put(new Node("dddddddddddddddd","NAT node","192.168.31.72","test",App.Now,BehindNat:true));
        using(var replica=new Store(Path.Combine(folder,"replica.db")))
        {
            var merge=typeof(Service).GetMethod("Merge",BindingFlags.NonPublic|BindingFlags.Instance)!;
            var replicaService=new Service(replica,cert);
            merge.Invoke(replicaService,[new Message("sync",Nodes:db.Nodes().ToArray())]);
            Assert(replica.Resolve(self)?.Location is {Manual:true,Latitude:52.37},"Membership synchronization lost manual location");
            var known=replica.Resolve(self)!;
            merge.Invoke(replicaService,[new Message("sync",Nodes:[known with{Location=new(999,0,true),Version=known.Version+1}])]);
            Assert(replica.Resolve(self)?.Location?.Latitude==52.37,"Invalid replicated location accepted");
        }
        db.PutLink(new(self,"bbbbbbbbbbbbbbbb",22.5,App.Now,true));db.PutLink(new("bbbbbbbbbbbbbbbb","cccccccccccccccc",18.1,App.Now,true));
        var salt=RandomNumberGenerator.GetBytes(32);var hash=Rfc2898DeriveBytes.Pbkdf2("web-test-password",salt,210_000,HashAlgorithmName.SHA256,32);
        db.PutWeb(new(Guid.NewGuid().ToString("N"),true,Convert.ToHexString(salt),Convert.ToHexString(hash),App.Now));
        var panel=new WebPanel(db,cert,0);await panel.Refresh();
        using var client=new HttpClient(new HttpClientHandler{ServerCertificateCustomValidationCallback=(_,_,_,_)=>true}){BaseAddress=new Uri("https://127.0.0.1:"+panel.ListeningPort)};
        try
        {
            Assert((await client.GetAsync("/api/state")).StatusCode==HttpStatusCode.Unauthorized,"Web authentication bypassed");
            Assert((await client.GetAsync("/api/imagery/nasa/0/0/0.jpg")).StatusCode==HttpStatusCode.Unauthorized,"Tile proxy bypassed authentication");
            client.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Basic",Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:web-test-password")));
            var state=await client.GetFromJsonAsync<JsonElement>("/api/state");var csrf=state.GetProperty("csrfToken").GetString()!;
            Assert(state.GetProperty("nodes")[0].TryGetProperty("location",out _),"State omitted locations");
            Assert((await client.GetAsync("/assets/cesium/Cesium.js")).Content.Headers.ContentType?.MediaType=="text/javascript","Cesium asset unavailable");
            Assert((await client.GetAsync("/assets/cesium/Assets/Textures/NaturalEarthII/tilemapresource.xml")).IsSuccessStatusCode,"Offline base map missing");
            var geography=await client.GetFromJsonAsync<JsonElement>("/assets/geography.json");
            Assert(geography.GetProperty("countries").GetArrayLength()>=200&&geography.GetProperty("cities").GetArrayLength()>=500,"Bundled country/city overlay missing");
            Assert(geography.GetProperty("countries").EnumerateArray().Any(c=>c.GetProperty("name").GetString()=="Россия"),"Russian country labels missing");
            Assert((await client.GetAsync("/api/imagery/nasa/9/0/0.jpg")).StatusCode==HttpStatusCode.BadRequest,"Tile endpoint did not validate coordinates");
            var endpoint="/api/nodes/bbbbbbbbbbbbbbbb/location";
            Assert((await client.PutAsJsonAsync(endpoint,new{latitude=90,longitude=180})).StatusCode==HttpStatusCode.Forbidden,"Location CSRF bypassed");
            client.DefaultRequestHeaders.Add("X-PNT-CSRF",csrf);
            Assert((await client.PutAsJsonAsync(endpoint,new{latitude=91,longitude=0})).StatusCode==HttpStatusCode.BadRequest,"Invalid coordinate accepted");
            Assert((await client.PutAsJsonAsync(endpoint,new{latitude=50.2,longitude=8.7})).IsSuccessStatusCode,"Manual location failed");
            using(var reopened=new Store(Path.Combine(folder,"pnt.db")))Assert(reopened.Resolve("bbbbbbbbbbbbbbbb")?.Location is {Manual:true,Latitude:50.2},"Manual location not persisted");
            Assert((await client.PutAsJsonAsync(endpoint,new{automatic=true})).IsSuccessStatusCode&&db.Resolve("bbbbbbbbbbbbbbbb")!.Location is null,"Auto location reset failed");
            db.Put(db.Resolve("bbbbbbbbbbbbbbbb")! with{Location=new(50.11,8.68,true),Version=App.Now+10});
            using var events=await client.GetAsync("/api/events",HttpCompletionOption.ResponseHeadersRead);
            using var reader=new StreamReader(await events.Content.ReadAsStreamAsync());
            Assert((await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)))!.StartsWith("data: "),"SSE initial state missing");
            db.PutLink(new(self,"bbbbbbbbbbbbbbbb",11.2,App.Now+1,true));
            await reader.ReadLineAsync();var update=await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
            Assert(update!.Contains("11.2"),"SSE did not deliver live ping");
            await reader.ReadLineAsync();
            var access=db.Web()!;db.PutWeb(access with{Id=Guid.NewGuid().ToString("N"),Version=access.Version+1});
            Assert(await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)) is null,"SSE retained access after web credential configuration changed");
            if(args.Contains("--serve"))
            {
                Console.WriteLine("BROWSER_URL=https://127.0.0.1:"+panel.ListeningPort);
                for(var i=0;i<180;i++)
                {
                    db.PutLink(new(self,"bbbbbbbbbbbbbbbb",11.2,App.Now,true));
                    db.PutLink(new("bbbbbbbbbbbbbbbb","cccccccccccccccc",18.1,App.Now,true));
                    await Task.Delay(5000);
                }
            }
            Console.WriteLine("PASS: geolocation cache, manual precedence and persistence, in-flight override, web auth/CSRF, coordinates, local Cesium/map assets, SSE live ping.");
        }
        finally{await panel.Stop();}
    }
}
