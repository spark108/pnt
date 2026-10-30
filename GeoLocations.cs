using System.Net;
using System.Text.Json;

namespace Pnt;

record NodeLocation(double Latitude,double Longitude,bool Manual=false,string? City=null,string? Country=null,string? Ip=null,long Updated=0);
record SetNodeLocation(double? Latitude,double? Longitude,bool Automatic=false);
record GeoCache(NodeLocation? Location,long RetryAfter);

sealed class GeoLocations(Store db,HttpClient? client=null)
{
    static readonly HttpClient http=new(){Timeout=TimeSpan.FromSeconds(8)};
    readonly HttpClient lookup=client??http;
    const long Week=7*24*3600_000L;
    internal static bool Valid(NodeLocation value)=>double.IsFinite(value.Latitude)&&double.IsFinite(value.Longitude)
        &&value.Latitude is >=-90 and <=90&&value.Longitude is >=-180 and <=180
        &&(value.City?.Length??0)<=128&&(value.Country?.Length??0)<=128&&(value.Ip?.Length??0)<=64;

    public NodeLocation? Get(Node node)
    {
        if(node.Location is {} location&&Valid(location))return location;
        var cached=Cached(node.Ip)?.Location;
        if(cached is null&&node.Id==db.Get("self")&&!Public(node.Ip))cached=Cached("self")?.Location;
        return cached is not null&&Valid(cached)?cached:null;
    }
    GeoCache? Cached(string ip)
    {
        try{return JsonSerializer.Deserialize<GeoCache>(db.Get("geo:"+ip)??"null",App.Json);}
        catch(JsonException){return null;}
    }
    internal static bool Public(string ip)
    {
        if(!IPAddress.TryParse(ip,out var address))return false;
        if(address.IsIPv4MappedToIPv6)address=address.MapToIPv4();
        if(IPAddress.IsLoopback(address)||address.Equals(IPAddress.Any)||address.Equals(IPAddress.IPv6Any))return false;
        var b=address.GetAddressBytes();
        if(b.Length==16)return (b[0]&0xe0)==0x20;
        return b[0] is not (0 or 10 or 127)&&b[0]<224&&!(b[0]==172&&b[1] is >=16 and <=31)
            &&!(b[0]==192&&b[1]==168)&&!(b[0]==169&&b[1]==254)&&!(b[0]==100&&b[1] is >=64 and <=127);
    }
    internal async Task<NodeLocation?> Lookup(string ip,CancellationToken token)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(8));token=timeout.Token;
        using var response=await lookup.GetAsync("https://ipwho.is/"+Uri.EscapeDataString(ip),HttpCompletionOption.ResponseHeadersRead,token);
        response.EnsureSuccessStatusCode();
        await using var stream=await response.Content.ReadAsStreamAsync(token);
        using var json=await JsonDocument.ParseAsync(stream,cancellationToken:token);
        var root=json.RootElement;
        if(!root.TryGetProperty("success",out var success)||success.ValueKind!=JsonValueKind.True)return null;
        string? Text(string name)=>root.TryGetProperty(name,out var value)&&value.ValueKind==JsonValueKind.String?value.GetString():null;
        if(!root.TryGetProperty("latitude",out var lat)||!lat.TryGetDouble(out var latitude)
            ||!root.TryGetProperty("longitude",out var lon)||!lon.TryGetDouble(out var longitude))return null;
        var result=new NodeLocation(latitude,longitude,City:Text("city"),Country:Text("country"),Ip:Text("ip"),Updated:App.Now);
        return Valid(result)?result:null;
    }
    public async Task Refresh(CancellationToken token)
    {
        foreach(var snapshot in db.Nodes().Where(n=>!n.Removed))
        {
            if(token.IsCancellationRequested)return;
            if(snapshot.Location is {Manual:true})continue;
            var own=snapshot.Id==db.Get("self");
            if(!Public(snapshot.Ip)&&!own)continue;
            if(snapshot.Location is {} current&&App.Now-current.Updated<Week&&(current.Ip==snapshot.Ip||!Public(snapshot.Ip)))continue;
            var key=Public(snapshot.Ip)?snapshot.Ip:"self";
            var cache=Cached(key);
            if(cache is not null&&App.Now<cache.RetryAfter)
            {
                if(own&&snapshot.Location is null&&cache.Location is {} cached&&db.Resolve(snapshot.Id) is Node latest&&latest.Location is null)
                    db.Put(latest with{Location=cached,Version=Math.Max(App.Now,latest.Version+1)});
                continue;
            }
            try
            {
                var location=await Lookup(key=="self"?"":key,token);
                db.Set("geo:"+key,JsonSerializer.Serialize(new GeoCache(location??cache?.Location,App.Now+(location is null?3600_000:Week)),App.Json));
                if(own&&location is not null&&db.Resolve(snapshot.Id) is Node latest&&latest.Location?.Manual!=true)
                    db.Put(latest with{Location=location,Version=Math.Max(App.Now,latest.Version+1)});
            }
            catch(OperationCanceledException)when(token.IsCancellationRequested){return;}
            catch(Exception){db.Set("geo:"+key,JsonSerializer.Serialize(new GeoCache(cache?.Location,App.Now+3600_000),App.Json));}
        }
    }
}
