using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;

namespace Pnt;

sealed class NasaImagery(HttpClient? client=null) : IDisposable
{
    static readonly HttpClient upstream=new(new SocketsHttpHandler{MaxConnectionsPerServer=8}){Timeout=TimeSpan.FromSeconds(10)};
    readonly HttpClient http=client??upstream;
    readonly MemoryCache cache=new(new MemoryCacheOptions{SizeLimit=32*1024*1024});
    readonly SemaphoreSlim slots=new(8);
    internal static bool Valid(int z,int y,int x)=>z is >=0 and <=8&&y>=0&&x>=0&&y<(1<<z)&&x<(1<<z);
    internal async Task<byte[]> Get(int z,int y,int x,CancellationToken token)
    {
        if(!Valid(z,y,x))throw new ArgumentOutOfRangeException(nameof(z));
        var key=$"{z}/{y}/{x}";
        if(cache.TryGetValue<byte[]>(key,out var hit))return hit!;
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(12));token=timeout.Token;
        await slots.WaitAsync(token);
        try
        {
            if(cache.TryGetValue<byte[]>(key,out hit))return hit!;
            using var response=await http.GetAsync("https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/BlueMarble_ShadedRelief_Bathymetry/default/GoogleMapsCompatible_Level8/"+key+".jpeg",HttpCompletionOption.ResponseHeadersRead,token);
            response.EnsureSuccessStatusCode();
            const int limit=2*1024*1024;
            if(response.Content.Headers.ContentType?.MediaType!="image/jpeg"||response.Content.Headers.ContentLength>limit)
                throw new IOException("NASA вернул некорректный тип тайла.");
            await using var stream=await response.Content.ReadAsStreamAsync(token);
            using var data=new MemoryStream();var buffer=new byte[16384];int read;
            while((read=await stream.ReadAsync(buffer,token))>0)
            {
                if(data.Length+read>limit)throw new IOException("Тайл NASA слишком большой.");
                data.Write(buffer,0,read);
            }
            var bytes=data.ToArray();
            if(bytes.Length<4||bytes[0]!=255||bytes[1]!=216)throw new IOException("NASA вернул повреждённый тайл.");
            cache.Set(key,bytes,new MemoryCacheEntryOptions{Size=bytes.Length,AbsoluteExpirationRelativeToNow=TimeSpan.FromDays(7)});
            return bytes;
        }
        finally{slots.Release();}
    }
    public async Task<IResult> Tile(int z,int y,int x,HttpContext context)
    {
        if(!Valid(z,y,x))return Results.BadRequest(new{error="Недопустимые координаты тайла."});
        try
        {
            var data=await Get(z,y,x,context.RequestAborted);
            context.Response.Headers.CacheControl="private, max-age=86400";
            return Results.Bytes(data,"image/jpeg");
        }
        catch(OperationCanceledException)when(context.RequestAborted.IsCancellationRequested){throw;}
        catch(Exception e)when(e is HttpRequestException or IOException or OperationCanceledException)
        {
            context.Response.Headers.RetryAfter="30";
            Console.Error.WriteLine($"pnt: NASA tile {z}/{y}/{x}: {e.GetBaseException().Message}");
            return Results.Json(new{error="Не удалось загрузить тайл NASA. Используется встроенная карта."},statusCode:503);
        }
    }
    public void Dispose(){cache.Dispose();slots.Dispose();}
}
