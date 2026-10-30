using System.IO.Compression;
using System.Reflection;
using Microsoft.AspNetCore.Http;

namespace Pnt;

static class WebAssets
{
    static readonly Lazy<byte[]> geography=new(()=>
    {
        var assembly=Assembly.GetExecutingAssembly();
        var resource=assembly.GetManifestResourceNames().Single(n=>n.EndsWith(".web.geography.json",StringComparison.OrdinalIgnoreCase));
        using var input=assembly.GetManifestResourceStream(resource)!;using var output=new MemoryStream();input.CopyTo(output);return output.ToArray();
    });
    public static IResult Geography(HttpContext context)
    {
        context.Response.Headers.CacheControl="private, max-age=86400";
        return Results.Bytes(geography.Value,"application/json; charset=utf-8");
    }
    static readonly Lazy<Dictionary<string,byte[]>> files=new(()=>
    {
        var assembly=Assembly.GetExecutingAssembly();
        var resource=assembly.GetManifestResourceNames().SingleOrDefault(n=>n.EndsWith(".web.cesium.zip",StringComparison.OrdinalIgnoreCase));
        var result=new Dictionary<string,byte[]>(StringComparer.Ordinal);
        if(resource is null)return result;
        using var stream=assembly.GetManifestResourceStream(resource)!;
        using var zip=new ZipArchive(stream,ZipArchiveMode.Read);
        foreach(var entry in zip.Entries)
        {
            if(entry.FullName.EndsWith('/'))continue;
            using var input=entry.Open();using var output=new MemoryStream();input.CopyTo(output);
            result[entry.FullName]=output.ToArray();
        }
        return result;
    });
    public static IResult Cesium(string? path,HttpContext context)
    {
        if(path is null||!files.Value.TryGetValue(path,out var data))return Results.NotFound();
        context.Response.Headers.CacheControl="private, max-age=86400";
        var type=Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".js"=>"text/javascript; charset=utf-8",".css"=>"text/css; charset=utf-8",".json"=>"application/json",
            ".jpg" or ".jpeg"=>"image/jpeg",".png"=>"image/png",".svg"=>"image/svg+xml",".wasm"=>"application/wasm",
            ".xml"=>"application/xml",_=>"application/octet-stream"
        };
        return Results.Bytes(data,type);
    }
}
