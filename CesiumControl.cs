using System.Text;
using System.Text.Json;

namespace Pnt;

record CesiumDataset(long Id,string Name,string Type,bool Enabled=true);
record CesiumConfig(string Id,string Token,CesiumDataset[] Assets,long Version);

static class CesiumControl
{
    internal static readonly string[] Types=["TERRAIN","IMAGERY","3DTILES","GEOJSON","CZML","KML"];
    internal static bool ValidToken(string value)=>value.Length is >=16 and <=8192&&!value.Any(char.IsWhiteSpace)&&!value.Any(char.IsControl);
    internal static bool Valid(CesiumConfig value)=>value.Id is {Length:32}&&value.Id.All(Uri.IsHexDigit)&&value.Version>0
        &&value.Token is not null&&(value.Token.Length==0||ValidToken(value.Token))&&value.Assets is {Length:<=128}
        &&value.Assets.All(a=>a is not null&&a.Id is >0 and <=9007199254740991&&a.Name is {Length:>0 and <=64}&&!a.Name.Any(char.IsControl)&&Types.Contains(a.Type))
        &&value.Assets.Select(a=>a.Id).Distinct().Count()==value.Assets.Length&&value.Assets.Count(a=>a.Enabled&&a.Type=="TERRAIN")<=1;
    public static object Public(CesiumConfig? config)=>new{configured=!string.IsNullOrEmpty(config?.Token),revision=config?.Id??"",assets=config?.Assets??[]};
    static CesiumConfig Next(CesiumConfig? old,string token,CesiumDataset[] assets)=>new(Guid.NewGuid().ToString("N"),token,assets,Math.Max(App.Now,(old?.Version??0)+1));
    static string ReadToken()
    {
        if(Console.IsInputRedirected)throw new ArgumentException("Введите токен в интерактивном терминале или передайте аргументом.");
        Console.Write("Токен Cesium ion: ");var value=new StringBuilder();
        while(true)
        {
            var key=Console.ReadKey(true);if(key.Key==ConsoleKey.Enter)break;
            if(key.Key==ConsoleKey.Backspace){if(value.Length>0)value.Length--;continue;}
            if(!char.IsControl(key.KeyChar)&&value.Length<8192)value.Append(key.KeyChar);
        }
        Console.WriteLine();return value.ToString().Trim();
    }
    static long AssetId(string value)=>long.TryParse(value,out var id)&&id is >0 and <=9007199254740991?id:throw new ArgumentException("Укажите положительный числовой ID ассета Cesium ion.");
    public static async Task Command(Store db,string[] args,HttpClient? client=null)
    {
        if(db.Self() is null||db.Get("left")=="1")throw new ArgumentException("Сначала присоединитесь к кластеру.");
        switch(args)
        {
            case ["token"]:
                await Command(db,["token",ReadToken()],client);break;
            case ["token",var value]:
                var token=value=="clear"?"":value.Trim();
                if(value!="clear"&&!ValidToken(token))throw new ArgumentException("Некорректный токен Cesium ion.");
                db.ChangeCesium(old=>Next(old,token,old?.Assets??[]));
                Console.WriteLine(token.Length==0?"Токен Cesium ion удалён.":"Токен Cesium ion сохранён. Настройка распространяется по кластеру.");break;
            case ["add",var key,..var rest] when rest.Length<=1:
                var id=AssetId(key);var snapshot=db.Cesium();
                if(string.IsNullOrEmpty(snapshot?.Token))throw new ArgumentException("Сначала задайте токен: pnt cesium token");
                var name=rest.Length==0?$"Cesium {id}":rest[0].Trim();
                if(name.Length is <1 or >64||name.Any(char.IsControl))throw new ArgumentException("Имя датасета: от 1 до 64 символов.");
                var endpoint=await new CesiumIonApi(client).Endpoint(id,snapshot.Token,default);
                var type=endpoint.GetProperty("type").GetString()!;
                db.ChangeCesium(old=>
                {
                    if(old?.Token!=snapshot.Token)throw new IOException("Токен изменился во время запроса. Повторите добавление.");
                    var assets=old.Assets.Where(a=>a.Id!=id).Select(a=>type=="TERRAIN"&&a.Type=="TERRAIN"?a with{Enabled=false}:a).Append(new CesiumDataset(id,name,type)).ToArray();
                    if(assets.Length>128)throw new ArgumentException("Допускается не более 128 датасетов.");
                    return Next(old,old.Token,assets);
                });
                Console.WriteLine($"Датасет добавлен: {id} · {name} · {type}");break;
            case [var action,var key] when action is "remove" or "enable" or "disable":
                var target=AssetId(key);
                db.ChangeCesium(old=>
                {
                    var asset=old?.Assets.FirstOrDefault(a=>a.Id==target)??throw new ArgumentException("Датасет не найден.");
                    var assets=action=="remove"?old!.Assets.Where(a=>a.Id!=target).ToArray():old!.Assets.Select(a=>a.Id==target?a with{Enabled=action=="enable"}
                        :action=="enable"&&asset.Type=="TERRAIN"&&a.Type=="TERRAIN"?a with{Enabled=false}:a).ToArray();
                    return Next(old,old.Token,assets);
                });
                Console.WriteLine(action=="remove"?"Датасет удалён.":action=="enable"?"Датасет включён.":"Датасет выключен.");break;
            case ["list"]:
                CliOutput.Table(["ID","Название","Тип","Состояние"],(db.Cesium()?.Assets??[]).Select(a=>new CliCell[]{a.Id.ToString(),a.Name,a.Type,new(a.Enabled?"включён":"выключен",a.Enabled?"green":"grey")}));break;
            case ["status"]:
                var config=db.Cesium();Console.WriteLine("Токен: "+(string.IsNullOrEmpty(config?.Token)?"не задан":"настроен"));Console.WriteLine("Датасетов: "+(config?.Assets.Length??0));break;
            default:throw new ArgumentException("pnt cesium token [токен|clear]; add <ID> [имя]; remove|enable|disable <ID>; list; status");
        }
    }
}

sealed class CesiumIonApi(HttpClient? client=null)
{
    static readonly HttpClient http=new(new SocketsHttpHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(15)};
    public async Task<JsonElement> Endpoint(long asset,string token,CancellationToken cancellation)
    {
        if(asset is <=0 or >9007199254740991||!CesiumControl.ValidToken(token))throw new ArgumentException("Некорректный ID ассета или токен Cesium ion.");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            using var request=new HttpRequestMessage(HttpMethod.Get,$"https://api.cesium.com/v1/assets/{asset}/endpoint?access_token={Uri.EscapeDataString(token)}");
            request.Headers.Add("X-Cesium-Client","PNT");
            using var response=await (client??http).SendAsync(request,timeout.Token);
            if(!response.IsSuccessStatusCode)throw new IOException($"Cesium ion: ассет {asset}, HTTP {(int)response.StatusCode}. Проверьте доступ токена к ассету.");
            if(response.Content.Headers.ContentLength>1024*1024)throw new IOException("Слишком большой ответ Cesium ion.");
            var text=await response.Content.ReadAsStringAsync(timeout.Token);
            if(text.Length>1024*1024||text.Contains(token,StringComparison.Ordinal))throw new IOException("Cesium ion вернул небезопасный ответ.");
            using var json=JsonDocument.Parse(text);var root=json.RootElement;
            if(!root.TryGetProperty("type",out var type)||type.ValueKind!=JsonValueKind.String||!CesiumControl.Types.Contains(type.GetString()??""))throw new IOException("Тип датасета Cesium ion не поддерживается.");
            return root.Clone();
        }
        catch(HttpRequestException){throw new IOException("Не удалось связаться с Cesium ion.");}
        catch(JsonException){throw new IOException("Некорректный ответ Cesium ion.");}
        catch(OperationCanceledException)when(!cancellation.IsCancellationRequested){throw new IOException("Cesium ion не ответил за 15 секунд.");}
    }
}
