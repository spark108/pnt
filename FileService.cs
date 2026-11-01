using System.Security.Cryptography;
using System.Text.Json;

namespace Pnt;

record FileRequest(string Operation,string Path="/",string? Destination=null,long Offset=0,int Count=0,string? Transfer=null,string? Version=null,string? Hash=null,string? Settings=null);
record FileEntry(string Name,bool Directory,long Size,string Modified,string Version);
record FileReply(FileEntry[]? Entries=null,FileEntry? Entry=null,long Offset=0,int Count=0,bool More=false,string? Version=null,string? Hash=null);
record FileUpload(string Id,string Path,string Original,long Start,long Offset,string Settings,long Updated,bool Done=false,string? Hash=null,bool Prepared=false,long LastOffset=-1,int LastCount=0,string? LastHash=null);

static class FileService
{
    internal const int BlockSize=1024*1024;
    static readonly SemaphoreSlim writes=new(1,1);
    sealed class UploadHash(IncrementalHash hash,long offset,string stamp):IDisposable
    {internal readonly IncrementalHash Hash=hash;internal long Offset=offset;internal string Stamp=stamp;public void Dispose()=>Hash.Dispose();}
    static readonly Dictionary<string,UploadHash> hashes=new();
    internal static bool Valid(Store db,string? settings)=>FtpControl.Active(db)&&db.Ftp() is {Enabled:true} config&&config.Id==settings;
    internal static string Native(string path,string? root=null)
    {
        if(path.Length>4096||!path.StartsWith('/')||path.Any(char.IsControl)||path.Contains('\\')||path.Split('/').Any(p=>p is "." or ".."))throw new IOException("Недопустимый путь.");
        if(root is not null)
        {
            var target=Path.GetFullPath(Path.Combine(root,path.TrimStart('/')));var basePath=Path.GetFullPath(root)+Path.DirectorySeparatorChar;
            if(target!=Path.GetFullPath(root)&&!target.StartsWith(basePath,OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal))throw new IOException("Путь вне файлового корня.");
            return target;
        }
        if(!OperatingSystem.IsWindows())return Path.GetFullPath(path);
        var parts=path.Split('/',StringSplitOptions.RemoveEmptyEntries);
        if(parts.Length==0)return "";
        if(parts[0].Length!=1||!char.IsAsciiLetter(parts[0][0])||parts.Any(p=>p.Contains(':')||p.EndsWith('.')||p.EndsWith(' ')))throw new IOException("Используйте путь /C/каталог/файл.");
        var result=char.ToUpperInvariant(parts[0][0])+":\\"+string.Join('\\',parts.Skip(1));
        if(!DriveInfo.GetDrives().Any(d=>d.Name.Equals(result[..3],StringComparison.OrdinalIgnoreCase)))throw new IOException("Диск не найден.");
        return Path.GetFullPath(result);
    }
    static string Stamp(FileSystemInfo info)=>info.Exists?(info is FileInfo f?f.Length:0)+":"+info.LastWriteTimeUtc.Ticks:"missing";
    static string Version(string path)=>Stamp(Directory.Exists(path)?new DirectoryInfo(path):new FileInfo(path));
    static FileEntry Entry(FileSystemInfo info)=>new(info.Name,info is DirectoryInfo,info is FileInfo file?file.Length:0,info.LastWriteTimeUtc.ToString("yyyyMMddHHmmss"),Stamp(info));
    static string Stage(FileUpload upload)=>Path.Combine(Path.GetDirectoryName(upload.Path)!,".pnt-upload-"+upload.Id+".part");
    static void Save(Store db,FileUpload upload)=>db.Set("ftp_upload:"+upload.Id,JsonSerializer.Serialize(upload,App.Json));
    static FileUpload Upload(Store db,FileRequest request,string path)
    {
        if(request.Transfer is not {Length:32} id||!id.All(Uri.IsHexDigit))throw new IOException("Недопустимый ID передачи.");
        var upload=JsonSerializer.Deserialize<FileUpload>(db.Get("ftp_upload:"+id)??"null",App.Json)??throw new IOException("Передача не найдена.");
        if(upload.Path!=path||upload.Settings!=request.Settings||upload.Updated<App.Now-86400000)throw new IOException("Передача истекла или не соответствует пути.");
        return upload;
    }
    static async Task<string> HashRange(string path,long offset,CancellationToken token)
    {
        await using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,65536,true);file.Position=offset;
        return Convert.ToHexString(await SHA256.HashDataAsync(file,token));
    }
    static async Task<UploadHash> Hasher(FileUpload upload,CancellationToken token)
    {
        var stage=Stage(upload);var stamp=Version(stage);
        if(hashes.TryGetValue(upload.Id,out var old)&&old.Offset==upload.Offset&&old.Stamp==stamp)return old;
        if(hashes.Remove(upload.Id,out old))old.Dispose();
        var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        try
        {
            await using var file=new FileStream(stage,FileMode.Open,FileAccess.Read,FileShare.Read,65536,true);file.Position=upload.Start;long remaining=upload.Offset-upload.Start;var bytes=new byte[65536];
            while(remaining>0){var n=await file.ReadAsync(bytes.AsMemory(0,(int)Math.Min(bytes.Length,remaining)),token);if(n==0)throw new IOException("Временный файл укорочен.");hash.AppendData(bytes,0,n);remaining-=n;}
            var result=new UploadHash(hash,upload.Offset,stamp);hashes[upload.Id]=result;return result;
        }
        catch{hash.Dispose();throw;}
    }
    internal static async Task<(FileReply Reply,byte[]? Data)> Execute(Store db,FileRequest request,byte[]? data,CancellationToken token,string? root=null)
    {
        if(!Valid(db,request.Settings))throw new IOException("Файловый доступ выключен или узел покинул кластер.");
        if(request.Offset<0||request.Count<0||request.Count>BlockSize)throw new IOException("Недопустимое смещение или размер блока.");
        var path=Native(request.Path,root);
        if(path.Length==0)
        {
            if(request.Operation=="stat")return (new(Entry:new("/",true,0,"19700101000000","drives")),null);
            if(request.Operation!="list")throw new IOException("Корень дисков доступен только для просмотра.");
            return (new(Entries:DriveInfo.GetDrives().Select(d=>new FileEntry(d.Name[..1],true,0,"19700101000000","drive")).ToArray()),null);
        }
        if(request.Operation=="stat")
        {
            FileSystemInfo info=Directory.Exists(path)?new DirectoryInfo(path):new FileInfo(path);if(!info.Exists)throw new FileNotFoundException("Файл или каталог не найден.");return(new(Entry:Entry(info)),null);
        }
        if(request.Operation=="list")
        {
            var info=new DirectoryInfo(path);if(!info.Exists)throw new DirectoryNotFoundException("Каталог не найден.");var version=Stamp(info);
            if(request.Version is not null&&request.Version!=version)throw new IOException("Каталог изменился; повторите просмотр.");
            if(request.Offset>1_000_000)throw new IOException("Каталог слишком большой.");
            var entries=info.EnumerateFileSystemInfos().Where(f=>!f.Name.Any(char.IsControl)&&!f.Name.StartsWith(".pnt-upload-",StringComparison.Ordinal)).Skip((int)request.Offset).Take(513).ToArray();
            return(new(Entries:entries.Take(512).Select(Entry).ToArray(),More:entries.Length>512,Version:version),null);
        }
        if(request.Operation=="read")
        {
            await using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,65536,true);var version=Version(path);
            if(request.Version is not null&&request.Version!=version)throw new IOException("Файл изменился во время передачи.");
            if(request.Offset>file.Length)throw new IOException("Смещение за концом файла.");
            file.Position=request.Offset;var bytes=new byte[(int)Math.Min(request.Count,file.Length-request.Offset)];await file.ReadExactlyAsync(bytes,token);
            if(Version(path)!=version)throw new IOException("Файл изменился во время передачи.");
            return(new(Offset:request.Offset,Count:bytes.Length,More:file.Position<file.Length,Version:version,Hash:Convert.ToHexString(SHA256.HashData(bytes))),bytes);
        }
        await writes.WaitAsync(token);
        try
        {
            if(!Valid(db,request.Settings))throw new IOException("Файловый доступ выключен.");
            switch(request.Operation)
            {
                case "mkdir":if(File.Exists(path)||Directory.Exists(path))throw new IOException("Путь уже существует.");if(!Directory.Exists(Path.GetDirectoryName(path)))throw new IOException("Родительский каталог не найден.");Directory.CreateDirectory(path);break;
                case "delete":if(!File.Exists(path))throw new IOException("Файл не найден.");File.Delete(path);break;
                case "rmdir":Directory.Delete(path,false);break;
                case "rename":
                    var target=Native(request.Destination??throw new IOException("Не задано назначение."),root);
                    if(Directory.Exists(path))Directory.Move(path,target);else File.Move(path,target);break;
                case "begin":
                {
                    if(request.Transfer is not {Length:32} transfer||!transfer.All(Uri.IsHexDigit))throw new IOException("Недопустимый ID передачи.");
                    var old=db.Get("ftp_upload:"+transfer) is not null?Upload(db,request,path):null;
                    if(old is {Prepared:true})return(new(Offset:old.Offset),null);
                    var original=Version(path);if(Directory.Exists(path))throw new IOException("Назначение является каталогом.");
                    if(old is not null&&(old.Original!=original||old.Start!=request.Offset))throw new IOException("Исходный файл изменился.");
                    var upload=old??new FileUpload(transfer,path,original,request.Offset,request.Offset,request.Settings!,App.Now);var stage=Stage(upload);
                    Save(db,upload);
                    if(File.Exists(stage)&&new FileInfo(stage).LinkTarget is not null)throw new IOException("Временный файл подменён ссылкой.");
                    var options=new FileStreamOptions{Mode=old is null?FileMode.CreateNew:FileMode.Create,Access=FileAccess.Write,Share=FileShare.None,BufferSize=65536,Options=FileOptions.Asynchronous};
                    if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
                    await using(var output=new FileStream(stage,options))
                    {
                        if(request.Offset>0)
                        {
                            await using var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,65536,true);if(input.Length<request.Offset)throw new IOException("Смещение за концом исходного файла.");
                            var buffer=new byte[65536];long remaining=request.Offset;while(remaining>0){var n=await input.ReadAsync(buffer.AsMemory(0,(int)Math.Min(buffer.Length,remaining)),token);if(n==0)throw new IOException("Исходный файл укорочен.");await output.WriteAsync(buffer.AsMemory(0,n),token);remaining-=n;}
                        }
                        output.Flush(true);
                    }
                    if(Version(path)!=original)throw new IOException("Исходный файл изменился.");Save(db,upload with{Prepared=true,Updated=App.Now});return(new(Offset:upload.Offset),null);
                }
                case "write":
                {
                    var upload=Upload(db,request,path);if(upload.Done)throw new IOException("Передача уже завершена.");
                    if(data is null||data.Length!=request.Count||request.Hash!=Convert.ToHexString(SHA256.HashData(data)))throw new IOException("Контрольная сумма блока не совпала.");
                    if(!upload.Prepared)throw new IOException("Передача не подготовлена.");
                    if(request.Offset<upload.Offset&&request.Offset==upload.LastOffset&&request.Count==upload.LastCount&&request.Hash==upload.LastHash)return(new(Offset:upload.Offset),null);
                    if(request.Offset!=upload.Offset)throw new IOException("Устаревший или недопустимый блок записи.");
                    var hasher=await Hasher(upload,token);
                    await using var output=new FileStream(Stage(upload),FileMode.Open,FileAccess.Write,FileShare.None,65536,true);
                    if(output.Length<request.Offset)throw new IOException("Временный файл повреждён.");output.Position=request.Offset;await output.WriteAsync(data,token);output.SetLength(request.Offset+data.Length);output.Flush(true);
                    await output.DisposeAsync();hasher.Hash.AppendData(data);hasher.Offset=request.Offset+data.Length;hasher.Stamp=Version(Stage(upload));
                    upload=upload with{Offset=request.Offset+data.Length,Updated=App.Now,LastOffset=request.Offset,LastCount=request.Count,LastHash=request.Hash};Save(db,upload);return(new(Offset:upload.Offset),null);
                }
                case "commit":
                {
                    var upload=Upload(db,request,path);if(upload.Done){if(upload.Offset!=request.Offset||upload.Hash!=request.Hash)throw new IOException("Результат передачи не совпадает.");return(new(Offset:upload.Offset,Hash:upload.Hash),null);}
                    var stage=Stage(upload);
                    if(!upload.Prepared||upload.Offset!=request.Offset)throw new IOException("Передача не завершена.");
                    if(!File.Exists(stage))
                    {
                        if(!File.Exists(path)||new FileInfo(path).Length!=upload.Offset||await HashRange(path,upload.Start,token)!=request.Hash)throw new IOException("Временный файл потерян.");
                    }
                    else
                    {
                        if(new FileInfo(stage).Length!=upload.Offset||Convert.ToHexString((await Hasher(upload,token)).Hash.GetCurrentHash())!=request.Hash)throw new IOException("Контрольная сумма файла не совпала.");
                        if(Version(path)!=upload.Original)throw new IOException("Назначение изменено другой операцией; загрузка не подменит его.");
                        if(!Valid(db,request.Settings))throw new IOException("Файловый доступ выключен.");
                        if(!OperatingSystem.IsWindows()&&File.Exists(path))File.SetUnixFileMode(stage,File.GetUnixFileMode(path));
                        File.Move(stage,path,true);
                    }
                    Save(db,upload with{Done=true,Hash=request.Hash,Updated=App.Now});if(hashes.Remove(upload.Id,out var completed))completed.Dispose();return(new(Offset:upload.Offset,Hash:request.Hash),null);
                }
                default:throw new IOException("Неизвестная файловая операция.");
            }
            return(new(),null);
        }
        finally{writes.Release();}
    }
    internal static async Task Cleanup(Store db,CancellationToken token)
    {
        await writes.WaitAsync(token);
        try
        {
            foreach(var json in db.FtpUploads())try
            {
                var upload=JsonSerializer.Deserialize<FileUpload>(json,App.Json)!;if(upload.Updated>App.Now-86400000)continue;
                if(!upload.Done)File.Delete(Stage(upload));if(hashes.Remove(upload.Id,out var hash))hash.Dispose();db.RemoveFtpUpload(upload.Id);
            }
            catch(Exception e){Console.Error.WriteLine("pnt: FTPS cleanup: "+e.Message);}
        }
        finally{writes.Release();}
    }
    internal static async Task Serve(Store db,Stream stream,Message session,CancellationToken token)
    {
        if(!Valid(db,session.Secret)){await Peer.Send(stream,new("error",Error:"FTPS выключен.",RequestId:session.RequestId));return;}
        await Peer.Send(stream,new("file-ready",RequestId:session.RequestId));
        while(!token.IsCancellationRequested)
        {
            using var idle=CancellationTokenSource.CreateLinkedTokenSource(token);idle.CancelAfter(TimeSpan.FromMinutes(3));
            var message=await Peer.Read(stream).WaitAsync(idle.Token);if(message is null)return;
            if(message.Type!="file-request"||message.RequestId!=session.RequestId||message.File is not {} request||request.Settings!=session.Secret)return;
            byte[]? data=null;
            if(request.Operation=="write")
            {
                if(request.Count is <0 or >BlockSize)return;data=new byte[request.Count];await stream.ReadExactlyAsync(data,idle.Token);
            }
            try
            {
                if(db.Resolve(session.Id??"") is null)throw new IOException("Узел-источник покинул кластер.");
                var result=await Execute(db,request,data,idle.Token);
                await Peer.Send(stream,new("file-result",RequestId:session.RequestId,Files:result.Reply)).WaitAsync(idle.Token);
                if(result.Data is not null)await stream.WriteAsync(result.Data,idle.Token);
            }
            catch(Exception e) when(e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {await Peer.Send(stream,new("file-error",RequestId:session.RequestId,Error:e.Message)).WaitAsync(idle.Token);}
        }
    }
}
