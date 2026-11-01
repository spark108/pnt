using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

sealed class FileOperationException(string message):IOException(message);

sealed class FileRemote(Store db,X509Certificate2 cert,string target,string settings,CancellationToken token):IDisposable
{
    readonly RouteTransport routing=new(db,cert);
    Peer? peer;
    string? requestId;
    public void Dispose(){peer?.Dispose();peer=null;}
    internal async Task<(FileReply Reply,byte[]? Data)> Call(FileRequest operation,byte[]? data=null)
    {
        for(var attempt=0;;attempt++)
        {
            token.ThrowIfCancellationRequested();
            if(!FileService.Valid(db,settings)||db.Resolve(target) is null)throw new FileOperationException("Файловый доступ выключен или узел исключён.");
            using var budget=CancellationTokenSource.CreateLinkedTokenSource(token);budget.CancelAfter(TimeSpan.FromSeconds(120));
            try
            {
                if(peer is null)
                {
                    peer=await routing.Connect(target,cancellation:budget.Token);
                    var task=await RouteTransport.SendTask(peer,new("file-session",Certificate.Id(cert),Target:target,Secret:settings));requestId=task.RequestId;
                    var ready=await RouteTransport.ReadResult(peer,requestId,TimeSpan.FromSeconds(10),budget.Token);
                    if(ready.Type!="file-ready")throw new FileOperationException(ready.Error??"Узел не поддерживает файловый сервис.");
                }
                await Peer.Send(peer.Stream,new("file-request",RequestId:requestId,File:operation with{Settings=settings})).WaitAsync(budget.Token);
                if(data is not null)await peer.Stream.WriteAsync(data,budget.Token);
                var result=await RouteTransport.ReadResult(peer,requestId,TimeSpan.FromSeconds(120),budget.Token);
                if(result.Type=="file-error")throw new FileOperationException(result.Error??"Ошибка файловой операции.");
                if(result.Type!="file-result"||result.Files is not {} reply)throw new IOException("Недопустимый ответ файлового сервиса.");
                byte[]? bytes=null;
                if(operation.Operation=="read")
                {
                    if(reply.Count<0||reply.Count>operation.Count||reply.Count>FileService.BlockSize||reply.Offset!=operation.Offset)throw new IOException("Недопустимый файловый блок.");
                    bytes=new byte[reply.Count];await peer.Stream.ReadExactlyAsync(bytes,budget.Token);
                    if(reply.Hash!=Convert.ToHexString(SHA256.HashData(bytes)))throw new IOException("Контрольная сумма блока не совпала.");
                }
                return(reply,bytes);
            }
            catch(FileOperationException){throw;}
            catch when(!token.IsCancellationRequested&&attempt<2&&operation.Operation is "list" or "stat" or "read" or "begin" or "write" or "commit")
            {
                Dispose();await Task.Delay(200,token);
            }
            catch{Dispose();throw;}
        }
    }
    internal async Task Download(Stream output,string path,long offset)
    {
        string? version=null;
        while(true)
        {
            var (reply,data)=await Call(new("read",path,Offset:offset,Count:FileService.BlockSize,Version:version));
            version??=reply.Version;if(reply.Version!=version||reply.Count==0&&reply.More)throw new IOException("Файл изменился или передача не продвигается.");
            await output.WriteAsync(data!,token);offset+=data!.Length;if(!reply.More)break;
        }
    }
    internal async Task Upload(Stream input,string path,long offset)
    {
        var transfer=Guid.NewGuid().ToString("N");await Call(new("begin",path,Offset:offset,Transfer:transfer));
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);var bytes=new byte[FileService.BlockSize];
        while(true)
        {
            var length=0;while(length<bytes.Length){var read=await input.ReadAsync(bytes.AsMemory(length),token);if(read==0)break;length+=read;}
            if(length==0)break;
            var block=length==bytes.Length?bytes:bytes[..length];
            var result=await Call(new("write",path,Offset:offset,Count:length,Transfer:transfer,Hash:Convert.ToHexString(SHA256.HashData(block))),block);
            if(result.Reply.Offset!=offset+length)throw new IOException("Смещение подтверждения записи не совпало.");
            hash.AppendData(block);offset+=length;if(length<bytes.Length)break;
        }
        var digest=Convert.ToHexString(hash.GetHashAndReset());var committed=await Call(new("commit",path,Offset:offset,Transfer:transfer,Hash:digest));
        if(committed.Reply.Hash!=digest||committed.Reply.Offset!=offset)throw new IOException("Подтверждение завершения передачи не совпало.");
    }
}
