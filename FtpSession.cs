using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Pnt;

sealed class FtpSession(FtpGateway gateway,Store db,X509Certificate2 cert,TcpClient client,string settings,CancellationToken stopped)
{
    Stream control=client.GetStream();
    readonly IPAddress remote=((IPEndPoint)client.Client.RemoteEndPoint!).Address;
    TcpListener? passive;
    bool tls,authenticated,protectedData,pbsz,binary=true;
    string user="",cwd="/";
    long restart;
    (Node Node,string Path)? rename;
    static string Safe(string text)=>text.Replace('\r',' ').Replace('\n',' ').Replace('\0',' ');
    static string Folder(Node node)=>Safe(node.Name).Replace('/','_').Replace('\\','_')+" ["+node.Id+"]";
    Task Reply(int code,string text)=>control.WriteAsync(Encoding.UTF8.GetBytes(code+" "+Safe(text)+"\r\n"),stopped).AsTask();
    async Task<string?> Line()
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stopped);timeout.CancelAfter(TimeSpan.FromSeconds(authenticated?180:30));
        var bytes=new byte[8192];var one=new byte[1];var length=0;
        while(length<bytes.Length){if(await control.ReadAsync(one,timeout.Token)==0)return null;if(one[0]==10)return new UTF8Encoding(false,true).GetString(bytes,0,length).TrimEnd('\r');bytes[length++]=one[0];}
        throw new IOException("Команда слишком длинная.");
    }
    string Normalize(string path)
    {
        if(path.Length>4096||path.Any(char.IsControl)||path.Contains('\\'))throw new IOException("Недопустимый путь.");
        var parts=new List<string>();foreach(var part in (path.StartsWith('/')?path:cwd.TrimEnd('/')+"/"+path).Split('/',StringSplitOptions.RemoveEmptyEntries)){if(part==".")continue;if(part==".."){if(parts.Count>0)parts.RemoveAt(parts.Count-1);}else parts.Add(part);}
        return "/"+string.Join('/',parts);
    }
    (Node Node,string Path)? Resolve(string path)
    {
        var full=Normalize(path);if(full=="/")return null;var split=full.IndexOf('/',1);var folder=split<0?full[1..]:full[1..split];
        var node=db.Nodes().FirstOrDefault(n=>!n.Removed&&(folder==n.Id||folder==Folder(n)||folder.EndsWith(" ["+n.Id+"]",StringComparison.Ordinal)))??throw new IOException("Узел не найден или исключён.");
        return(node,split<0?"/":full[split..]);
    }
    FileRemote Remote(Node node,CancellationToken token)=>new(db,cert,node.Id,settings,token);
    async Task<FileEntry> Stat((Node Node,string Path)? path)
    {
        if(path is null)return new("/",true,0,"19700101000000","root");
        using var connection=Remote(path.Value.Node,stopped);return (await connection.Call(new("stat",path.Value.Path))).Reply.Entry??throw new IOException("Нет сведений о файле.");
    }
    string DisplayCwd(){if(cwd=="/")return cwd;var split=cwd.IndexOf('/',1);var id=split<0?cwd[1..]:cwd[1..split];return "/"+Folder(db.Resolve(id)??throw new IOException("Узел исключён."))+(split<0?"":cwd[split..]);}
    async Task Passive(bool extended)
    {
        gateway.Release(passive);passive=gateway.Passive();var port=((IPEndPoint)passive.LocalEndpoint).Port;
        if(extended){await Reply(229,$"Entering Extended Passive Mode (|||{port}|)");return;}
        var ip=((IPEndPoint)client.Client.LocalEndPoint!).Address;
        if(db.Self() is {} self&&!Enrollment.Private(self.Ip)&&IPAddress.TryParse(self.Ip,out var advertised)&&advertised.AddressFamily==AddressFamily.InterNetwork)ip=advertised;
        await Reply(227,"Entering Passive Mode ("+string.Join(',',ip.MapToIPv4().GetAddressBytes())+$",{port/256},{port%256})");
    }
    async Task Data(Func<Stream,CancellationToken,Task> action)
    {
        if(!protectedData||!pbsz){await Reply(536,"Use PBSZ 0 and PROT P.");return;}
        if(passive is null){await Reply(425,"Use EPSV or PASV first.");return;}
        var socket=passive;passive=null;
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(stopped);budget.CancelAfter(TimeSpan.FromMinutes(3));
        try
        {
            await Reply(150,"Opening protected binary data connection.");
            using var acceptLimit=CancellationTokenSource.CreateLinkedTokenSource(budget.Token);acceptLimit.CancelAfter(TimeSpan.FromSeconds(30));
            TcpClient? data=null;while(data is null){var candidate=await socket.AcceptTcpClientAsync(acceptLimit.Token);if(!((IPEndPoint)candidate.Client.RemoteEndPoint!).Address.Equals(remote)){candidate.Dispose();continue;}data=candidate;}
            using(data)
            using(var stream=new SslStream(data.GetStream(),false))
            {
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=cert,EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13},acceptLimit.Token);
                using var progress=new FtpDataStream(stream,budget);
                await action(progress,budget.Token);await stream.FlushAsync(budget.Token);await stream.ShutdownAsync().WaitAsync(budget.Token);
            }
            await Reply(226,"Transfer complete.");
        }
        catch(Exception e)when(!stopped.IsCancellationRequested){await Reply(426,"Transfer failed: "+e.Message);}
        finally{gateway.Release(socket);}
    }
    static string Facts(FileEntry e)=>$"type={(e.Directory?"dir":"file")};size={e.Size};modify={e.Modified}; ";
    static string Listing(FileEntry e)=>$"{(e.Directory?'d':'-')}rw-r--r-- 1 pnt pnt {e.Size.ToString(CultureInfo.InvariantCulture)} {DateTime.ParseExact(e.Modified,"yyyyMMddHHmmss",CultureInfo.InvariantCulture).ToString("MMM dd HH:mm",CultureInfo.InvariantCulture)} ";
    async Task List(string argument,string mode)
    {
        if(argument is "-a" or "-l" or "-la" or "-al")argument="";
        var path=Resolve(argument);await Data(async(stream,token)=>
        {
            async Task Write(FileEntry entry){var text=(mode=="MLSD"?Facts(entry):mode=="LIST"?Listing(entry):"")+Safe(entry.Name)+"\r\n";await stream.WriteAsync(Encoding.UTF8.GetBytes(text),token);}
            if(path is null){foreach(var n in db.Nodes().Where(n=>!n.Removed).OrderBy(n=>n.Id))await Write(new(Folder(n),true,0,"19700101000000","node"));return;}
            using var connection=Remote(path.Value.Node,token);long offset=0;string? version=null;
            while(true){var reply=(await connection.Call(new("list",path.Value.Path,Offset:offset,Version:version))).Reply;foreach(var e in reply.Entries??[])await Write(e);offset+=reply.Entries?.Length??0;version??=reply.Version;if(!reply.More)break;}
        });
    }
    internal async Task Run()
    {
        await Reply(220,"PNT FTPS. AUTH TLS required.");
        try{while(!stopped.IsCancellationRequested)
        {
            if(!FileService.Valid(db,settings)){await Reply(421,"File access disabled.");break;}
            var line=await Line();if(line is null)break;var space=line.IndexOf(' ');var command=(space<0?line:line[..space]).ToUpperInvariant();var argument=space<0?"":line[(space+1)..];
            if(command!="RNTO"&&command!="RNFR")rename=null;
            try
            {
                if(command=="QUIT"){await Reply(221,"Goodbye.");break;}
                if(command=="AUTH")
                {
                    if(tls||!argument.Equals("TLS",StringComparison.OrdinalIgnoreCase)){await Reply(504,"Use AUTH TLS.");continue;}
                    await Reply(234,"Proceed with TLS.");var stream=new SslStream(control,false);control=stream;
                    using var limit=CancellationTokenSource.CreateLinkedTokenSource(stopped);limit.CancelAfter(TimeSpan.FromSeconds(15));
                    await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions{ServerCertificate=cert,EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13},limit.Token);tls=true;continue;
                }
                if(command=="FEAT"){await control.WriteAsync(Encoding.UTF8.GetBytes("211-Features\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n UTF8\r\n EPSV\r\n SIZE\r\n MDTM\r\n MLST type*;size*;modify*;\r\n REST STREAM\r\n TVFS\r\n211 End\r\n"),stopped);continue;}
                if(command=="SYST"){await Reply(215,"UNIX Type: L8");continue;}
                if(command=="NOOP"){await Reply(200,"OK");continue;}
                if(!tls){await Reply(534,"AUTH TLS required before authentication.");continue;}
                if(command=="PBSZ"){pbsz=argument=="0";await Reply(pbsz?200:501,pbsz?"PBSZ=0":"Use PBSZ 0.");continue;}
                if(command=="PROT"){protectedData=pbsz&&argument.Equals("P",StringComparison.OrdinalIgnoreCase);await Reply(protectedData?200:536,protectedData?"Private data connections required.":"Use PBSZ 0 and PROT P.");continue;}
                if(command=="USER"){authenticated=false;user=argument;await Reply(331,"Password required.");continue;}
                if(command=="PASS"){authenticated=gateway.Authenticate(user,argument,remote);if(!authenticated)await Task.Delay(500,stopped);await Reply(authenticated?230:530,authenticated?"Owner authenticated.":"Authentication failed or rate limited.");continue;}
                if(!authenticated){await Reply(530,"Log in first.");continue;}
                switch(command)
                {
                    case "OPTS":await Reply(argument.Equals("UTF8 ON",StringComparison.OrdinalIgnoreCase)||argument.StartsWith("MLST ",StringComparison.OrdinalIgnoreCase)?200:501,"UTF-8 enabled.");break;
                    case "TYPE":if(argument is "I" or "A"){binary=argument=="I";await Reply(200,"Type set.");}else await Reply(504,"Use TYPE I.");break;
                    case "MODE":await Reply(argument=="S"?200:504,"Stream mode only.");break;
                    case "STRU":await Reply(argument=="F"?200:504,"File structure only.");break;
                    case "PWD":case "XPWD":await Reply(257,"\""+DisplayCwd().Replace("\"","\"\"")+"\" is the current directory.");break;
                    case "CWD":case "CDUP":
                    {
                        var path=Resolve(command=="CDUP"?"..":argument);var info=await Stat(path);if(!info.Directory)throw new IOException("Это не каталог.");cwd=path is null?"/":"/"+path.Value.Node.Id+(path.Value.Path=="/"?"":path.Value.Path);await Reply(250,"Directory changed.");break;
                    }
                    case "EPSV":if(argument.Length>0&&argument!="1"){await Reply(522,"Use IPv4 EPSV.");break;}await Passive(true);break;
                    case "PASV":await Passive(false);break;
                    case "PORT":case "EPRT":await Reply(502,"Active FTP is disabled. Use EPSV or PASV.");break;
                    case "LIST":case "NLST":case "MLSD":await List(argument,command);break;
                    case "MLST":
                    {var path=Resolve(argument);var info=await Stat(path);await control.WriteAsync(Encoding.UTF8.GetBytes("250-Listing\r\n "+Facts(info)+Safe(Normalize(argument))+"\r\n250 End\r\n"),stopped);break;}
                    case "SIZE":case "MDTM":
                    {var info=await Stat(Resolve(argument));if(info.Directory)throw new IOException("Это каталог.");await Reply(213,command=="SIZE"?info.Size.ToString(CultureInfo.InvariantCulture):info.Modified);break;}
                    case "REST":if(!long.TryParse(argument,NumberStyles.None,CultureInfo.InvariantCulture,out restart)||restart<0){restart=0;await Reply(501,"Invalid restart offset.");}else await Reply(350,"Restart position accepted.");break;
                    case "RETR":case "STOR":
                    {
                        var offset=restart;restart=0;if(!binary){await Reply(504,"File transfers require binary mode: TYPE I.");break;}
                        var path=Resolve(argument)??throw new IOException("Выберите файл узла.");if(path.Path=="/")throw new IOException("Корень узла нельзя заменить файлом.");
                        await Data(async(stream,token)=>{using var connection=Remote(path.Node,token);if(command=="RETR")await connection.Download(stream,path.Path,offset);else await connection.Upload(stream,path.Path,offset);});break;
                    }
                    case "MKD":case "XMKD":case "RMD":case "XRMD":case "DELE":
                    {
                        var path=Resolve(argument)??throw new IOException("Виртуальный корень нельзя изменять.");if(path.Path=="/")throw new IOException("Корень узла нельзя изменять.");
                        using var connection=Remote(path.Node,stopped);await connection.Call(new(command is "MKD" or "XMKD"?"mkdir":command=="DELE"?"delete":"rmdir",path.Path));await Reply(250,"Operation complete.");break;
                    }
                    case "RNFR":rename=Resolve(argument)??throw new IOException("Виртуальный корень нельзя переименовать.");if(rename.Value.Path=="/")throw new IOException("Корень узла нельзя переименовать.");await Stat(rename);await Reply(350,"Send RNTO.");break;
                    case "RNTO":
                    {
                        var source=rename??throw new IOException("Сначала выполните RNFR.");rename=null;var target=Resolve(argument)??throw new IOException("Недопустимое назначение.");if(source.Node.Id!=target.Node.Id||target.Path=="/")throw new IOException("Перемещение между узлами не поддерживается.");using var connection=Remote(source.Node,stopped);await connection.Call(new("rename",source.Path,Destination:target.Path));await Reply(250,"Renamed.");break;
                    }
                    case "ABOR":gateway.Release(passive);passive=null;restart=0;await Reply(225,"No transfer in progress.");break;
                    default:await Reply(502,"Command not implemented.");break;
                }
            }
            catch(Exception e)when(e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException){await Reply(550,e.Message);}
        }}finally{gateway.Release(passive);await control.DisposeAsync();}
    }
}
