using System.Text;

namespace Pnt;

// Logging must never stop networking or maintenance when the disk is full.
sealed class ServiceLog(string path,Func<string,Stream>? open=null,Func<long>? clock=null,long retryDelay=5000,long limit=10*1024*1024):TextWriter
{
    readonly object gate=new();
    StreamWriter? writer;
    long retryAt,size;
    bool disposed;
    public override Encoding Encoding=>new UTF8Encoding(false);
    long Now=>(clock??(()=>Environment.TickCount64))();
    void Drop()
    {
        var previous=writer;writer=null;
        try{previous?.Dispose();}catch(IOException){}catch(UnauthorizedAccessException){}
    }
    void Append(string text)
    {
        lock(gate)
        {
            if(disposed||Now<retryAt)return;
            try
            {
                if(writer is not null&&size>=limit){Drop();File.Move(path,path+".previous",true);size=0;}
                if(writer is null)
                {
                    if(File.Exists(path)&&new FileInfo(path).Length>=limit)File.Move(path,path+".previous",true);
                    var stream=open?.Invoke(path)??new FileStream(path,FileMode.Append,FileAccess.Write,FileShare.ReadWrite);
                    size=stream.CanSeek?stream.Length:0;
                    writer=new StreamWriter(stream,Encoding){AutoFlush=true};
                }
                writer.Write(text);size+=Encoding.GetByteCount(text);
            }
            catch(IOException){Drop();retryAt=Now+retryDelay;}
            catch(UnauthorizedAccessException){Drop();retryAt=Now+retryDelay;}
        }
    }
    public override void Write(char value)=>Append(value.ToString());
    public override void Write(string? value){if(value is not null)Append(value);}
    public override void Write(char[] buffer,int index,int count)=>Append(new string(buffer,index,count));
    public override void WriteLine(string? value)=>Append(DateTimeOffset.Now.ToString("O")+" "+value+NewLine);
    public override void WriteLine()=>Append(NewLine);
    protected override void Dispose(bool disposing)
    {lock(gate){disposed=true;Drop();}base.Dispose(disposing);}
}
