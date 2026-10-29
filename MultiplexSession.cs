using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Pnt;

sealed class MultiplexSession(Peer raw, bool client, Func<Stream, Task> accept)
{
    const byte OpenFrame=0, DataFrame=1, FinFrame=2, ResetFrame=3, WindowFrame=4, PingFrame=5, PongFrame=6;
    const int Chunk=16*1024, Window=8;
    readonly ConcurrentDictionary<int, LogicalStream> streams = new();
    readonly SemaphoreSlim writer = new(1,1);
    readonly CancellationTokenSource stop = new();
    readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    int nextId = client ? -1 : 0;
    long lastRead = Environment.TickCount64;
    public bool Alive => !stop.IsCancellationRequested;
    public string Fingerprint => raw.RemoteFingerprint;
    public string RemoteId => raw.RemoteId;
    public Task Completion => completion.Task;

    public void Start() { _ = ReadLoop(); _ = KeepAlive(); }
    public async Task<Stream> Open(CancellationToken token)
    {
        if (!Alive || streams.Count>=1024) throw new IOException("Канал перегружен или закрыт.");
        var id=Interlocked.Add(ref nextId,2);
        var stream=new LogicalStream(this,id);
        if (!streams.TryAdd(id,stream)) throw new IOException("ID потока уже занят.");
        try { await Send(OpenFrame,id,ReadOnlyMemory<byte>.Empty,token); return stream; }
        catch { stream.Abort(); throw; }
    }

    async Task Send(byte type, int id, ReadOnlyMemory<byte> payload, CancellationToken token = default)
    {
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,stop.Token);
        await writer.WaitAsync(linked.Token);
        try
        {
            var header=new byte[9];header[0]=type;
            BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(1),id);
            BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5),payload.Length);
            await raw.Stream.WriteAsync(header,linked.Token);
            if (!payload.IsEmpty) await raw.Stream.WriteAsync(payload,linked.Token);
        }
        catch { Close(); throw; }
        finally { writer.Release(); }
    }

    async Task ReadLoop()
    {
        try
        {
            var header=new byte[9];
            while(Alive)
            {
                await raw.Stream.ReadExactlyAsync(header,stop.Token);
                var type=header[0];var id=BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
                var size=BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5));
                if(size<0||size>Chunk||type>6||type!=DataFrame&&size!=0) throw new IOException("Недопустимый кадр канала.");
                var payload=new byte[size];
                if(size>0) await raw.Stream.ReadExactlyAsync(payload,stop.Token);
                Interlocked.Exchange(ref lastRead,Environment.TickCount64);
                if(type==PingFrame){await Send(PongFrame,0,ReadOnlyMemory<byte>.Empty);continue;}
                if(type==PongFrame)continue;
                if(type==OpenFrame)
                {
                    if(id<=0||id%2!=(client?0:1)||streams.Count>=1024)throw new IOException("Недопустимое открытие потока.");
                    var created=new LogicalStream(this,id);
                    if(!streams.TryAdd(id,created))throw new IOException("Повторный ID потока.");
                    _=Task.Run(async()=>{try{await accept(created);}catch{created.Dispose();}});
                    continue;
                }
                if(!streams.TryGetValue(id,out var stream))continue;
                switch(type)
                {
                    case DataFrame:if(!stream.Receive(payload)){stream.Abort();await Send(ResetFrame,id,ReadOnlyMemory<byte>.Empty);}break;
                    case FinFrame:stream.End();break;
                    case ResetFrame:stream.Abort();break;
                    case WindowFrame:stream.Grant();break;
                }
            }
        }
        catch { }
        finally { Close(); }
    }

    async Task KeepAlive()
    {
        try
        {
            while(Alive)
            {
                await Task.Delay(15_000,stop.Token);
                if(Environment.TickCount64-Interlocked.Read(ref lastRead)>45_000) {Close();break;}
                await Send(PingFrame,0,ReadOnlyMemory<byte>.Empty);
            }
        }
        catch { Close(); }
    }

    public void Close()
    {
        if(stop.IsCancellationRequested)return;
        stop.Cancel();raw.Dispose();
        foreach(var stream in streams.Values)stream.Abort();
        completion.TrySetResult();
    }

    sealed class LogicalStream(MultiplexSession session,int id) : Stream
    {
        readonly Channel<byte[]> incoming=Channel.CreateBounded<byte[]>(new BoundedChannelOptions(Window){SingleReader=true,SingleWriter=true});
        readonly SemaphoreSlim credits=new(Window,Window);
        readonly CancellationTokenSource closed=new();
        readonly CancellationTokenSource remoteEnded=new();
        byte[]? buffer;
        int offset;
        int disposed;
        public bool Receive(byte[] data)=>incoming.Writer.TryWrite(data);
        public void End(){incoming.Writer.TryComplete();remoteEnded.Cancel();}
        public void Grant(){try{credits.Release();}catch(SemaphoreFullException){Abort();}}
        public void Abort()
        {
            closed.Cancel();incoming.Writer.TryComplete(new IOException("Поток закрыт."));session.streams.TryRemove(id,out _);
        }
        public override async ValueTask<int> ReadAsync(Memory<byte> destination,CancellationToken token=default)
        {
            if(destination.IsEmpty)return 0;
            using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,closed.Token);
            if(buffer is null)
            {
                if(!await incoming.Reader.WaitToReadAsync(linked.Token))return 0;
                if(!incoming.Reader.TryRead(out buffer))return 0;
                offset=0;
            }
            var count=Math.Min(destination.Length,buffer.Length-offset);
            buffer.AsMemory(offset,count).CopyTo(destination);offset+=count;
            if(offset==buffer.Length){buffer=null;await session.Send(WindowFrame,id,ReadOnlyMemory<byte>.Empty,linked.Token);}
            return count;
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> data,CancellationToken token=default)
        {
            using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,closed.Token,remoteEnded.Token);
            while(!data.IsEmpty)
            {
                await credits.WaitAsync(linked.Token);
                var count=Math.Min(Chunk,data.Length);
                await session.Send(DataFrame,id,data[..count],linked.Token);data=data[count..];
            }
        }
        protected override void Dispose(bool disposing)
        {
            if(Interlocked.Exchange(ref disposed,1)!=0)return;
            session.streams.TryRemove(id,out _);closed.Cancel();incoming.Writer.TryComplete();
            _=Finish();
            async Task Finish(){try{await session.Send(FinFrame,id,ReadOnlyMemory<byte>.Empty);}catch{}}
            base.Dispose(disposing);
        }
        public override int Read(byte[] b,int o,int c)=>ReadAsync(b.AsMemory(o,c)).AsTask().GetAwaiter().GetResult();
        public override void Write(byte[] b,int o,int c)=>WriteAsync(b.AsMemory(o,c)).AsTask().GetAwaiter().GetResult();
        public override Task<int> ReadAsync(byte[] b,int o,int c,CancellationToken t)=>ReadAsync(b.AsMemory(o,c),t).AsTask();
        public override Task WriteAsync(byte[] b,int o,int c,CancellationToken t)=>WriteAsync(b.AsMemory(o,c),t).AsTask();
        public override void Flush(){} public override Task FlushAsync(CancellationToken t)=>Task.CompletedTask;
        public override bool CanRead=>disposed==0;public override bool CanWrite=>disposed==0;public override bool CanSeek=>false;
        public override long Length=>throw new NotSupportedException();public override long Position{get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override long Seek(long o,SeekOrigin s)=>throw new NotSupportedException();public override void SetLength(long v)=>throw new NotSupportedException();
    }
}
