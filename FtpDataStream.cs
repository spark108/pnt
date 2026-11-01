namespace Pnt;

sealed class FtpDataStream(Stream inner,CancellationTokenSource idle):Stream
{
    void Progress()=>idle.CancelAfter(TimeSpan.FromMinutes(3));
    public override bool CanRead=>inner.CanRead;
    public override bool CanWrite=>inner.CanWrite;
    public override bool CanSeek=>false;
    public override long Length=>throw new NotSupportedException();
    public override long Position{get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
    public override void Flush()=>inner.Flush();
    public override Task FlushAsync(CancellationToken token)=>inner.FlushAsync(token);
    public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
    public override void SetLength(long length)=>throw new NotSupportedException();
    public override int Read(byte[] buffer,int offset,int count){var n=inner.Read(buffer,offset,count);Progress();return n;}
    public override void Write(byte[] buffer,int offset,int count){inner.Write(buffer,offset,count);Progress();}
    public override Task<int> ReadAsync(byte[] buffer,int offset,int count,CancellationToken token)=>ReadAsync(buffer.AsMemory(offset,count),token).AsTask();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default){var n=await inner.ReadAsync(buffer,token);Progress();return n;}
    public override Task WriteAsync(byte[] buffer,int offset,int count,CancellationToken token)=>WriteAsync(buffer.AsMemory(offset,count),token).AsTask();
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,CancellationToken token=default){await inner.WriteAsync(buffer,token);Progress();}
}
