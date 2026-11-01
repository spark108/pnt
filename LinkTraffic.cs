using System.Collections.Concurrent;
using System.Diagnostics;

namespace Pnt;

record LinkTrafficReport(string Source,string Target,double SentBytesPerSecond,double ReceivedBytesPerSecond,long Updated,long IntervalMs);

static class LinkTraffic
{
    static readonly ConcurrentDictionary<string,Func<string,string,bool>> authorized=new();
    static readonly ConcurrentDictionary<(string Self,string Remote),Counter> counters=new();
    internal static void Register(string self,Func<string,string,bool> check)=>authorized[self]=check;
    internal static Stream Wrap(Stream stream,string self,string remote,string fingerprint,bool leaveOpen=false)
    {
        if(self==remote||!authorized.TryGetValue(self,out var check))return stream;
        long nextCheck=0;
        Counter? Acquire()
        {
            var now=Stopwatch.GetTimestamp();var previous=Interlocked.Read(ref nextCheck);
            if(now<previous||Interlocked.CompareExchange(ref nextCheck,now+Stopwatch.Frequency,previous)!=previous)return null;
            try{return check(remote,fingerprint)?counters.GetOrAdd((self,remote),p=>new(p.Self,p.Remote,now)):null;}
            catch{return null;}
        }
        return new MeteredStream(stream,Acquire,leaveOpen);
    }
    internal static IEnumerable<LinkTrafficReport> Sample(string self,IReadOnlySet<string> members)
    {
        var now=Stopwatch.GetTimestamp();var utc=App.Now;
        foreach(var pair in counters.Where(p=>p.Key.Self==self))
        {
            if(!members.Contains(pair.Key.Remote)){counters.TryRemove(pair.Key,out _);continue;}
            if(pair.Value.Sample(now,utc) is {} sample)yield return sample;
        }
    }
    internal sealed class Counter(string source,string target,long started)
    {
        long sent,received,previousSent,previousReceived,previousTime=started;
        readonly object gate=new();
        internal void Add(long read,long written){Interlocked.Add(ref received,read);Interlocked.Add(ref sent,written);}
        internal LinkTrafficReport? Sample(long now,long utc)
        {
            lock(gate)
            {
                var seconds=(now-previousTime)/(double)Stopwatch.Frequency;
                if(seconds<1)return null;
                var currentSent=Interlocked.Read(ref sent);var currentReceived=Interlocked.Read(ref received);
                var tx=(currentSent-previousSent)/seconds;var rx=(currentReceived-previousReceived)/seconds;
                previousTime=now;previousSent=currentSent;previousReceived=currentReceived;
                return seconds>30?null:new(source,target,tx,rx,utc,(long)(seconds*1000));
            }
        }
    }
    internal sealed class MeteredStream(Stream inner,Func<Counter?> acquire,bool leaveOpen=false):Stream
    {
        int disposed;Counter? counter=acquire();
        void Count(long read,long written){counter??=acquire();counter?.Add(read,written);}
        public override bool CanRead=>inner.CanRead;
        public override bool CanWrite=>inner.CanWrite;
        public override bool CanSeek=>inner.CanSeek;
        public override long Length=>inner.Length;
        public override long Position{get=>inner.Position;set=>inner.Position=value;}
        public override void Flush()=>inner.Flush();
        public override Task FlushAsync(CancellationToken token)=>inner.FlushAsync(token);
        public override long Seek(long offset,SeekOrigin origin)=>inner.Seek(offset,origin);
        public override void SetLength(long value)=>inner.SetLength(value);
        public override int Read(byte[] buffer,int offset,int count){var n=inner.Read(buffer,offset,count);Count(n,0);return n;}
        public override int Read(Span<byte> buffer){var n=inner.Read(buffer);Count(n,0);return n;}
        public override Task<int> ReadAsync(byte[] buffer,int offset,int count,CancellationToken token)=>ReadAsync(buffer.AsMemory(offset,count),token).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default)
        {var n=await inner.ReadAsync(buffer,token);Count(n,0);return n;}
        public override void Write(byte[] buffer,int offset,int count){inner.Write(buffer,offset,count);Count(0,count);}
        public override void Write(ReadOnlySpan<byte> buffer){inner.Write(buffer);Count(0,buffer.Length);}
        public override Task WriteAsync(byte[] buffer,int offset,int count,CancellationToken token)=>WriteAsync(buffer.AsMemory(offset,count),token).AsTask();
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,CancellationToken token=default)
        {await inner.WriteAsync(buffer,token);Count(0,buffer.Length);}
        protected override void Dispose(bool disposing)
        {
            if(disposing&&Interlocked.Exchange(ref disposed,1)==0&&!leaveOpen&&!QuicTransport.DisposeStream(inner))inner.Dispose();
            base.Dispose(disposing);
        }
        public override async ValueTask DisposeAsync()
        {
            if(Interlocked.Exchange(ref disposed,1)==0&&!leaveOpen&&!QuicTransport.DisposeStream(inner))await inner.DisposeAsync();
            GC.SuppressFinalize(this);
        }
    }
}
