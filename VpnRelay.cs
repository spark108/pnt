using System.Threading.Channels;

namespace Pnt;

sealed class VpnRelay
{
    readonly Func<string?,CancellationToken,Task<Peer?>> connect;
    readonly Action<Peer> changed;
    readonly object gate=new();
    readonly Channel<(byte[] Data,long Created)> pending=Channel.CreateBounded<(byte[],long)>(new BoundedChannelOptions(128){FullMode=BoundedChannelFullMode.DropOldest,SingleReader=true});
    readonly HashSet<Task> readers=new();
    Peer? active,standby;
    string? failed;
    int enabled;

    public VpnRelay(Func<string?,CancellationToken,Task<Peer?>> connect,Action<Peer> changed){this.connect=connect;this.changed=changed;}
    public bool Enabled=>Volatile.Read(ref enabled)!=0;
    public void Enable(byte[]? first=null){if(Interlocked.Exchange(ref enabled,1)==0&&first!=null)Send(first);}
    public void Send(byte[] packet)=>pending.Writer.TryWrite((packet,Environment.TickCount64));

    public async Task Run(Func<byte[],Task> receive,CancellationToken cancellation)
    {
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        var token=stop.Token;
        void Activate(Peer peer){changed(peer);}
        void Remove(Peer peer)
        {
            Peer? replacement=null;
            lock(gate)
            {
                if(ReferenceEquals(active,peer)){failed=peer.RemoteId;active=standby;standby=null;replacement=active;}
                else if(ReferenceEquals(standby,peer))standby=null;
            }
            try{peer.Dispose();}catch(IOException){}
            if(replacement!=null)Activate(replacement);
        }
        async Task Read(Peer peer)
        {
            try
            {
                while(!token.IsCancellationRequested)
                {
                    var packet=await VpnDatagrams.Read(peer.Stream,token);
                    bool current;lock(gate)current=ReferenceEquals(active,peer);
                    if(current)await receive(packet);
                }
            }
            catch(Exception){if(!token.IsCancellationRequested)Remove(peer);}
        }
        async Task Maintain()
        {
            while(!token.IsCancellationRequested)
            {
                Peer? current,backup;lock(gate){current=active;backup=standby;}
                if(Enabled&&(current==null||backup==null))
                {
                    async Task<Peer?> TryConnect(string? avoid)
                    {
                        try
                        {
                            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(8));
                            return await connect(avoid,timeout.Token);
                        }
                        catch(Exception)when(!token.IsCancellationRequested){return null;}
                    }
                    var peer=await TryConnect(current?.RemoteId??failed);
                    if(peer==null&&current==null&&!token.IsCancellationRequested)peer=await TryConnect(null);
                    if(peer!=null)
                    {
                        bool selected=false,accepted=false;
                        lock(gate)
                        {
                            if(!token.IsCancellationRequested)
                            {
                                if(active==null){active=peer;selected=accepted=true;}
                                else if(standby==null&&active.RemoteId!=peer.RemoteId){standby=peer;accepted=true;}
                            }
                        }
                        if(accepted)
                        {
                            var reader=Read(peer);lock(gate)readers.Add(reader);
                            _=reader.ContinueWith(task=>{lock(gate)readers.Remove(task);},TaskScheduler.Default);
                            if(selected)Activate(peer);
                        }
                        else peer.Dispose();
                    }
                }
                await Task.Delay(500,token);
            }
        }
        async Task Write()
        {
            await foreach(var packet in pending.Reader.ReadAllAsync(token))
            {
                while(!token.IsCancellationRequested&&Environment.TickCount64-packet.Created<5000)
                {
                    Peer? peer;lock(gate)peer=active;
                    if(peer==null){await Task.Delay(50,token);continue;}
                    try
                    {
                        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(2));
                        await VpnDatagrams.Write(peer.Stream,packet.Data,timeout.Token);break;
                    }
                    catch(Exception)when(!token.IsCancellationRequested){Remove(peer);}
                }
            }
        }
        var tasks=new[]{Maintain(),Write()};
        try{await Task.WhenAll(tasks);}
        finally
        {
            stop.Cancel();lock(gate){active?.Dispose();standby?.Dispose();active=standby=null;}
            Task[] remaining;lock(gate)remaining=readers.ToArray();
            try{await Task.WhenAll(remaining);}catch(Exception)when(stop.IsCancellationRequested){}
        }
    }
}
