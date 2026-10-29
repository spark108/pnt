using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Pnt;

static class RelayChecks
{
    public static async Task Main()
    {
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var connections=new ConcurrentBag<TcpClient>();
        var received=Channel.CreateUnbounded<byte[]>();
        var selected=Channel.CreateUnbounded<string>();
        int online=1,backup=0;
        TcpClient? primaryConnection=null;
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
        async Task<Peer?> Connect(string? avoid,CancellationToken token)
        {
            if(Volatile.Read(ref online)==0)throw new IOException("Network unavailable");
            var id=avoid=="primary"?"backup":"primary";
            var outgoing=new TcpClient();
            await outgoing.ConnectAsync(IPAddress.Loopback,((IPEndPoint)listener.LocalEndpoint).Port,token);
            var incoming=await listener.AcceptTcpClientAsync(token);connections.Add(incoming);
            if(id=="primary")Interlocked.CompareExchange(ref primaryConnection,incoming,null);
            _=Task.Run(async()=>
            {
                try{while(!stop.IsCancellationRequested){var packet=await VpnDatagrams.Read(incoming.GetStream(),stop.Token);await VpnDatagrams.Write(incoming.GetStream(),packet,stop.Token);}}
                catch(Exception)when(stop.IsCancellationRequested||!incoming.Connected){}
                catch(IOException){}catch(ObjectDisposedException){}
            });
            if(id=="backup")Interlocked.Increment(ref backup);
            return new Peer(outgoing.GetStream(),"test",id);
        }
        var relay=new VpnRelay(Connect,p=>selected.Writer.TryWrite(p.RemoteId));
        var run=relay.Run(packet=>{received.Writer.TryWrite(packet);return Task.CompletedTask;},stop.Token);
        async Task Packet(byte value)
        {
            relay.Send([value]);
            var data=await received.Reader.ReadAsync(stop.Token);
            if(data.Length!=1||data[0]!=value)throw new Exception("Packet corrupted during relay transition");
        }
        try
        {
            relay.Enable();await Packet(1);
            if(await selected.Reader.ReadAsync(stop.Token)!="primary")throw new Exception("Initial relay mismatch");
            while(Volatile.Read(ref backup)==0)await Task.Delay(50,stop.Token);
            await Task.Delay(200,stop.Token);
            primaryConnection!.Dispose();
            if(await selected.Reader.ReadAsync(stop.Token)!="backup")throw new Exception("Warm standby not promoted");
            await Packet(2);
            Interlocked.Exchange(ref online,0);
            foreach(var connection in connections)connection.Dispose();
            await Task.Delay(700,stop.Token);
            if(run.IsCompleted)throw new Exception("Relay outage terminated the VPN transport");
            Interlocked.Exchange(ref online,1);
            await Packet(3);
            Console.WriteLine("PASS: framed data survives standby promotion and a complete relay outage without terminating the session.");
        }
        finally
        {
            stop.Cancel();try{await run;}catch(OperationCanceledException){}
            foreach(var connection in connections)connection.Dispose();listener.Stop();
        }
    }
}
