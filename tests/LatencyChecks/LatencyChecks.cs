using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Pnt;

static class LatencyChecks
{
    static void Assert(bool condition,string message) { if(!condition)throw new Exception(message); }

    static async Task Run(Func<Stream,Message,Task> respond,Func<Peer,Task> check)
    {
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
        using var client=new TcpClient {NoDelay=true};
        var accepted=listener.AcceptTcpClientAsync();
        await client.ConnectAsync(IPAddress.Loopback,((IPEndPoint)listener.LocalEndpoint).Port);
        using var server=await accepted;server.NoDelay=true;listener.Stop();
        using var peer=new Peer(client.GetStream(),"test","target");
        var serving=Task.Run(async()=>
        {
            var request=await Peer.Read(server.GetStream());
            Assert(request?.Type=="latency-open","Missing probe preparation");
            await respond(server.GetStream(),request!);
        });
        try {await check(peer);}finally {client.Dispose();}
        await serving.WaitAsync(TimeSpan.FromSeconds(5));
    }

    public static async Task Main()
    {
        await Run(async(stream,request)=>
        {
            await Task.Delay(400);
            await LatencyProbe.Reply(stream,request,"target",default);
        },async peer=>
        {
            var total=Stopwatch.StartNew();
            var rtt=await LatencyProbe.Measure(peer,"source","target");
            Assert(double.IsFinite(rtt)&&rtt>=0,"Invalid RTT");
            Assert(total.Elapsed.TotalMilliseconds-rtt>350,"Preparation included in RTT");
        });
        await Run(async(stream,request)=>
        {
            await Peer.Send(stream,new Message("latency-ready","target",RequestId:request.RequestId,ProbeCount:3));
            var nonce=new byte[16];
            foreach(var delay in new[]{20,300,20})
            {
                await stream.ReadExactlyAsync(nonce);await Task.Delay(delay);await stream.WriteAsync(nonce);
            }
        },async peer=>
        {
            var rtt=await LatencyProbe.Measure(peer,"source","target");
            Assert(rtt>=15&&rtt<200,"Median did not reject a delayed sample");
        });
        await Run(async(stream,request)=>
        {
            await Peer.Send(stream,new Message("latency-ready","target",RequestId:request.RequestId,ProbeCount:1));
            var nonce=new byte[16];await stream.ReadExactlyAsync(nonce);nonce[0]^=255;await stream.WriteAsync(nonce);
        },async peer=>
        {
            try {await LatencyProbe.Measure(peer,"source","target",samples:1);throw new Exception("Corrupt echo accepted");}
            catch(IOException){}
        });
        await Run(async(stream,request)=>
        {
            await Peer.Send(stream,new Message("latency-ready","wrong-target",RequestId:request.RequestId,ProbeCount:1));
        },async peer=>
        {
            try {await LatencyProbe.Measure(peer,"source","target",samples:1);throw new Exception("Wrong target accepted");}
            catch(IOException){}
        });
        await Run(async(stream,request)=>await Task.Delay(300),async peer=>
        {
            using var cancel=new CancellationTokenSource(80);
            try {await LatencyProbe.Measure(peer,"source","target",cancel.Token);throw new Exception("Cancellation ignored");}
            catch(OperationCanceledException){}
        });
        Console.WriteLine("PASS: internal nonce echo, preparation excluded, median RTT, corrupt echo and wrong target rejected, cancellation.");
    }
}
