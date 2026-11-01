using System.Diagnostics;
namespace Pnt;
static class TrafficChecks
{
    static void Assert(bool value,string message){if(!value)throw new Exception(message);}
    public static async Task Main()
    {
        const string a="aaaaaaaaaaaaaaaa",b="bbbbbbbbbbbbbbbb";
        var counter=new LinkTraffic.Counter(a,b,0);counter.Add(1000,2000);
        Assert(counter.Sample(Stopwatch.Frequency/2,App.Now) is null,"Counter published an unstable short interval");
        var sample=counter.Sample(2*Stopwatch.Frequency,App.Now)!;
        Assert(sample.SentBytesPerSecond==1000&&sample.ReceivedBytesPerSecond==500&&sample.IntervalMs==2000,"Bytes/second calculation failed");
        var idle=counter.Sample(4*Stopwatch.Frequency,App.Now)!;Assert(idle.SentBytesPerSecond==0&&idle.ReceivedBytesPerSecond==0,"Idle link retained old speed");
        counter.Add(50,50);Assert(counter.Sample(40*Stopwatch.Frequency,App.Now) is null,"Long-pause traffic was published as a fresh rate");
        var streamCounter=new LinkTraffic.Counter(a,b,0);
        using(var bytes=new MemoryStream(new byte[64]))
        using(var stream=new LinkTraffic.MeteredStream(bytes,()=>streamCounter,true))
        {
            Assert(await stream.ReadAsync(new byte[5])==5&&stream.Read(new byte[3],0,3)==3,"Stream read was unexpectedly short");
            await stream.WriteAsync(new byte[7]);stream.Write(new byte[11],0,11);
        }
        var counted=streamCounter.Sample(Stopwatch.Frequency,App.Now)!;
        Assert(counted.ReceivedBytesPerSecond==8&&counted.SentBytesPerSecond==18,"Stream wrapper double counted or dropped I/O");
        var folder=Path.Combine(Path.GetTempPath(),"pnt-traffic-check-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);
        using var db=new Store(Path.Combine(folder,"node.db"));
        db.Put(new Node(a,"A","192.0.2.1",new string('A',64),App.Now));db.Put(new Node(b,"B","192.0.2.2",new string('B',64),App.Now));
        var report=new LinkTrafficReport(a,b,1000,2000,App.Now,5000);db.PutTraffic(report);
        foreach(var invalid in new[]{report with{SentBytesPerSecond=-1},report with{ReceivedBytesPerSecond=double.NaN},report with{Source=b,Target=b},report with{Target="unknown"},report with{Updated=App.Now-60000},report with{Updated=App.Now+120000},report with{IntervalMs=0}})db.PutTraffic(invalid);
        Assert(db.Traffic().Single()==report,"Invalid report overwrote measured throughput");
        db.PutTraffic(report with{SentBytesPerSecond=999,Updated=report.Updated-1});Assert(db.Traffic().Single()==report,"Stale gossip overwrote fresh speed");
        var json=System.Text.Json.JsonSerializer.Serialize(new Message("sync",Traffic:[report]),App.Json);
        Assert(System.Text.Json.JsonSerializer.Deserialize<Message>(json,App.Json)!.Traffic!.Single()==report,"Rates lost in cluster protocol");
        var enrolled=false;LinkTraffic.Register(a,(_,_)=>enrolled);
        using var raw=new MemoryStream();using var measured=LinkTraffic.Wrap(raw,a,b,new string('B',64),true);
        measured.Write(new byte[10]);Assert(!LinkTraffic.Sample(a,new HashSet<string>{b}).Any(),"Untrusted peer obtained a metrics entry");
        enrolled=true;await Task.Delay(1100);measured.Write(new byte[100]);await Task.Delay(1100);
        Assert(LinkTraffic.Sample(a,new HashSet<string>{b}).Single().SentBytesPerSecond>0,"Reverse enrollment channel did not start measuring after approval");
        Console.WriteLine("PASS: rates, idle/stale handling, byte counting, report validation, gossip serialization and reverse enrollment metrics.");
    }
}
