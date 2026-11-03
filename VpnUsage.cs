using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Data.Sqlite;

namespace Pnt;

record VpnUsageClient(string Client,long Connections,long Active,long Direct,long Relay,long Received,long Sent,long LastSeen);
record VpnUsageRoute(string Mode,string[] Route,long Connections,long Received,long Sent);
record VpnUsageNode(string Node,long Connections,long Clients,long Entry,long Transit,long Received,long Sent);
record VpnUsageReport(long Since,long Updated,VpnUsageClient[] Clients,VpnUsageRoute[] Routes,VpnUsageNode[] Nodes);

static class VpnUsage
{
    internal const long SessionGap=180_000;
    static readonly SemaphoreSlim sampling=new(1,1);
    static long nextSample;

    internal static async Task<Dictionary<string,VpnStatistics>> ReadClients(Store db,X509Certificate2 cert,CancellationToken token)
    {
        await sampling.WaitAsync(token);
        try
        {
            var raw=JsonSerializer.Deserialize<Dictionary<string,VpnStatistics>>(await VpnAdapter.Run("clients",null,[],token),App.Json)??[];
            var now=App.Now;
            var clients=raw.ToDictionary(p=>p.Key,p=>VpnConnections.Observe(Certificate.Id(cert),p.Key,p.Value,now/1000));
            Record(db,Certificate.Id(cert),clients,now);
            return clients;
        }
        finally{sampling.Release();}
    }
    internal static async Task Sample(Store db,X509Certificate2 cert,CancellationToken token)
    {
        if(!OperatingSystem.IsLinux()||Environment.TickCount64<Volatile.Read(ref nextSample)||db.Get("left")=="1"||db.Self()?.Removed!=false||!db.VpnServers().Any(s=>s.Id==db.Get("self")))return;
        Volatile.Write(ref nextSample,Environment.TickCount64+15_000);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try{await ReadClients(db,cert,timeout.Token);}
        catch(OperationCanceledException)when(token.IsCancellationRequested){}
        catch(Exception e){Console.Error.WriteLine("pnt: VPN usage: "+e.Message);}
    }

    internal static void Record(Store db,string node,IReadOnlyDictionary<string,VpnStatistics> samples,long now)
    {
        using var connection=db.Open();using var tx=connection.BeginTransaction(deferred:false);
        SqliteCommand Command(string sql,params (string,object?)[] values)
        {
            var command=connection.CreateCommand();command.Transaction=tx;command.CommandText=sql;
            foreach(var (key,value) in values)command.Parameters.AddWithValue(key,value??DBNull.Value);
            return command;
        }
        void Execute(string sql,params (string,object?)[] values){using var command=Command(sql,values);command.ExecuteNonQuery();}
        using(var latest=Command("SELECT v FROM meta WHERE k='vpn_usage_updated'"))
            if(long.TryParse(latest.ExecuteScalar() as string,out var recorded)&&now<=recorded){tx.Commit();return;}
        Execute("INSERT INTO meta(k,v) VALUES('vpn_usage_since',$now) ON CONFLICT(k) DO NOTHING",("$now",now.ToString()));
        var previous=new Dictionary<string,(long Time,long Rx,long Tx,string? Session)>();
        using(var command=Command("SELECT client,observed,received,sent,session FROM vpn_usage_state"))
        using(var reader=command.ExecuteReader())
            while(reader.Read())previous[reader.GetString(0)]=(reader.GetInt64(1),reader.GetInt64(2),reader.GetInt64(3),reader.IsDBNull(4)?null:reader.GetString(4));
        foreach(var client in samples.Keys.Union(previous.Keys))
        {
            if(client.Length!=16||!client.All(Uri.IsHexDigit))continue;
            var known=previous.TryGetValue(client,out var old);if(known&&now<=old.Time)continue;
            samples.TryGetValue(client,out var stats);
            var connected=stats is {Exists:true,Connected:true};
            var rx=Math.Max(0,stats?.Received??old.Rx);var sent=Math.Max(0,stats?.Sent??old.Tx);
            var deltaRx=known&&stats?.Exists==true?(rx>=old.Rx?rx-old.Rx:rx):0;
            var deltaTx=known&&stats?.Exists==true?(sent>=old.Tx?sent-old.Tx:sent):0;
            var session=old.Session;
            if(session is not null&&(!connected||now-old.Time>SessionGap))
            {
                Execute("UPDATE vpn_usage_sessions SET ended=last_seen WHERE id=$id AND ended=0",("$id",session));session=null;
            }
            if(connected)
            {
                var mode=stats!.Mode=="relay"?"relay":"direct";
                var path=mode=="relay"?stats.Route??[node]:[node];
                if(path.Length is <1 or >10||path[^1]!=node||path.Distinct().Count()!=path.Length||path.Any(n=>n.Length!=16||!n.All(Uri.IsHexDigit)))throw new IOException("Недопустимый маршрут статистики VPN.");
                if(session is null)
                {
                    session=Guid.NewGuid().ToString("N");
                    Execute("INSERT INTO vpn_usage_sessions(id,client,started,last_seen) VALUES($id,$client,$now,$now)",("$id",session),("$client",client),("$now",now));
                }
                Execute("UPDATE vpn_usage_sessions SET last_seen=$now,received=received+$rx,sent=sent+$tx WHERE id=$id",("$id",session),("$now",now),("$rx",deltaRx),("$tx",deltaTx));
                Execute("INSERT INTO vpn_usage_paths VALUES($id,$mode,$route,$now,$now,$rx,$tx) ON CONFLICT(session,mode,route) DO UPDATE SET last_seen=excluded.last_seen,received=received+excluded.received,sent=sent+excluded.sent",
                    ("$id",session),("$mode",mode),("$route",JsonSerializer.Serialize(path,App.Json)),("$now",now),("$rx",deltaRx),("$tx",deltaTx));
            }
            Execute("INSERT INTO vpn_usage_state VALUES($client,$now,$rx,$tx,$session) ON CONFLICT(client) DO UPDATE SET observed=excluded.observed,received=excluded.received,sent=excluded.sent,session=excluded.session",
                ("$client",client),("$now",now),("$rx",rx),("$tx",sent),("$session",session));
        }
        Execute("INSERT INTO meta(k,v) VALUES('vpn_usage_updated',$now) ON CONFLICT(k) DO UPDATE SET v=excluded.v",("$now",now.ToString()));
        tx.Commit();
    }

    internal static VpnUsageReport Read(Store db,long now)
    {
        using var connection=db.Open();using var tx=connection.BeginTransaction(deferred:true);
        SqliteCommand Command(string sql)
        {var command=connection.CreateCommand();command.Transaction=tx;command.CommandText=sql;command.Parameters.AddWithValue("$minimum",now-SessionGap);return command;}
        var clients=new List<VpnUsageClient>();var routes=new List<VpnUsageRoute>();var nodes=new List<VpnUsageNode>();long since=0,updated=0;
        using(var command=Command("SELECT v FROM meta WHERE k='vpn_usage_since'"))long.TryParse(command.ExecuteScalar() as string,out since);
        using(var command=Command("SELECT v FROM meta WHERE k='vpn_usage_updated'"))long.TryParse(command.ExecuteScalar() as string,out updated);
        using(var command=Command("SELECT client,count(*),sum(ended=0 AND last_seen>=$minimum),sum(EXISTS(SELECT 1 FROM vpn_usage_paths p WHERE p.session=s.id AND mode='direct')),sum(EXISTS(SELECT 1 FROM vpn_usage_paths p WHERE p.session=s.id AND mode='relay')),sum(received),sum(sent),max(last_seen) FROM vpn_usage_sessions s GROUP BY client ORDER BY count(*) DESC,client"))
        using(var reader=command.ExecuteReader())while(reader.Read())clients.Add(new(reader.GetString(0),reader.GetInt64(1),reader.GetInt64(2),reader.GetInt64(3),reader.GetInt64(4),reader.GetInt64(5),reader.GetInt64(6),reader.GetInt64(7)));
        using(var command=Command("SELECT mode,route,count(*),sum(received),sum(sent) FROM vpn_usage_paths GROUP BY mode,route ORDER BY count(*) DESC,mode,route"))
        using(var reader=command.ExecuteReader())while(reader.Read())routes.Add(new(reader.GetString(0),JsonSerializer.Deserialize<string[]>(reader.GetString(1),App.Json)!,reader.GetInt64(2),reader.GetInt64(3),reader.GetInt64(4)));
        using(var command=Command("SELECT j.value,count(DISTINCT p.session),count(DISTINCT s.client),count(DISTINCT CASE WHEN j.key=0 THEN p.session END),count(DISTINCT CASE WHEN j.key>0 THEN p.session END),sum(p.received),sum(p.sent) FROM vpn_usage_paths p JOIN vpn_usage_sessions s ON s.id=p.session JOIN json_each(p.route) j WHERE p.mode='relay' AND (j.key=0 OR j.key<json_array_length(p.route)-1) GROUP BY j.value ORDER BY count(DISTINCT p.session) DESC,j.value"))
        using(var reader=command.ExecuteReader())while(reader.Read())nodes.Add(new(reader.GetString(0),reader.GetInt64(1),reader.GetInt64(2),reader.GetInt64(3),reader.GetInt64(4),reader.GetInt64(5),reader.GetInt64(6)));
        tx.Commit();return new(since,updated,clients.ToArray(),routes.ToArray(),nodes.ToArray());
    }

    internal static void Print(Store db,VpnUsageReport report,long now)
    {
        var nodeNames=db.Nodes().ToDictionary(n=>n.Id,n=>n.Name);
        var clientNames=db.VpnClients().ToDictionary(c=>c.Id,c=>c.Name);
        string Date(long value)=>value==0?"—":DateTimeOffset.FromUnixTimeMilliseconds(value).ToString("u");
        string Bytes(long value)=>$"{value:N0} Б";
        string NodeName(string id)=>nodeNames.GetValueOrDefault(id,id);
        string ClientName(string id)=>clientNames.GetValueOrDefault(id,id);
        Console.WriteLine("Накопительная статистика подключений (наблюдения AmneziaWG)");
        CliOutput.Table(["С начала (UTC)","Последний замер (UTC)","Подключений","Клиентов","Активно","Принято сервером","Отправлено сервером"],[[Date(report.Since),Date(report.Updated),report.Clients.Sum(c=>c.Connections).ToString(),report.Clients.Length.ToString(),report.Clients.Sum(c=>c.Active).ToString(),Bytes(report.Clients.Sum(c=>c.Received)),Bytes(report.Clients.Sum(c=>c.Sent))]]);
        if(report.Since==0){Console.WriteLine("Наблюдения ещё не собраны службой выходного VPN-узла.");return;}
        if(report.Updated==0||now-report.Updated>60_000)Console.WriteLine("Замеры устарели или недоступны; исторические данные сохранены.");
        if(report.Clients.Length==0){Console.WriteLine("VPN-подключения пока не наблюдались.");return;}
        CliOutput.Table(["Способ","Подключений"],[[CliOutput.Mode("прямое"),report.Clients.Sum(c=>c.Direct).ToString()],[CliOutput.Mode("транспорт"),report.Clients.Sum(c=>c.Relay).ToString()]]);
        CliOutput.Table(["ID клиента","Имя","Подключений","Активно","Прямое","Транспорт","Принято","Отправлено","Последний раз (UTC)"],report.Clients.Select(c=>new CliCell[]{c.Client,ClientName(c.Client),c.Connections.ToString(),c.Active.ToString(),c.Direct.ToString(),c.Relay.ToString(),Bytes(c.Received),Bytes(c.Sent),Date(c.LastSeen)}));
        CliOutput.Table(["Способ","Подключений","Принято","Отправлено","Маршрут (имя / ID)"],report.Routes.Select(r=>new CliCell[]{CliOutput.Mode(r.Mode=="relay"?"транспорт":"прямое"),r.Connections.ToString(),Bytes(r.Received),Bytes(r.Sent),string.Join(" → ",r.Route.Select(id=>NodeName(id)+" / "+id))}));
        if(report.Nodes.Length>0)CliOutput.Table(["ID узла","Узел","Подключений","Клиентов","Вход","Транзит","Принято","Отправлено"],report.Nodes.Select(n=>new CliCell[]{n.Node,NodeName(n.Node),n.Connections.ToString(),n.Clients.ToString(),n.Entry.ToString(),n.Transit.ToString(),Bytes(n.Received),Bytes(n.Sent)}));
        Console.WriteLine("Опрос каждые 15 с; перерыв более 180 с означает новое подключение. Способы и маршруты одного сеанса могут пересекаться. Трафик — с начала наблюдений; распределение по маршрутам приблизительное.");
    }
}
