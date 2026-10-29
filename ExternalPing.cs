using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Pnt;

record ExternalPingMeasurement(string? Ip, double? Ms, string? Error);
record NodeExternalPing(Node Node, string[]? Route, ExternalPingMeasurement Measurement);

static class ExternalPing
{
    public static async Task<int> Run(Store db, X509Certificate2 cert, string host)
    {
        if (db.Get("cluster") is null || db.Get("left") == "1" || db.Self()?.Removed == true)
            throw new Exception("Узел не состоит в активном кластере.");
        ValidateHost(host);
        var self = db.Self()!;
        var nodes = db.Nodes().Where(x => !x.Removed).OrderBy(x => x.Name).ToArray();
        Console.WriteLine($"Пинг {host} с {nodes.Length} узлов кластера...");
        var results = await Task.WhenAll(nodes.Select(node => Query(db, cert, self, node, host)));
        foreach (var result in results)
        {
            var route = FormatRelay(db, result.Route);
            var measurement = result.Measurement;
            var value = measurement.Ms is double ms
                ? $"{ms:0.0} ms до {measurement.Ip}{route}"
                : $"{measurement.Error ?? "нет ответа"}{route}";
            Console.WriteLine($"{result.Node.Id}  {result.Node.Name,-20} {result.Node.Ip,-16} {value}");
        }
        var best = results.Where(x => x.Measurement.Ms.HasValue)
            .OrderBy(x => x.Measurement.Ms).FirstOrDefault();
        if (best is null)
        {
            Console.WriteLine("Ни один узел не получил ответ ICMP.");
            return 1;
        }
        Console.WriteLine($"Минимальный пинг: {best.Node.Name} ({best.Node.Id}) — " +
            $"{best.Measurement.Ms:0.0} ms до {best.Measurement.Ip}{FormatRelay(db, best.Route)}");
        return 0;
    }

    static string FormatRelay(Store db, string[]? route)
    {
        if (route is not { Length: > 2 }) return "";
        return " через " + string.Join(" → ", route.Skip(1).SkipLast(1)
            .Select(id => db.Nodes().FirstOrDefault(x => x.Id == id)?.Name ?? id));
    }

    internal static async Task<NodeExternalPing> Query(Store db, X509Certificate2 cert, Node self, Node node, string host, bool tcp = false)
    {
        if (node.Id == self.Id)
            return new NodeExternalPing(node, [self.Id], tcp ? await Management.CheckSsh(host) : await Measure(host));
        var lastError = "нет маршрута к узлу";
        foreach (var relay in RoutePlanner.Candidates(db, self.Id, node.Id, []))
        {
            try
            {
                using var peer = await Peer.Connect(relay.Ip, relay.Cert, cert);
                await Peer.Send(peer.Stream, new Message(tcp ? "tcp-check" : "ping-external", self.Id, Target: node.Id,
                    Hops: [self.Id], Host: host)).WaitAsync(TimeSpan.FromSeconds(10));
                var ready = await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(45));
                if (ready?.Type != "ready")
                {
                    lastError = ready?.Error ?? "узел не ответил";
                    continue;
                }
                var answer = await Peer.Read(peer.Stream).WaitAsync(TimeSpan.FromSeconds(15));
                if (answer?.Type != "ping-result")
                {
                    lastError = answer?.Error ?? "нет результата пинга";
                    continue;
                }
                if (answer.PingMs is double value && (!double.IsFinite(value) || value < 0))
                {
                    lastError = "недопустимый результат пинга";
                    continue;
                }
                return new NodeExternalPing(node, ready.Hops,
                    new ExternalPingMeasurement(answer.Ip, answer.PingMs, answer.Error));
            }
            catch (Exception e) { lastError = e.GetBaseException().Message; }
        }
        return new NodeExternalPing(node, null, new ExternalPingMeasurement(null, null, lastError));
    }

    public static async Task<ExternalPingMeasurement> Measure(string host)
    {
        try
        {
            ValidateHost(host);
            IPAddress address;
            if (IPAddress.TryParse(host, out var literal)) address = literal;
            else
            {
                var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(TimeSpan.FromSeconds(5));
                address = addresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork)
                    ?? throw new Exception("Домен не имеет IPv4 адреса.");
            }
            var samples = new List<long>();
            var lastStatus = "нет ответа ICMP";
            for (var attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(address, 1500).WaitAsync(TimeSpan.FromSeconds(2));
                    if (reply.Status == IPStatus.Success) samples.Add(reply.RoundtripTime);
                    else lastStatus = "ICMP: " + reply.Status;
                }
                catch (TimeoutException) { lastStatus = "таймаут ICMP"; }
                catch (PingException e) { lastStatus = "ICMP: " + e.GetBaseException().Message; }
            }
            return samples.Count > 0
                ? new ExternalPingMeasurement(address.ToString(), samples.Average(), null)
                : new ExternalPingMeasurement(address.ToString(), null, lastStatus);
        }
        catch (Exception e) { return new ExternalPingMeasurement(null, null, e.GetBaseException().Message); }
    }

    static void ValidateHost(string host)
    {
        if (host.Length is < 1 or > 253 || host.Any(char.IsWhiteSpace))
            throw new Exception("Укажите IPv4 адрес или домен.");
        if (IPAddress.TryParse(host, out var ip))
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) throw new Exception("Поддерживаются только IPv4 адреса.");
        }
        else if (Uri.CheckHostName(host) != UriHostNameType.Dns)
            throw new Exception("Укажите IPv4 адрес или домен.");
    }
}
