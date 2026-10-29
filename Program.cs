using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Pnt;

record Node(string Id, string Name, string Ip, string Cert, long Version, bool Removed = false,
    bool Updating = false, long UpdatingSince = 0, bool BehindNat = false, string Platform = "linux");
record JoinRequest(string Id, string Name, string Ip, string ObservedIp, string Cert, string Platform, long Created, string Status = "pending", bool BehindNat = false);
record Rule(string Id, string In, int InPort, string? Via, string To, int ToPort, long Version, bool Removed = false,
    string InAddress = "0.0.0.0", string? InInterface = null, string? OutAddress = null, string? OutInterface = null);
record Invite(string Id, string Secret, string Ip, long Expires, bool Used = false);
record Token(string Cluster, string Host, string Cert, string Id, string Secret);
record UpdateNotice(string Id, string Commit, long Version);
record WebConfig(string Id, bool Enabled, string Salt, string Hash, long Version);
record PingReport(string Source, string Target, double Ms, long Updated, bool Direct = false, string[]? Route = null);
record Message(string Type, string? Id = null, string? Name = null, string? Ip = null, string? Cert = null,
    string? Secret = null, string? Target = null, int Port = 0, string? Via = null,
    string[]? Hops = null, Node[]? Nodes = null, Rule[]? Rules = null, string? Error = null, string? KeyHash = null,
    UpdateNotice? Update = null, PingReport[]? Pings = null, WebConfig? Web = null,
    string? Command = null, string? Output = null, bool Stderr = false, int ExitCode = 0,
    string? Host = null, double? PingMs = null, bool Interactive = false,
    string? RequestId = null, long Deadline = 0, string[][]? Routes = null, PingReport[]? Links = null,
    NodeInterface[]? Interfaces = null, string? OutAddress = null, string? OutInterface = null, string? Platform = null, bool BehindNat = false,
    VpnServer[]? VpnServers = null, VpnClient[]? VpnClients = null, string? VpnPayload = null);

static class App
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static readonly string Dir = Environment.GetEnvironmentVariable("PNT_DATA_DIR") ?? (OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"PNT","data") : "/var/lib/pnt");
    public static string ConfigDir => Environment.GetEnvironmentVariable("PNT_CONFIG_DIR") ?? (OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"PNT","config") : "/etc/pnt");
    public static string Platform => OperatingSystem.IsWindows() ? "windows" : "linux";
    public static long Now => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    internal static string OwnIp
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("PNT_ADVERTISE_IP");
            if (configured == null && File.Exists("/etc/default/pnt"))
            {
                var line = File.ReadLines("/etc/default/pnt").LastOrDefault(x => x.TrimStart().StartsWith("PNT_ADVERTISE_IP="));
                configured = line?.Split('=', 2)[1].Trim().Trim('"', '\'');
            }
            var ip = configured ?? Dns.GetHostAddresses(Dns.GetHostName()).FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(x))?.ToString() ?? "127.0.0.1";
            if (!IPAddress.TryParse(ip, out _)) throw new Exception("PNT_ADVERTISE_IP должен быть IP-адресом.");
            return ip;
        }
    }

    static async Task<int> Main(string[] a)
    {
        try
        {
            if(a is ["_vpn-client", .. var clientArgs])return await VpnClientAgent.Run(clientArgs);
            LocalAccess.Demand();
            if(a is ["_prepare-access"]){LocalAccess.Prepare();return 0;}
            if (a.Length == 0 || a[0] is "help" or "--help") { Help(); return 0; }
            if(a is ["install"] or ["update"])return await Management.Local(a[0]);
            if(OperatingSystem.IsWindows() && a is ["serve"])LocalAccess.Prepare();
            Directory.CreateDirectory(Dir);
            using var db = new Store(Path.Combine(Dir, "pnt.db"));
            var cert = Certificate.Load(Path.Combine(Dir, "node.pfx"));
            var me = Certificate.Id(cert);
            switch (a)
            {
                case ["vpn", .. var vpnArgs]: await VpnControl.Command(db,cert,vpnArgs);break;
                case ["install", "-r", var remoteHost]: return await Management.Remote(db, cert, remoteHost);
                case ["serve"]:
                    if (OperatingSystem.IsWindows() && !Environment.UserInteractive) WindowsServiceHost.Run(db,cert);
                    else await new Service(db, cert).Run(); break;
                case ["identity"]: Console.WriteLine(me); break;
                case ["identity", "--fingerprint"]: Console.WriteLine(Certificate.Fingerprint(cert));break;
                case ["connect", "status"]: Console.WriteLine($"Узел: {me}\nСервер: {db.Get("bootstrap_host")}\nСертификат сервера: {db.Get("bootstrap_pin:"+db.Get("bootstrap_host"))}\nКластер: {db.Get("cluster") ?? "ожидает подтверждения"}");break;
                case ["connect", "cluster", var host]:
                    if(db.Get("cluster") is not null) throw new Exception("Узел уже состоит в кластере.");
                    if(!IPAddress.TryParse(host,out var bootstrapIp) || bootstrapIp.AddressFamily!=AddressFamily.InterNetwork)throw new Exception("Укажите IPv4 действующего узла.");
                    db.Set("bootstrap_host",bootstrapIp.ToString());db.Set("bootstrap_name",Environment.MachineName);
                    db.Set("bootstrap_ip",OwnIp);Console.WriteLine("Заявка будет отправлена службой PNT. На действующем узле: pnt cluster requests, затем pnt cluster accept <id>. ID этого узла: "+me);break;
                case ["cluster", "requests"]:
                    Active(db);foreach(var request in Enrollment.Requests(db).Where(r=>r.Status=="pending"))Console.WriteLine($"{request.Id} {request.Name} {request.ObservedIp} {request.Platform} сертификат {request.Cert}");break;
                case ["cluster", "accept", var requestId]: Enrollment.Approve(db,requestId);Console.WriteLine("Заявка подтверждена.");break;
                case ["cluster", "reject", var requestId]: Enrollment.Reject(db,requestId);Console.WriteLine("Заявка отклонена.");break;
                case ["create", "cluster", var key]:
                    if (db.Get("cluster") != null) throw new Exception("Кластер уже создан или принят.");
                    db.Set("cluster", Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
                    db.Set("key_hash", Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))));
                    db.Set("self", me);
                    db.Put(new Node(me, Environment.MachineName, OwnIp, Certificate.Fingerprint(cert), Now, Platform:Platform));
                    Console.WriteLine($"Кластер создан. ID узла: {me}"); break;
                case ["cluster", "add", var ip]:
                    Active(db);
                    if (!IPAddress.TryParse(ip, out _)) throw new Exception("Ожидается IP-адрес.");
                    var inviteId = Guid.NewGuid().ToString("N");
                    var expires = Now + 3600_000;
                    var secret = Convert.ToBase64String(HMACSHA256.HashData(Convert.FromHexString(db.Get("key_hash")!), Encoding.UTF8.GetBytes($"{inviteId}:{ip}:{expires}")));
                    var inv = new Invite(inviteId, secret, ip, expires);
                    db.Invite(inv);
                    var invitationToken = new Token(db.Get("cluster")!, db.Self()!.Ip, Certificate.Fingerprint(cert), inv.Id, inv.Secret);
                    Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(invitationToken, Json)))); break;
                case ["accept", "cluster", var token]: await Accept(db, cert, token); break;
                case ["cluster", "remove", var node]:
                    Active(db);
                    var removed = db.Resolve(node) ?? throw new Exception("Узел не найден.");
                    if (removed.Id == me) throw new Exception("Используйте cluster leave.");
                    db.Put(removed with { Removed = true, Version = Now });
                    Console.WriteLine("Узел исключён."); break;
                case ["cluster", "leave"]:
                    Active(db); db.Put(db.Self()! with { Removed = true, Version = Now });
                    db.Set("left", "1"); Console.WriteLine("Выход зарегистрирован."); break;
                case ["cluster", "nodes"]: PrintNodes(db, null); break;
                case ["cluster", "nodes", var fromNode]: PrintNodes(db, fromNode); break;
                case ["nodes"]: PrintNodes(db, null); break;
                case ["nodes", var fromNode]: PrintNodes(db, fromNode); break;
                case ["routes"]: PrintRoutes(db, null); break;
                case ["routes", var destination]: PrintRoutes(db, destination); break;
                case ["sh", var target, "--interactive", .. var command] when command.Length > 0:
                    if (Console.IsInputRedirected) throw new Exception("Нужен интерактивный терминал.");
                    return await RemoteCommands.Run(db, cert, target, string.Join(' ', command), true);
                case ["sh", var target, .. var command] when command.Length > 0:
                    return await RemoteCommands.Run(db, cert, target, string.Join(' ', command));
                case ["ping", var host]:
                    return await ExternalPing.Run(db, cert, host);
                case ["cluster", "status"]:
                    Active(db); Console.WriteLine($"Кластер: {db.Get("cluster")}\nУзел: {me}\nIP: {db.Self()!.Ip}\nУзлов: {db.Nodes().Count(x => !x.Removed)}"); break;
                case ["cluster", "invites"]:
                    foreach (var i in db.Invites()) Console.WriteLine($"{i.Id} {i.Ip} {DateTimeOffset.FromUnixTimeMilliseconds(i.Expires):u} {(i.Used ? "использовано" : "активно")}"); break;
                case ["cluster", "invite", "revoke", var id]: db.Revoke(id); break;
                case ["cluster", "update", "announce", var commit]:
                    Active(db);
                    if (commit.Length != 40 || !commit.All(Uri.IsHexDigit)) throw new Exception("Ожидается SHA-1 коммита Git.");
                    var current = db.Update();
                    if (current?.Commit != commit)
                    {
                        current = new UpdateNotice(Guid.NewGuid().ToString("N"), commit.ToLowerInvariant(), Now);
                        db.PutUpdate(current);
                    }
                    db.Set("update_applied", current.Id);
                    Console.WriteLine($"Обновление {current.Commit} объявлено кластеру."); break;
                case ["cluster", "update", "applied", var updateId]:
                    if (db.Update()?.Id != updateId) throw new Exception("Событие обновления не найдено.");
                    db.Set("update_applied", updateId);
                    Console.WriteLine("Обновление узла подтверждено."); break;
                case ["cluster", "maintenance", "start"]:
                    await SetMaintenance(db, cert, true); break;
                case ["cluster", "maintenance", "done"]:
                    await SetMaintenance(db, cert, false); break;
                case ["web", "enable"]:
                    Active(db);
                    if (db.Rules().Any(x => !x.Removed && x.InPort == WebPanel.Port))
                        throw new Exception($"Порт {WebPanel.Port} занят правилом проброса. Удалите правило перед включением веб интерфейса.");
                    var password = ReadPassword();
                    var salt = RandomNumberGenerator.GetBytes(32);
                    var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 210_000, HashAlgorithmName.SHA256, 32);
                    var previous = db.Web();
                    db.PutWeb(new WebConfig(Guid.NewGuid().ToString("N"), true, Convert.ToHexString(salt),
                        Convert.ToHexString(hash), Math.Max(Now, (previous?.Version ?? 0) + 1)));
                    await Broadcast(db, cert);
                    Console.WriteLine($"Веб интерфейс включён на https://<IP>:{WebPanel.Port}/ (логин admin). Изменение отправлено узлам."); break;
                case ["web", "disable"]:
                    Active(db);
                    var currentWeb = db.Web();
                    db.PutWeb(new WebConfig(Guid.NewGuid().ToString("N"), false, "", "",
                        Math.Max(Now, (currentWeb?.Version ?? 0) + 1)));
                    await Broadcast(db, cert);
                    Console.WriteLine("Веб интерфейс выключен; пароль сброшен. Изменение отправлено узлам."); break;
                case ["name", .. var words] when words.Length > 0:
                    Active(db); var name = string.Join(' ', words).Trim();
                    if (name.Length is < 1 or > 64) throw new Exception("Имя: от 1 до 64 символов.");
                    db.Put(db.Self()! with { Name = name, Version = Now }); break;
                case ["forward", "add", .. var options]: AddRule(db, options); break;
                case ["forward", "list"]:
                    foreach (var r in db.Rules().Where(x => !x.Removed)) Console.WriteLine($"{r.Id} tcp {r.In}:{r.InPort} via {r.Via ?? "auto"} -> {r.To}:{r.ToPort}"); break;
                case ["forward", "show", var id]:
                    Console.WriteLine(JsonSerializer.Serialize(db.Rules().FirstOrDefault(x => x.Id == id) ?? throw new Exception("Правило не найдено."), Json)); break;
                case ["forward", "remove", var id]:
                    var rule = db.Rules().FirstOrDefault(x => x.Id == id && !x.Removed) ?? throw new Exception("Правило не найдено.");
                    db.Put(rule with { Removed = true, Version = Now }); break;
                default: Help(); return 2;
            }
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("pnt: " + e.GetBaseException().Message); return 1; }
    }

    static void Active(Store db)
    {
        if (db.Get("cluster") == null || db.Get("left") == "1" || db.Self()?.Removed == true) throw new Exception("Узел не состоит в активном кластере.");
    }

    static void PrintNodes(Store db, string? fromNode)
    {
        Active(db);
        var source = fromNode is null ? db.Self()! : db.Resolve(fromNode) ?? throw new Exception("Узел для измерения пинга не найден.");
        if (fromNode is not null) Console.WriteLine($"Пинг от узла {source.Name} ({source.Id}), измерения за последние 30 секунд:");
        foreach (var node in db.Nodes())
        {
            var ping = source.Id == node.Id ? new PingReport(source.Id, node.Id, 0, Now, true, [source.Id])
                : db.Pings().FirstOrDefault(x => x.Source == source.Id && x.Target == node.Id);
            var status = node.Removed ? "исключён"
                : node.Updating && node.UpdatingSince > 0 && Now - node.UpdatingSince < 3600_000 ? "update"
                : ping is not null ? $"{ping.Ms:0.0} ms" + (ping.Direct ? "" :
                    ping.Route is { Length: > 2 } route ? " через " + string.Join(" → ", route.Skip(1).SkipLast(1).Select(x => db.Nodes().FirstOrDefault(n => n.Id == x)?.Name ?? x)) : " через другой узел")
                : "нет связи";
            Console.WriteLine($"{node.Id}  {node.Name,-20} {node.Ip,-16} {status}{(node.BehindNat ? " [NAT]" : "")}");
        }
    }

    static void PrintRoutes(Store db, string? destination)
    {
        Active(db);
        var nodes = destination is null ? db.Nodes().Where(n => !n.Removed && n.Id != db.Get("self"))
            : new[] { db.Resolve(destination) ?? throw new Exception("Узел не найден.") };
        foreach (var node in nodes)
        {
            Console.WriteLine($"{node.Name} ({node.Id}):");
            var routes = db.Routes(node.Id).OrderByDescending(r => r.Primary).ThenBy(r => r.Ms).ToArray();
            if (routes.Length == 0) Console.WriteLine("  поиск маршрута...");
            foreach (var route in routes)
                Console.WriteLine($"  {(App.Now-route.Updated >= RouteCache.FreshFor ? "устарел" : route.Primary ? "основной" : "резервный")} {route.Ms:0.0} ms  " +
                    string.Join(" → ", route.Path.Select(id => db.Resolve(id)?.Name ?? id)));
        }
    }

    static async Task SetMaintenance(Store db, X509Certificate2 cert, bool updating)
    {
        Active(db);
        var self = db.Self()!;
        db.Put(self with { Updating = updating, UpdatingSince = updating ? Now : 0,
            Version = Math.Max(Now, self.Version + 1) });
        var notified = await Broadcast(db, cert);
        Console.WriteLine($"Статус {(updating ? "update" : "рабочий")} сохранён; оповещено узлов: {notified}.");
    }

    static string ReadPassword()
    {
        if (Console.IsInputRedirected) throw new Exception("Для задания пароля нужен интерактивный терминал.");
        Console.Write("Пароль веб интерфейса: ");
        var password = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (password.Length > 0) password.Length--; continue; }
            if (!char.IsControl(key.KeyChar) && password.Length < 1024) password.Append(key.KeyChar);
        }
        Console.WriteLine();
        if (password.Length == 0) throw new Exception("Пароль не может быть пустым.");
        return password.ToString();
    }

    static async Task<string> Broadcast(Store db, X509Certificate2 cert)
    {
        var self = db.Self()!;
        var message = new Message("sync", self.Id, Nodes: db.Nodes().ToArray(),
            Rules: db.Rules().ToArray(), Update: db.Update(), Pings: db.Pings().ToArray(), Web: db.Web());
        var peers = db.Nodes().Where(x => !x.Removed && x.Id != self.Id).ToArray();
        var routing = new RouteTransport(db, cert);
        var results = await Task.WhenAll(peers.Select(async node =>
        {
            try
            {
                using var peer = await routing.Connect(node.Id);
                var task = await RouteTransport.SendTask(peer, message);
                return (await RouteTransport.ReadResult(peer, task.RequestId, TimeSpan.FromSeconds(8))).Type == "sync";
            }
            catch { return false; }
        }));
        return $"{results.Count(x => x)}/{peers.Length}";
    }

    static void AddRule(Store db, string[] args)
    {
        Active(db);
        var m = new Dictionary<string, string>();
        for (var i = 0; i < args.Length; i += 2)
        {
            if (i + 1 == args.Length || !args[i].StartsWith("--")) throw new Exception("Неверные параметры.");
            m[args[i]] = args[i + 1];
        }
        if (!m.TryGetValue("--listen", out var input) || !m.TryGetValue("--to", out var output)) throw new Exception("Укажите --listen и --to.");
        var (inputHost, inputPort) = ParseEndpoint(input);
        var (outputHost, outputPort) = ParseEndpoint(output);
        if (inputPort == 442 || inputPort == WebPanel.Port && db.Web()?.Enabled == true)
            throw new Exception("Этот порт зарезервирован службой PNT.");
        var ingress = db.Resolve(inputHost) ?? throw new Exception("Узел входа не найден.");
        if (db.Rules().Any(x => !x.Removed && x.In == ingress.Id && x.InPort == inputPort)) throw new Exception("Этот входной порт уже используется другим правилом.");
        var via = m.GetValueOrDefault("--via");
        if (via != null) via = (db.Resolve(via) ?? throw new Exception("Узел выхода не найден.")).Id;
        var target = db.Resolve(outputHost);
        if (target == null && (via == null || !IPAddress.TryParse(outputHost, out _))) throw new Exception("Для внешнего IP требуется --via <узел>.");
        if (m.GetValueOrDefault("--proto", "tcp") != "tcp") throw new Exception("Пока поддерживается только TCP.");
        var r = new Rule(Guid.NewGuid().ToString("N")[..12], ingress.Id, inputPort, via, target?.Id ?? outputHost, outputPort, Now);
        db.Put(r); Console.WriteLine("Правило: " + r.Id);
    }

    static (string, int) ParseEndpoint(string s)
    {
        var p = s.LastIndexOf(':');
        if (p < 1 || !int.TryParse(s[(p + 1)..], out var port) || port is < 1 or > 65535) throw new Exception("Адрес должен иметь вид узел:порт или IPv4:порт.");
        return (s[..p], port);
    }

    static async Task Accept(Store db, X509Certificate2 cert, string encoded)
    {
        if (db.Get("cluster") != null) throw new Exception("Узел уже состоит в кластере.");
        Token token;
        try { token = JsonSerializer.Deserialize<Token>(Convert.FromBase64String(encoded), Json)!; }
        catch { throw new Exception("Неверный ключ приглашения."); }
        using var peer = await Peer.ConnectRaw(token.Host, token.Cert, cert);
        await Peer.Send(peer.Stream, new Message("join", Certificate.Id(cert), Environment.MachineName, OwnIp, Certificate.Fingerprint(cert), token.Secret, token.Id,Platform:Platform));
        var reply = await Peer.Read(peer.Stream) ?? throw new Exception("Нет ответа на приглашение.");
        if (reply.Type != "welcome") throw new Exception(reply.Error ?? "Приглашение отклонено.");
        if (reply.KeyHash == null || reply.KeyHash.Length != 64) throw new Exception("Ответ не содержит ключ кластера.");
        db.Set("cluster", token.Cluster); db.Set("self", Certificate.Id(cert)); db.Set("key_hash", reply.KeyHash);
        foreach (var n in reply.Nodes ?? []) db.Put(n);
        db.Put(new Node(Certificate.Id(cert), Environment.MachineName, OwnIp, Certificate.Fingerprint(cert), Now,Platform:Platform));
        foreach (var r in reply.Rules ?? []) db.Put(r);
        if (reply.Update is not null) db.PutUpdate(reply.Update);
        if (reply.Web is not null) db.PutWeb(reply.Web);
        Console.WriteLine("Присоединён к кластеру. ID: " + Certificate.Id(cert));
    }

    static void Help() => Console.WriteLine("""
        pnt create cluster <key>
        pnt cluster add <ip> | remove <node|ip> | leave | nodes [node-id] | status | invites
        pnt nodes [node-id]
        pnt routes [node-id]
        pnt sh <node-id> <command...>
        pnt ping <IPv4|domain>
        pnt install | update
        pnt install -r root@IPv4
        pnt connect cluster <IPv4> | connect status
        pnt cluster requests | accept <id> | reject <id>
        pnt identity
        pnt cluster invite revoke <id>
        pnt accept cluster <invite_key>
        pnt name <name>
        pnt vpn add server <node> <display_name> | remove <node> | servers
        pnt vpn client create <name> --servers <node1,node2> --out <file>
        pnt vpn client list | show <client> | allow <client> <node> | deny <client> <node> | revoke <client>
        pnt vpn client handshake <client> [node]
        pnt forward add --listen <node>:<port> [--via <node>] --to <node|ip>:<port> [--proto tcp]
        pnt forward list | show <id> | remove <id>
        pnt web enable | disable
        pnt serve
        """);
}
