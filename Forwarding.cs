using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Pnt;

record NodeInterface(string Name, string Address);
record CreateForward(string InNode, int InPort, string InAddress, string? InInterface,
    string OutNode, string? OutAddress, string? OutInterface, string Destination, int DestinationPort);

static class Forwarding
{
    public static NodeInterface[] Interfaces() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up)
        .SelectMany(n => n.GetIPProperties().UnicastAddresses
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(a => new NodeInterface(n.Name,a.Address.ToString())))
        .OrderBy(n => n.Name).ThenBy(n => n.Address).ToArray();

    public static async Task<NodeInterface[]> GetInterfaces(Store db, X509Certificate2 cert, string node, CancellationToken token = default)
    {
        if (db.Resolve(node) is null) throw new ArgumentException("Узел не найден.");
        if (node == db.Get("self")) return Interfaces();
        using var peer = await new RouteTransport(db,cert).Connect(node,cancellation:token);
        var task = await RouteTransport.SendTask(peer,new Message("interfaces",db.Get("self"),Target:node));
        var reply = await RouteTransport.ReadResult(peer,task.RequestId,TimeSpan.FromSeconds(8),token);
        if (reply.Type != "interfaces" || reply.Interfaces is null) throw new IOException("Узел не вернул список интерфейсов. Проверьте версию PNT.");
        return reply.Interfaces;
    }

    public static void ValidateSelection(IEnumerable<NodeInterface> interfaces, string? name, string? address, bool incoming)
    {
        if (string.IsNullOrEmpty(name))
        {
            if (incoming && address == "0.0.0.0" || !incoming && string.IsNullOrEmpty(address)) return;
            throw new ArgumentException("Выберите интерфейс вместе с его IPv4 адресом.");
        }
        if (!interfaces.Any(i => i.Name == name && i.Address == address))
            throw new ArgumentException("Выбранный интерфейс или IPv4 адрес недоступен на узле.");
    }

    public static async Task<Rule> Create(Store db,X509Certificate2 cert,CreateForward input,CancellationToken token=default)
    {
        if (db.Get("left")=="1" || db.Self()?.Removed != false) throw new ArgumentException("Узел не состоит в активном кластере.");
        var ingress=db.Resolve(input.InNode) ?? throw new ArgumentException("Узел входа не найден.");
        var exit=db.Resolve(input.OutNode) ?? throw new ArgumentException("Узел выхода не найден.");
        if (input.InPort is <1 or >65535 || input.DestinationPort is <1 or >65535) throw new ArgumentException("Порт должен быть от 1 до 65535.");
        if(input.InPort==442 || input.InPort==WebPanel.Port && db.Web()?.Enabled==true) throw new ArgumentException("Порт занят службой PNT.");
        if(!IPAddress.TryParse(input.Destination,out var destination) || destination.AddressFamily!=AddressFamily.InterNetwork || destination.Equals(IPAddress.Any))
            throw new ArgumentException("Укажите IPv4 адрес назначения.");
        if(db.Rules().Any(r=>!r.Removed && r.In==ingress.Id && r.InPort==input.InPort &&
            (r.InAddress=="0.0.0.0" || input.InAddress=="0.0.0.0" || r.InAddress==input.InAddress)))
            throw new ArgumentException("Этот адрес и порт входа уже заняты правилом проброса.");
        var selections=await Task.WhenAll(GetInterfaces(db,cert,ingress.Id,token),GetInterfaces(db,cert,exit.Id,token));
        ValidateSelection(selections[0],input.InInterface,input.InAddress,true);
        ValidateSelection(selections[1],input.OutInterface,input.OutAddress,false);
        var rule=new Rule(Guid.NewGuid().ToString("N")[..12],ingress.Id,input.InPort,exit.Id,destination.ToString(),input.DestinationPort,App.Now,
            InAddress:input.InAddress,InInterface:input.InInterface,OutAddress:input.OutAddress,OutInterface:input.OutInterface);
        db.Put(rule);
        return rule;
    }

    public static void BindDevice(Socket socket,string? name)
    {
        if(string.IsNullOrEmpty(name)||!OperatingSystem.IsLinux())return;
        var bytes=Encoding.UTF8.GetBytes(name+"\0");
        if(bytes.Length>16)throw new ArgumentException("Недопустимое имя сетевого интерфейса.");
        // Linux SOL_SOCKET / SO_BINDTODEVICE; names come from the local interface inventory.
        if(setsockopt(socket.SafeHandle,1,25,bytes,(uint)bytes.Length)!=0)throw new SocketException(Marshal.GetLastPInvokeError());
    }

    public static async Task<TcpClient> Connect(string host,int port,string? name,string? address)
    {
        var tcp=new TcpClient(AddressFamily.InterNetwork);
        try
        {
            ValidateSelection(Interfaces(),name,address,false);
            BindDevice(tcp.Client,name);
            if(!string.IsNullOrEmpty(address))tcp.Client.Bind(new IPEndPoint(IPAddress.Parse(address),0));
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await tcp.ConnectAsync(host,port,timeout.Token);
            return tcp;
        }
        catch {tcp.Dispose();throw;}
    }

    [DllImport("libc",SetLastError=true)]
    static extern int setsockopt(SafeSocketHandle socket,int level,int option,byte[] value,uint length);
}
