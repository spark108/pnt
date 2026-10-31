using System.CommandLine;
using Pnt;

if(args is ["--encoding-sample"])
{
    System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
    if(OperatingSystem.IsWindows())Console.OutputEncoding=System.Text.Encoding.GetEncoding(866);
    Console.Out.Write("");
    CliOutput.Table(["Имя","Состояние"],[["Проверка",CliOutput.Status("подключён")]]);
    return;
}

static void Require(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

string[]? executed = null;
var root = CommandLine.Build(args => { executed = args; return Task.FromResult(17); });
async Task<(int Code, string Output)> Invoke(params string[] args)
{
    executed = null;
    using var output = new StringWriter();
    var code = await root.Parse(args).InvokeAsync(new InvocationConfiguration
        { Output = output, Error = output, EnableDefaultExceptionHandler = false });
    return (code, output.ToString());
}

var rootHelp = await Invoke("--help");
Require(rootHelp.Code == 0 && rootHelp.Output.Contains("node") && !rootHelp.Output.Contains("--servers"), "Root help must list only its commands");
var nodeHelp=await Invoke("node","--help");
Require(nodeHelp.Output.Contains("init")&&nodeHelp.Output.Contains("join")&&!nodeHelp.Output.Contains("requests"),"New node help shows member-only commands");
await Invoke("node","init","short-key");Require(executed!.SequenceEqual(new[]{"create","cluster","short-key"}),"Node init dispatch failed");
await Invoke("node","join","192.0.2.1");Require(executed!.SequenceEqual(new[]{"connect","cluster","192.0.2.1"}),"Node join dispatch failed");
await Invoke("node","status");Require(executed!.SequenceEqual(new[]{"node","status"}),"Unjoined node status failed");
await Invoke("node","invite","accept","token");Require(executed!.SequenceEqual(new[]{"accept","cluster","token"}),"Invite acceptance dispatch failed");
Require((await Invoke("node","init")).Code!=0&&executed is null,"Init accepted a missing key");
var freshRoot=root;
root=CommandLine.Build(args=>{executed=args;return Task.FromResult(17);},clustered:true);
nodeHelp=await Invoke("node","--help");
Require(!nodeHelp.Output.Contains("init")&&!nodeHelp.Output.Contains("join")&&nodeHelp.Output.Contains("accept")&&nodeHelp.Output.Contains("list"),"Member node help must hide init/join");
foreach(var legacy in new[]{"create","accept","connect","cluster","nodes","name","identity","routes"})
{
    Require(!root.Subcommands.Any(c=>c.Name==legacy),"Legacy command still registered: "+legacy);
    Require((await Invoke(legacy)).Code!=0&&executed is null,"Legacy command executed: "+legacy);
    await Invoke(legacy,"--help");Require(executed is null,"Legacy help executed: "+legacy);
}
Require((await Invoke("nodes","other")).Code!=0&&executed is null,"Legacy nodes argument accepted");
Require((await Invoke("cluster","status")).Code!=0&&executed is null,"Legacy cluster status accepted");
await Invoke("node","status","--require-cluster");Require(executed!.SequenceEqual(new[]{"node","status","--require-cluster"}),"Cluster status check flag lost");
await Invoke("node","maintenance","start");Require(executed!.SequenceEqual(new[]{"cluster","maintenance","start"}),"Maintenance worker command failed");
await Invoke("node","update","applied","id");Require(executed!.SequenceEqual(new[]{"cluster","update","applied","id"}),"Update worker command failed");
var inviteHelp=await Invoke("node","invite","--help");Require(!inviteHelp.Output.Contains("accept")&&inviteHelp.Output.Contains("create"),"Member help offered joining by invite");
foreach(var (input,expected) in new (string[],string[])[]{
 (["node","list"],["nodes"]),(["node","list","other"],["nodes","other"]),
 (["node","accept","id"],["cluster","accept","id"]),(["node","reject","id"],["cluster","reject","id"]),
 (["node","requests"],["cluster","requests"]),(["node","leave"],["cluster","leave"]),
 (["node","kick","other"],["node","kick","other"]),
 (["node","remove","other"],["cluster","remove","other"]),(["node","name","Node Name"],["name","Node Name"]),
 (["node","status"],["node","status"]),(["node","identity","--fingerprint"],["identity","--fingerprint"]),
 (["node","routes","other"],["routes","other"]),(["node","invite","create","192.0.2.2"],["cluster","add","192.0.2.2"]),
 (["node","invite","revoke","id"],["cluster","invite","revoke","id"]),(["node","invite","list"],["cluster","invites"])
}){await Invoke(input);Require(executed!.SequenceEqual(expected),"Node dispatch failed: "+string.Join(' ',input));}
await Invoke("node","list","--interactive");Require(executed!.SequenceEqual(new[]{"nodes","--interactive"}),"Interactive list dispatch failed");
await Invoke("node","list","other","--interactive");Require(executed!.SequenceEqual(new[]{"nodes","other","--interactive"}),"Interactive source node lost");
Require((await Invoke("node","accept")).Code!=0&&executed is null,"Accept permitted a missing ID");
root=freshRoot;
var vpnHelp = await Invoke("vpn", "--help");
Require(vpnHelp.Code == 0 && vpnHelp.Output.Contains("client") && !vpnHelp.Output.Contains("--servers"), "VPN help must not flatten client commands");
var clientHelp = await Invoke("vpn", "client", "--help");
Require(clientHelp.Code == 0 && clientHelp.Output.Contains("handshake") && !clientHelp.Output.Contains("--listen"), "Client help must remain scoped");
var createHelp = await Invoke("vpn", "client", "create", "--help");
Require(createHelp.Code == 0 && createHelp.Output.Contains("--servers") && createHelp.Output.Contains("--out") && executed is null, "Leaf help must describe options without executing");

var count = 0;
async Task Walk(Command command, string[] path)
{
    var help = await Invoke([.. path, "--help"]);
    Require(help.Code == 0 && executed is null, "Help failed: " + string.Join(' ', path));
    count++;
    foreach (var child in command.Subcommands) await Walk(child, [.. path, child.Name]);
}
await Walk(root, []);
Require((await Invoke("vpn", "client", "create", "test")).Code != 0 && executed is null, "Missing options must not reach storage");
Require((await Invoke("forward", "add", "--listen", "node:123", "--wrong", "x")).Code != 0 && executed is null, "Unknown options must be rejected");
Require((await Invoke("cluster", "stats")).Code != 0 && executed is null, "Unknown subcommands must be rejected");
await Invoke("vpn","client","unbind","0123456789abcdef");Require(executed!.SequenceEqual(new[]{"vpn","client","unbind","0123456789abcdef"}),"Client unbind binding failed");
Require((await Invoke("vpn","client","unbind")).Code!=0&&executed is null,"Client unbind accepted missing ID");
await Invoke("vpn","client","get","Alice");Require(executed!.SequenceEqual(new[]{"vpn","client","get","Alice"}),"Client get console binding failed");
await Invoke("vpn","client","get","Alice","--out=file.pnt");Require(executed!.SequenceEqual(new[]{"vpn","client","get","Alice","--out","file.pnt"}),"Client get output binding failed");
Require((await Invoke("vpn","client","get")).Code!=0&&executed is null,"Client get accepted missing client");
Require((await Invoke("vpn","client","get","Alice","--out")).Code!=0&&executed is null,"Client get accepted missing output path");
await Invoke("vpn","status","exit-node");Require(executed!.SequenceEqual(new[]{"vpn","status","exit-node"}),"VPN status node binding failed");
Require((await Invoke("vpn","status")).Code!=0&&executed is null,"VPN status accepted missing node");
foreach(var action in new[]{"start","stop","restart"})
{
    await Invoke("vpn",action);Require(executed!.SequenceEqual(new[]{"vpn",action}),"Local VPN control failed");
    await Invoke("vpn",action,"exit-node");Require(executed!.SequenceEqual(new[]{"vpn",action,"exit-node"}),"Remote VPN control failed");
    Require((await Invoke("vpn",action,"one","two")).Code!=0&&executed is null,"VPN control accepted extra nodes");
}
await Invoke("vpn", "server", "install", "test-node");
Require(executed!.SequenceEqual(new[] { "vpn", "server", "install", "test-node" }), "VPN installer dispatch failed");
await Invoke("vpn", "server", "list");
Require(executed!.SequenceEqual(new[] { "vpn", "server", "list" }), "VPN server list dispatch failed");
await Invoke("vpn", "server", "rename", "test-node", "Нидерланды #1");
Require(executed!.SequenceEqual(new[] {"vpn","server","rename","test-node","Нидерланды #1"}),"VPN server display name binding failed");
Require((await Invoke("vpn","server","rename","test-node")).Code!=0&&executed is null,"Server rename accepted missing display name");
await Invoke("vpn", "server", "remove", "test-node");
Require(executed!.SequenceEqual(new[] { "vpn", "server", "remove", "test-node" }), "VPN server removal dispatch failed");
Require((await Invoke("vpn", "servers")).Code != 0 && executed is null, "Old VPN server command still exists");
Require((await Invoke("vpn", "add", "server", "test-node", "name")).Code != 0 && executed is null, "Old VPN registration command still exists");
await Invoke("cesium","token");Require(executed!.SequenceEqual(new[]{"cesium","token"}),"Hidden token prompt dispatch failed");
await Invoke("cesium","add","96188","Здания");Require(executed!.SequenceEqual(new[]{"cesium","add","96188","Здания"}),"Cesium dataset arguments lost");
Require((await Invoke("cesium","add")).Code!=0&&executed is null,"Cesium asset ID was optional");
Require((await Invoke("vpn", "client", "create", "test", "--out", "test.pnt", "--servers", "one,two")).Code == 17, "Command callback result was lost");
Require(executed!.SequenceEqual(new[] { "vpn", "client", "create", "test", "--servers", "one,two", "--out", "test.pnt" }), "Named options must be canonicalized for the existing handler");
var rebootId="0123456789abcdef";
foreach(var suffix in new[]{Array.Empty<string>(),new[]{"-f"}})
{
    Require((await Invoke(["node",rebootId,"reboot",..suffix])).Code==17,"Reboot command rejected");
    Require(executed!.SequenceEqual(new[]{"node",rebootId,"reboot"}.Concat(suffix)),"Reboot ID/force binding failed");
}
foreach(var invalid in new[]{new[]{"node","reboot"},new[]{"node","bad","reboot"},new[]{"node","reboot",rebootId},new[]{"node",rebootId,"reboot","--force"},new[]{"node",rebootId,"list"},new[]{"node",rebootId,"status"}})
    Require((await Invoke(invalid)).Code!=0&&executed is null,"Invalid reboot/node syntax accepted: "+string.Join(' ',invalid));
Require((await Invoke("node",rebootId,"reboot","--help")).Code==0&&executed is null,"Reboot help executed task");
await Invoke("node","list");
Require(executed!.SequenceEqual(new[] { "nodes" }), "Omitted optional arguments must remain omitted");
await Invoke("node","identity", "--fingerprint");
Require(executed!.SequenceEqual(new[] { "identity", "--fingerprint" }), "Boolean option binding failed");
await Invoke("update", "--check");
Require(executed!.SequenceEqual(new[] { "update", "--check" }), "Update check must reach the read-only handler");
await Invoke("install", "-r", "root@192.0.2.1");
Require(executed!.SequenceEqual(new[] { "install", "-r", "root@192.0.2.1" }), "Remote install binding failed");

await CommandLine.Run(["sh", "node", "ping", "--help", "-c", "3"], args => { executed = args; return Task.FromResult(0); });
Require(executed!.SequenceEqual(new[] { "sh", "node", "ping", "--help", "-c", "3" }), "Remote command arguments must pass through unchanged");
var originalOutput = Console.Out;
try
{
    using var helpOutput = new StringWriter();
    Console.SetOut(helpOutput);
    executed = null;
    Require(await CommandLine.Run(["help", "vpn", "client", "create"], _ => { throw new Exception("Help executed a command"); }) == 0, "Help alias failed");
    Require(helpOutput.ToString().Contains("--servers"), "Help alias selected the wrong level");
    Require(await CommandLine.Run(["vpn", "client"], _ => { throw new Exception("Group executed a command"); }) == 0, "Bare groups must show help");
}
finally { Console.SetOut(originalOutput); }
using(var plain = new StringWriter())
{
    CliOutput.Table(["Имя","Статус"],[["узел[red]",CliOutput.Status("подключён")]],plain);
    Require(plain.ToString().Contains("Имя\tСтатус")&&plain.ToString().Contains("узел[red]\tподключён"),"Plain table must preserve literal text and column delimiters");
    Require(!plain.ToString().Contains('\u001b'),"Redirected table emitted terminal escapes");
}
Require(CliOutput.Clean("\u001b[31mname\u001b[0m\nnext\tx")=="name next x","Terminal controls in table data were not sanitized");
using(var colored = new StringWriter())
{
    var console=Spectre.Console.AnsiConsole.Create(new Spectre.Console.AnsiConsoleSettings
    {
        Out=new Spectre.Console.AnsiConsoleOutput(colored),Ansi=Spectre.Console.AnsiSupport.Yes,
        ColorSystem=Spectre.Console.ColorSystemSupport.TrueColor,Interactive=Spectre.Console.InteractionSupport.No
    });
    console.Profile.Width=80;console.Profile.Capabilities.Unicode=true;
    CliOutput.Render(console,["Имя","Состояние","Подключение"],[["узел[red]literal[/]",CliOutput.Status("подключён"),CliOutput.Mode("транспорт")]]);
    Require(colored.ToString().Contains("[red]literal[/]"),"User data was interpreted as console markup");
    Require(colored.ToString().Contains('\u001b')&&colored.ToString().Contains('╭'),"Interactive table did not render colors and borders");
    console.Profile.Width=28;
    CliOutput.Render(console,["Имя","Статус"],[["节点 с длинным именем",CliOutput.Status("неизвестно")]]);
    CliOutput.Render(console,["Пустая таблица"],[]);
}
using(var liveOutput=new StringWriter())
using(var cancellation=new CancellationTokenSource(TimeSpan.FromMilliseconds(2200)))
{
    var console=Spectre.Console.AnsiConsole.Create(new Spectre.Console.AnsiConsoleSettings{Out=new Spectre.Console.AnsiConsoleOutput(liveOutput),Ansi=Spectre.Console.AnsiSupport.Yes,Interactive=Spectre.Console.InteractionSupport.Yes});
    var frames=0;
    await CliOutput.LiveTable(["Статус"],()=>new[]{new CliCell[]{++frames==1?"update":"подключён"}},cancellation.Token,console);
    Require(frames>=2&&liveOutput.ToString().Contains("update")&&liveOutput.ToString().Contains("подключён"),"Live table did not refresh and cancel");
}
Console.WriteLine($"PASS: {count} help pages, argument validation, aliases, remote passthrough, color tables, literal data, narrow terminals and plain redirected output.");
