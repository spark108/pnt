using System.CommandLine;
using Pnt;

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
Require(rootHelp.Code == 0 && rootHelp.Output.Contains("cluster") && !rootHelp.Output.Contains("--servers"), "Root help must list only its commands");
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
Require((await Invoke("vpn", "client", "create", "test", "--out", "test.pnt", "--servers", "one,two")).Code == 17, "Command callback result was lost");
Require(executed!.SequenceEqual(new[] { "vpn", "client", "create", "test", "--servers", "one,two", "--out", "test.pnt" }), "Named options must be canonicalized for the existing handler");
await Invoke("nodes");
Require(executed!.SequenceEqual(new[] { "nodes" }), "Omitted optional arguments must remain omitted");
await Invoke("identity", "--fingerprint");
Require(executed!.SequenceEqual(new[] { "identity", "--fingerprint" }), "Boolean option binding failed");
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
Console.WriteLine($"PASS: {count} help pages, argument validation, option ordering, aliases, remote command passthrough.");
