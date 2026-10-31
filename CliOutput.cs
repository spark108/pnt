using Spectre.Console;
using Spectre.Console.Rendering;
using System.Text;
using System.Text.RegularExpressions;

namespace Pnt;

readonly record struct CliCell(string Value, string? Style = null)
{
    public static implicit operator CliCell(string value) => new(value);
}

static class CliOutput
{
    internal static void Initialize()
    {
        if (OperatingSystem.IsWindows() && !Console.IsOutputRedirected && Console.OutputEncoding.CodePage != Encoding.UTF8.CodePage)
            Console.OutputEncoding = new UTF8Encoding(false);
    }
    static readonly Regex escapes = new(@"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1B]*(?:\x07|\x1B\\))", RegexOptions.Compiled);
    internal static string Clean(string value) => string.Concat(escapes.Replace(value, "").Select(c => char.IsControl(c) ? ' ' : c));
    internal static CliCell Status(string value) => new(value, value switch
    {
        "подключён" or "активен" or "основной" or "прямое" => "green",
        "отключён" or "отозван" or "исключён" or "нет связи" => "red",
        "update" or "неизвестно" or "резервный" or "устарел" or "поиск" => "yellow",
        _ => null
    });
    internal static CliCell Mode(string value) => new(value, value.Contains("транспорт") ? "cyan" : value == "прямое" ? "green" : "grey");
    internal static void Error(string value)
    {
        Initialize();
        if (Console.IsErrorRedirected || Environment.GetEnvironmentVariable("NO_COLOR") is not null || Environment.GetEnvironmentVariable("TERM") == "dumb")
        { Console.Error.WriteLine(Clean(value)); return; }
        AnsiConsole.Create(new AnsiConsoleSettings { Out = new AnsiConsoleOutput(Console.Error), Interactive = InteractionSupport.No })
            .Write(new Text(Clean(value) + Environment.NewLine, Style.Parse("red")));
    }
    internal static void Table(string[] columns, IEnumerable<CliCell[]> rows, TextWriter? output = null)
    {
        if (output is null) Initialize();
        var writer = output ?? Console.Out;
        var data = rows.ToArray();
        if (data.Any(row => row.Length != columns.Length)) throw new ArgumentException("Incorrect table column count.");
        if (output is not null || Console.IsOutputRedirected || Environment.GetEnvironmentVariable("TERM") == "dumb")
        {
            writer.WriteLine(string.Join('\t', columns.Select(Clean)));
            foreach (var row in data) writer.WriteLine(string.Join('\t', row.Select(c => Clean(c.Value))));
            return;
        }
        var color = Environment.GetEnvironmentVariable("NO_COLOR") is null;
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Out = new AnsiConsoleOutput(writer), Ansi = color ? AnsiSupport.Detect : AnsiSupport.No,
            ColorSystem = color ? ColorSystemSupport.Detect : ColorSystemSupport.NoColors,
            Interactive = InteractionSupport.No
        });
        Render(console, columns, data);
    }
    internal static async Task LiveTable(string[] columns,Func<IEnumerable<CliCell[]>> rows,CancellationToken cancellation,IAnsiConsole? console=null)
    {
        Initialize();
        if(console is null)
        {
            if(Console.IsOutputRedirected||Environment.GetEnvironmentVariable("TERM")=="dumb")
                throw new ArgumentException("Для --interactive нужен терминал без перенаправления вывода.");
            console=AnsiConsole.Create(new AnsiConsoleSettings{Out=new AnsiConsoleOutput(Console.Out),Ansi=AnsiSupport.Detect,
                ColorSystem=Environment.GetEnvironmentVariable("NO_COLOR") is null?ColorSystemSupport.Detect:ColorSystemSupport.NoColors,Interactive=InteractionSupport.Yes});
        }
        try
        {
            await console.Live(BuildTable(columns,rows())).AutoClear(false).StartAsync(async context=>
            {
                context.Refresh();
                while(!cancellation.IsCancellationRequested)
                {
                    await Task.Delay(1000,cancellation);
                    context.UpdateTarget(BuildTable(columns,rows()));
                    context.Refresh();
                }
            });
        }
        catch(OperationCanceledException) when(cancellation.IsCancellationRequested){}
    }
    internal static void Render(IAnsiConsole console, string[] columns, IEnumerable<CliCell[]> rows)=>console.Write(BuildTable(columns,rows));
    static Table BuildTable(string[] columns,IEnumerable<CliCell[]> rows)
    {
        var table = new Table().Border(TableBorder.Rounded).BorderStyle(Style.Parse("grey"));
        foreach (var column in columns) table.AddColumn(new TableColumn(new Text(Clean(column), Style.Parse("bold"))));
        foreach (var row in rows)
        {
            if(row.Length!=columns.Length)throw new ArgumentException("Incorrect table column count.");
            table.AddRow(row.Select(cell => (IRenderable)new Text(Clean(cell.Value), Style.Parse(cell.Style ?? "default"))).ToArray());
        }
        return table;
    }
}
