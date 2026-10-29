using System.CommandLine;

namespace Pnt;

static class CommandLine
{
    public static Task<int> Run(string[] args, Func<string[], Task<int>> execute)
    {
        if (args is ["sh", var target, .. var tail] && target is not ("--help" or "-h" or "-?" or "help") && tail.Length > 0)
        {
            if (tail is ["--interactive"]) throw new ArgumentException("После --interactive укажите команду.");
            return execute(args);
        }
        var root = Build(execute);
        if (args is ["help", .. var path]) args = [.. path, "--help"];
        if (args.Length == 0) args = ["--help"];
        var current = (Command)root;
        var groupsOnly = true;
        foreach (var token in args)
        {
            var child = current.Subcommands.FirstOrDefault(c => c.Name == token);
            if (child is null) { groupsOnly = false; break; }
            current = child;
        }
        if (groupsOnly && current.Subcommands.Count > 0) args = [.. args, "--help"];
        return root.Parse(args).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
    }

    internal static RootCommand Build(Func<string[], Task<int>> execute)
    {
        var root = new RootCommand("PNT — управление децентрализованной сетью серверов.");
        var groups = new Dictionary<string, Command> { [""] = root };
        void Group(string path, string description)
        {
            var split = path.LastIndexOf(' ');
            var parent = split < 0 ? "" : path[..split];
            var command = new Command(path[(split + 1)..], description);
            groups[parent].Subcommands.Add(command);
            groups[path] = command;
        }
        void Leaf(string path, string description, (string Name, string Description)[]? parameters = null,
            (string Name, string Description, bool Required)[]? options = null, string[]? flags = null)
        {
            var split = path.LastIndexOf(' ');
            var parent = split < 0 ? "" : path[..split];
            var command = new Command(path[(split + 1)..], description);
            var arguments = (parameters ?? []).Select(p => new Argument<string>(p.Name.TrimEnd('?'))
            {
                Description = p.Description,
                Arity = p.Name.EndsWith('?') ? ArgumentArity.ZeroOrOne : ArgumentArity.ExactlyOne
            }).ToArray();
            var named = (options ?? []).Select(o => new Option<string>(o.Name)
                { Description = o.Description, Required = o.Required }).ToArray();
            var switches = (flags ?? []).Select(f => new Option<bool>(f)
                { Description = f switch { "--fingerprint" => "Показать отпечаток сертификата.", "--check" => "Только проверить наличие новой версии без установки.", _ => "Интерактивный режим." } }).ToArray();
            foreach (var argument in arguments) command.Arguments.Add(argument);
            foreach (var option in named) command.Options.Add(option);
            foreach (var flag in switches) command.Options.Add(flag);
            command.SetAction(async (result, cancellation) =>
            {
                var values = path.Split(' ').ToList();
                foreach (var argument in arguments)
                    if (result.GetValue(argument) is { } value) values.Add(value);
                foreach (var option in named)
                    if (result.GetValue(option) is { } value) { values.Add(option.Name); values.Add(value); }
                foreach (var flag in switches)
                    if (result.GetValue(flag)) values.Add(flag.Name);
                return await execute(values.ToArray());
            });
            groups[parent].Subcommands.Add(command);
        }
        Group("create", "Создание ресурсов PNT.");
        Group("accept", "Принятие приглашений.");
        Group("connect", "Заявка на присоединение к кластеру.");
        Group("cluster", "Управление узлами и состоянием кластера.");
        Group("cluster invite", "Управление приглашениями.");
        Group("cluster update", "События обновления кластера.");
        Group("cluster maintenance", "Статус обслуживания текущего узла.");
        Group("forward", "Проброс TCP-портов через сеть PNT.");
        Group("web", "Веб-интерфейс всех узлов кластера.");
        Group("vpn", "VPN-серверы и доступ клиентов.");
        Group("vpn add", "Регистрация VPN-серверов.");
        Group("vpn client", "Управление VPN-клиентами и их правами.");
        Leaf("create cluster", "Создать кластер с общим ключом.", [("key", "Общий ключ кластера.")]);
        Leaf("accept cluster", "Принять приглашение в кластер.", [("invite", "Ключ приглашения.")]);
        Leaf("connect cluster", "Отправить заявку действующему узлу.", [("ip", "IPv4 действующего узла.")]);
        Leaf("connect status", "Показать состояние заявки на присоединение.");
        Leaf("identity", "Показать уникальный ID текущего узла.", flags: ["--fingerprint"]);
        Leaf("name", "Изменить отображаемое имя текущего узла. Имя с пробелами заключите в кавычки.", [("name", "Новое имя узла.")]);
        Leaf("nodes", "Показать узлы, пинг и промежуточные серверы.", [("from?", "ID или имя узла, от лица которого показать измерения.")]);
        Leaf("routes", "Показать основные и резервные маршруты.", [("node?", "ID, имя или IP конечного узла.")]);
        Leaf("ping", "Измерить пинг до внешнего адреса со всех доступных узлов.", [("host", "IPv4 или домен назначения.")]);
        Leaf("install", "Установить PNT локально или на удалённом сервере.", options: [("-r", "SSH-адрес удалённого сервера, например root@192.0.2.1.", false)]);
        Leaf("update", "Обновить PNT и объявить обновление кластеру.", flags: ["--check"]);
        Leaf("serve", "Запустить фоновую службу узла.");
        Leaf("cluster add", "Создать приглашение для указанного IP.", [("ip", "IP приглашаемого узла.")]);
        Leaf("cluster remove", "Исключить узел из кластера.", [("node", "ID, имя или IP узла.")]);
        Leaf("cluster leave", "Выйти из кластера текущим узлом.");
        Leaf("cluster nodes", "Показать узлы, пинг и маршруты.", [("from?", "Узел, от лица которого показать измерения.")]);
        Leaf("cluster status", "Показать состояние текущего кластера.");
        Leaf("cluster requests", "Показать ожидающие заявки новых узлов.");
        Leaf("cluster accept", "Подтвердить заявку нового узла.", [("id", "ID заявки.")]);
        Leaf("cluster reject", "Отклонить заявку нового узла.", [("id", "ID заявки.")]);
        Leaf("cluster invites", "Показать выданные приглашения.");
        Leaf("cluster invite revoke", "Отозвать приглашение.", [("id", "ID приглашения.")]);
        Leaf("cluster update announce", "Объявить коммит обновления узлам.", [("commit", "Полный SHA-1 коммита Git.")]);
        Leaf("cluster update applied", "Подтвердить применение обновления.", [("id", "ID события обновления.")]);
        Leaf("cluster maintenance start", "Сообщить кластеру о начале обслуживания.");
        Leaf("cluster maintenance done", "Сообщить кластеру о завершении обслуживания.");
        Leaf("web enable", "Включить веб-интерфейс на порту 8016. Пароль запрашивается отдельно.");
        Leaf("web disable", "Отключить веб-интерфейс и сбросить пароль.");
        Leaf("forward add", "Создать проброс TCP-порта.", options:
        [
            ("--listen", "Узел входа и порт: <node>:<port>.", true),
            ("--to", "Назначение: <node|IPv4>:<port>.", true),
            ("--via", "Узел выхода; обязателен для внешнего IP.", false),
            ("--proto", "Протокол проброса; поддерживается tcp.", false)
        ]);
        Leaf("forward list", "Показать все активные пробросы.");
        Leaf("forward show", "Показать свойства проброса.", [("id", "ID правила.")]);
        Leaf("forward remove", "Удалить проброс порта.", [("id", "ID правила.")]);
        Leaf("vpn add server", "Разрешить узел с AmneziaWG как VPN-сервер.", [("node", "ID или имя узла."), ("display-name", "Имя сервера для клиентов; используйте кавычки для пробелов.")]);
        Leaf("vpn remove", "Исключить узел из каталога VPN.", [("node", "ID или имя узла.")]);
        Leaf("vpn servers", "Показать разрешённые VPN-серверы.");
        Leaf("vpn client create", "Создать клиента и экспортировать подписанный профиль доступа.", [("name", "Уникальное имя клиента.")],
            [("--servers", "Разрешённые узлы через запятую.", true), ("--out", "Путь нового файла .pnt; существующий файл не перезаписывается.", true)]);
        Leaf("vpn client list", "Показать VPN-клиентов и состояние доступа.");
        Leaf("vpn client show", "Показать свойства и права клиента.", [("client", "ID или имя клиента.")]);
        Leaf("vpn client allow", "Разрешить клиенту VPN-сервер.", [("client", "ID или имя клиента."), ("node", "ID или имя сервера.")]);
        Leaf("vpn client deny", "Запретить клиенту VPN-сервер.", [("client", "ID или имя клиента."), ("node", "ID или имя сервера.")]);
        Leaf("vpn client revoke", "Отозвать доступ клиента ко всем серверам.", [("client", "ID или имя клиента.")]);
        Leaf("vpn client handshake", "Показать рукопожатие и счётчики трафика клиента.", [("client", "ID или имя клиента."), ("node?", "Проверять только указанный сервер.")]);
        var shell = new Command("sh", "Выполнить команду на узле с потоковой передачей вывода. Аргументы после узла передаются удалённой оболочке без разбора.");
        shell.Arguments.Add(new Argument<string>("node") { Description = "ID или имя конечного узла." });
        shell.Arguments.Add(new Argument<string[]>("command") { Description = "Команда и её аргументы.", Arity = ArgumentArity.OneOrMore });
        shell.Options.Add(new Option<bool>("--interactive") { Description = "Интерактивный режим, если поддерживается узлом." });
        shell.SetAction((result, cancellation) => execute(["sh", .. result.Tokens.Select(t => t.Value).Skip(1)]));
        root.Subcommands.Add(shell);
        return root;
    }
}
