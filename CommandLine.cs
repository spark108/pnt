using System.CommandLine;

namespace Pnt;

static class CommandLine
{
    public static Task<int> Run(string[] args, Func<string[], Task<int>> execute, bool clustered = false)
    {
        if (args is ["sh", var target, .. var tail] && target is not ("--help" or "-h" or "-?" or "help") && tail.Length > 0)
        {
            if (tail is ["--interactive"]) throw new ArgumentException("После --interactive укажите команду.");
            return execute(args);
        }
        var root = Build(execute, clustered);
        if (args is ["help", .. var path]) args = [.. path, "--help"];
        if (args.Length == 0) args = ["--help"];
        var current = (Command)root;
        var groupsOnly = true;
        var targetSeen=false;
        foreach (var token in args)
        {
            var child = current.Subcommands.FirstOrDefault(c => c.Name == token);
            if(child is null&&current.Name=="node"&&!targetSeen&&token.Length==16&&token.All(Uri.IsHexDigit)){targetSeen=true;continue;}
            if (child is null) { groupsOnly = false; break; }
            current = child;
        }
        if (groupsOnly && current.Subcommands.Count > 0) args = [.. args, "--help"];
        return root.Parse(args).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
    }

    internal static RootCommand Build(Func<string[], Task<int>> execute, bool clustered = false)
    {
        var nodeTarget=new Argument<string>("id"){Arity=ArgumentArity.ZeroOrOne,Description="ID узла для команды reboot; указывается перед reboot."};
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
            (string Name, string Description, bool Required)[]? options = null, string[]? flags = null, string? dispatch = null, bool hidden = false)
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
                { Description = f switch { "--fingerprint" => "Показать отпечаток сертификата.", "--require-cluster" => "Вернуть ошибку, если узел не состоит в активном кластере.", "--check" => "Только проверить наличие новой версии без установки.", "--interactive" when path=="node list" => "Обновлять таблицу на месте до Ctrl+C.", _ => "Интерактивный режим." } }).ToArray();
            foreach (var argument in arguments) command.Arguments.Add(argument);
            foreach (var option in named) command.Options.Add(option);
            foreach (var flag in switches) command.Options.Add(flag);
            if(path.StartsWith("node "))command.Validators.Add(result=>
            {
                if(result.GetValue(nodeTarget) is not null)result.AddError("Эта команда используется без ID перед подкомандой.");
            });
            command.SetAction(async (result, cancellation) =>
            {
                var values = (dispatch ?? path).Split(' ').ToList();
                foreach (var argument in arguments)
                    if (result.GetValue(argument) is { } value) values.Add(value);
                foreach (var option in named)
                    if (result.GetValue(option) is { } value) { values.Add(option.Name); values.Add(value); }
                foreach (var flag in switches)
                    if (result.GetValue(flag)) values.Add(flag.Name);
                return await execute(values.ToArray());
            });
            command.Hidden = hidden;
            groups[parent].Subcommands.Add(command);
        }
        Group("node", "Узлы, подключение и управление кластером.");
        groups["node"].Arguments.Add(nodeTarget);
        var reboot=new Command("reboot","Перезагрузить ОС: pnt node <id> reboot [-f]. Требует подтверждения.");
        var forceReboot=new Option<bool>("-f"){Description="Принудительная перезагрузка; подтверждение остаётся обязательным."};
        reboot.Options.Add(forceReboot);
        reboot.Validators.Add(result=>
        {
            var target=result.GetValue(nodeTarget);
            if(target is null||target.Length!=16||!target.All(Uri.IsHexDigit))result.AddError("Укажите 16-значный ID узла перед reboot: pnt node <id> reboot [-f].");
        });
        reboot.SetAction((result,cancellation)=>execute(result.GetValue(forceReboot)?["node",result.GetValue(nodeTarget)!,"reboot","-f"]:["node",result.GetValue(nodeTarget)!,"reboot"]));
        groups["node"].Subcommands.Add(reboot);
        Group("node invite", "Приглашения в кластер.");
        Leaf("node init", "Создать новый кластер с общим ключом.", [("key", "Общий ключ кластера.")], dispatch:"create cluster", hidden:clustered);
        Leaf("node join", "Отправить заявку на вступление в кластер.", [("ip", "IPv4 действующего узла.")], dispatch:"connect cluster", hidden:clustered);
        Leaf("node status", "Показать состояние узла и подключения.", flags:["--require-cluster"]);
        Leaf("node identity", "Показать уникальный ID текущего узла.", flags:["--fingerprint"], dispatch:"identity");
        Leaf("node name", "Изменить имя текущего узла.", [("name", "Новое имя.")], dispatch:"name", hidden:!clustered);
        Leaf("node list", "Показать узлы, пинг и транспортные маршруты.", [("from?", "ID или имя узла, от лица которого показать пинг.")], flags:["--interactive"], dispatch:"nodes", hidden:!clustered);
        Leaf("node routes", "Показать основные и резервные маршруты.", [("node?", "ID, имя или IP конечного узла.")], dispatch:"routes", hidden:!clustered);
        Leaf("node requests", "Показать ожидающие заявки на вступление.", dispatch:"cluster requests", hidden:!clustered);
        Leaf("node accept", "Принять заявку нового узла.", [("id", "ID заявки.")], dispatch:"cluster accept", hidden:!clustered);
        Leaf("node reject", "Отклонить заявку нового узла.", [("id", "ID заявки.")], dispatch:"cluster reject", hidden:!clustered);
        Leaf("node kick", "Попросить узел добровольно выйти и сообщить об этом кластеру.", [("node", "ID, имя или IP узла.")], hidden:!clustered);
        Leaf("node remove", "Исключить другой узел из кластера.", [("node", "ID, имя или IP узла.")], dispatch:"cluster remove", hidden:!clustered);
        Leaf("node leave", "Отключить текущий узел от кластера.", dispatch:"cluster leave", hidden:!clustered);
        Leaf("node invite create", "Создать приглашение для IP.", [("ip", "IPv4 приглашаемого узла.")], dispatch:"cluster add", hidden:!clustered);
        Leaf("node invite accept", "Вступить в кластер по приглашению.", [("invite", "Ключ приглашения.")], dispatch:"accept cluster", hidden:clustered);
        Leaf("node invite list", "Показать выданные приглашения.", dispatch:"cluster invites", hidden:!clustered);
        Leaf("node invite revoke", "Отозвать приглашение.", [("id", "ID приглашения.")], dispatch:"cluster invite revoke", hidden:!clustered);
        Group("node update", "Служебные события обновления кластера.");
        Group("node maintenance", "Статус обслуживания текущего узла.");
        Leaf("node update announce", "Объявить коммит обновления.", [("commit", "SHA-1 коммита.")], dispatch:"cluster update announce");
        Leaf("node update applied", "Подтвердить применение обновления.", [("id", "ID события.")], dispatch:"cluster update applied");
        Leaf("node maintenance start", "Объявить обслуживание.", dispatch:"cluster maintenance start");
        Leaf("node maintenance done", "Завершить обслуживание.", dispatch:"cluster maintenance done");
        Group("forward", "Проброс TCP-портов через сеть PNT.");
        Group("web", "Веб-интерфейс всех узлов кластера.");
        Group("cesium", "Датасеты Cesium ion на глобусе.");
        Leaf("cesium token", "Сохранить токен Cesium ion; без аргумента — скрытый ввод. clear удаляет токен.", [("token?", "Токен Cesium ion либо clear.")]);
        Leaf("cesium add", "Подключить датасет по ID Cesium ion.", [("id", "Числовой ID ассета."),("name?", "Отображаемое имя.")]);
        Leaf("cesium remove", "Удалить датасет с глобуса.", [("id", "ID ассета.")]);
        Leaf("cesium enable", "Включить датасет.", [("id", "ID ассета.")]);
        Leaf("cesium disable", "Выключить датасет.", [("id", "ID ассета.")]);
        Leaf("cesium list", "Показать подключённые датасеты.");
        Leaf("cesium status", "Показать состояние настройки Cesium без токена.");
        Group("vpn", "VPN-серверы и доступ клиентов.");
        Leaf("vpn status", "Показать состояние AmneziaWG и клиентов на узле.", [("node", "ID, имя или IP узла.")]);
        Leaf("vpn start", "Запустить выбранную конфигурацию AmneziaWG.", [("node?", "Узел; по умолчанию текущий.")]);
        Leaf("vpn stop", "Остановить выбранную конфигурацию AmneziaWG.", [("node?", "Узел; по умолчанию текущий.")]);
        Leaf("vpn restart", "Перезапустить выбранную конфигурацию AmneziaWG.", [("node?", "Узел; по умолчанию текущий.")]);
        Group("vpn server", "Установка и управление VPN-серверами.");
        Group("vpn client", "Управление VPN-клиентами и их правами.");
        Leaf("ping", "Измерить пинг до внешнего адреса со всех доступных узлов.", [("host", "IPv4 или домен назначения.")]);
        Leaf("install", "Установить PNT локально или на удалённом сервере.", options: [("-r", "SSH-адрес удалённого сервера, например root@192.0.2.1.", false)]);
        Leaf("update", "Обновить PNT и объявить обновление кластеру.", flags: ["--check"]);
        Leaf("serve", "Запустить фоновую службу узла.");
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
        Leaf("vpn server install", "Установить AmneziaWG, выбрать конфигурацию и разрешить узел как VPN-сервер.", [("node", "ID или имя узла Debian Linux.")]);
        Leaf("vpn server rename", "Изменить отображаемое имя VPN-сервера у клиентов.", [("node", "ID или имя узла."), ("name", "Новое отображаемое имя VPN-сервера.")]);
        Leaf("vpn server remove", "Исключить узел из каталога VPN.", [("node", "ID или имя узла.")]);
        Leaf("vpn server list", "Показать разрешённые VPN-серверы.");
        Leaf("vpn client create", "Создать клиента и экспортировать подписанный профиль доступа.", [("name", "Уникальное имя клиента.")],
            [("--servers", "Разрешённые узлы через запятую.", true), ("--out", "Путь нового файла .pnt; существующий файл не перезаписывается.", true)]);
        Leaf("vpn client get", "Выгрузить профиль доступа клиента в консоль или файл.", [("client", "ID или имя клиента.")],
            [("--out", "Путь нового файла .pnt; без параметра профиль выводится в консоль.", false)]);
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
