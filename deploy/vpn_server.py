import base64
import fcntl
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:" + os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")


CONFIG_DIRS = [Path(p) for p in ("/etc/amnezia/amneziawg", "/etc/amneziawg", "/etc/wireguard", "/opt/amnezia/awg")]
IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
IDENTITY = re.compile(r"[0-9a-f]{24}")
CLIENT = re.compile(r"[0-9a-f]{16}")
TOOLS_COMMIT = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
GO_COMMIT = "v3.1.20260814"


def run(args, data=None, timeout=60, check=True, env=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError("Command failed: " + Path(args[0]).name)
    return result.stdout.strip() if check else result


def stage(text):
    print(text, flush=True)


def values(text):
    interface = text.split("[Peer]", 1)[0]
    return dict(re.findall(r"^\s*([A-Za-z0-9]+)\s*=\s*([^\r\n#]+)", interface, re.M))


def provider(kind, iface, path, text, active=False, container=None):
    identity = hashlib.sha256(f"{kind}:{container or ''}:{path}".encode()).hexdigest()[:24]
    data = values(text)
    reason = ""
    try:
        address = ipaddress.ip_interface(data["Address"].split(",")[0].strip())
        port = int(data["ListenPort"].strip())
        if address.version != 4 or not 1 <= port <= 65535 or not 2 <= address.network.num_addresses <= 65536:
            raise ValueError()
        if len(base64.b64decode(data["PrivateKey"].strip(), validate=True)) != 32:
            raise ValueError()
        for allowed in re.findall(r"^\s*AllowedIPs\s*=\s*(.*?)\s*$", text, re.M):
            if any(ipaddress.ip_network(item.strip(), strict=False).prefixlen == 0 for item in allowed.split(",")):
                raise ValueError()
    except (KeyError, ValueError):
        reason = "Нет серверной IPv4 подсети/ListenPort либо конфигурация содержит маршрут по умолчанию"
        address, port = None, 0
    return {"id": identity, "kind": kind, "interface": iface, "config": str(path), "container": container,
            "active": active, "supported": not reason, "reason": reason,
            "address": str(address) if address else "", "port": port}


def inventory():
    result, seen = [], set()
    awg = shutil.which("awg")
    active = run([awg, "show", "interfaces"]).split() if awg else []
    for directory in CONFIG_DIRS:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.conf")):
            if not IFACE.fullmatch(path.stem) or path.resolve() in seen:
                continue
            seen.add(path.resolve())
            text = path.read_text()
            if directory.name == "wireguard" and not any(re.fullmatch(r"Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]", key) for key in values(text)):
                continue
            result.append(provider("native", path.stem, path, text, path.stem in active))
    if shutil.which("docker"):
        containers = run(["docker", "ps", "-a", "--format", "{{.Names}}"], check=False)
        if containers.returncode == 0:
            for name in containers.stdout.splitlines():
                if not re.fullmatch(r"amnezia-awg[A-Za-z0-9_.-]*", name):
                    continue
                status = json.loads(run(["docker", "inspect", name]))[0]
                interfaces = []
                if status["State"]["Running"]:
                    interfaces = run(["docker", "exec", name, "sh", "-c", "awg show interfaces 2>/dev/null || wg show interfaces"]).split()
                for path, text in docker_configurations(name):
                    iface = Path(path).stem
                    if IFACE.fullmatch(iface):
                        result.append(provider("docker", iface, path, text, iface in interfaces, name))
    selected_file = Path(os.environ.get("PNT_VPN_DATA", "/var/lib/pnt/vpn")) / "selected-server.json"
    selected = json.loads(selected_file.read_text())["id"] if selected_file.is_file() else None
    return [dict(item, selected=item["id"] == selected) for item in result]


def docker_configurations(container):
    result = subprocess.run(["docker", "cp", container + ":/opt/amnezia/awg/.", "-"], capture_output=True, timeout=30)
    if result.returncode:
        return []
    configurations = []
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        for entry in archive:
            path = Path(entry.name)
            if entry.isfile() and len(path.parts) == 1 and path.suffix == ".conf" and entry.size <= 1048576:
                configurations.append(("/opt/amnezia/awg/" + path.name, archive.extractfile(entry).read().decode()))
                if len(configurations) > 128:
                    raise RuntimeError("Слишком много конфигураций контейнера")
    return configurations


def configuration_text(binding):
    if binding["kind"] == "native":
        return Path(binding["config"]).read_text()
    return next(text for path, text in docker_configurations(binding["container"]) if path == binding["config"])


def write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".pnt-" + secrets.token_hex(6))
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "w") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def free_network(routes, configurations):
    used = []
    for route in routes:
        if route.get("dst") not in (None, "default", "0.0.0.0/0"):
            used.append(ipaddress.ip_network(route["dst"], strict=False))
    used.extend(ipaddress.ip_interface(c["address"]).network for c in configurations if c.get("address"))
    for pool in ("10.77.0.0/16", "172.27.0.0/16", "192.168.0.0/16"):
        for network in ipaddress.ip_network(pool).subnets(new_prefix=24):
            if not any(network.overlaps(other) for other in used if other.version == 4):
                return network
    raise RuntimeError("Не найдена свободная IPv4 подсеть для AmneziaWG")


def checkout(url, revision, directory):
    run(["git", "init", str(directory)])
    run(["git", "-C", str(directory), "fetch", "--depth", "1", url, revision], timeout=300)
    run(["git", "-C", str(directory), "checkout", "--detach", "FETCH_HEAD"])


def install_tools(native=True):
    missing = native and (not shutil.which("awg") or not shutil.which("awg-quick"))
    module = run(["modprobe", "amneziawg"], check=False) if native and shutil.which("modprobe") else None
    need_go = native and (module is None or module.returncode != 0) and not shutil.which("amneziawg-go")
    packages = [package for command, package in (("ip", "iproute2"), ("sysctl", "procps")) if not shutil.which(command)]
    if not Path("/etc/ssl/certs/ca-certificates.crt").exists():
        packages.append("ca-certificates")
    if not shutil.which("nft") and not shutil.which("iptables"):
        packages.append("nftables")
    if missing or need_go:
        packages += ["git", "build-essential", "pkg-config", "libmnl-dev"]
    if not packages and not missing and not need_go:
        return
    stage("Установка зависимостей Debian")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(["apt-get", "update"], timeout=600, env=env)
    run(["apt-get", "install", "-y", *packages], timeout=900, env=env)
    with tempfile.TemporaryDirectory(prefix="pnt-awg-") as temporary:
        work = Path(temporary)
        if missing:
            stage("Сборка официальных amneziawg-tools")
            source = work / "tools"
            checkout("https://github.com/amnezia-vpn/amneziawg-tools.git", TOOLS_COMMIT, source)
            run(["make", "-C", str(source / "src"), "-j2"], timeout=600)
            run(["make", "-C", str(source / "src"), "install", "PREFIX=/usr/local", "WITH_WGQUICK=yes", "WITH_SYSTEMDUNITS=no"], timeout=120)
        if need_go:
            stage("Сборка официального amneziawg-go")
            source = work / "go-source"
            checkout("https://github.com/amnezia-vpn/amneziawg-go.git", GO_COMMIT, source)
            with urllib.request.urlopen("https://go.dev/dl/?mode=json", timeout=30) as response:
                releases = json.load(response)
            arch = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armv6l"}.get(platform.machine())
            package = next((p for release in releases if release.get("stable") for p in release["files"]
                            if p["os"] == "linux" and p["arch"] == arch and p["kind"] == "archive"), None)
            if package is None:
                raise RuntimeError("Не найдена сборка Go для архитектуры узла")
            archive = work / "go.tar.gz"
            with urllib.request.urlopen("https://go.dev/dl/" + package["filename"], timeout=60) as response, archive.open("wb") as output:
                shutil.copyfileobj(response, output)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != package["sha256"]:
                raise RuntimeError("SHA-256 пакета Go не совпадает")
            with tarfile.open(archive) as tar:
                for item in tar.getmembers():
                    target = (work / item.name).resolve()
                    if not target.is_relative_to(work.resolve()) or not (item.isfile() or item.isdir()):
                        raise RuntimeError("Недопустимый путь в архиве Go")
                tar.extractall(work)
            env = dict(os.environ, GOTELEMETRY="off", GOTOOLCHAIN="auto", GOMAXPROCS="2", GOFLAGS="-p=1",
                       GOCACHE=str(work / "go-cache"), GOMODCACHE=str(work / "go-modules"), GOPATH=str(work / "go-path"))
            env["PATH"] = str(work / "go/bin") + ":" + env["PATH"]
            run(["make", "-C", str(source), "-j2"], timeout=900, env=env)
            run(["install", "-m", "0755", str(source / "amneziawg-go"), "/usr/local/bin/amneziawg-go"])


def create_configuration(configurations):
    existing = {item["interface"] for item in configurations}
    iface = next(("awg" + str(i) for i in range(64) if "awg" + str(i) not in existing and not Path("/sys/class/net/awg" + str(i)).exists()), None)
    if iface is None:
        raise RuntimeError("Не найдено свободное имя интерфейса awg")
    routes = json.loads(run(["ip", "-j", "-4", "route", "show", "table", "all"]))
    network = free_network(routes, configurations)
    port = None
    for candidate in range(51820, 51921):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind(("0.0.0.0", candidate))
                port = candidate
                break
            except OSError:
                pass
    if port is None:
        raise RuntimeError("Нет свободного UDP порта")
    private = run([shutil.which("awg"), "genkey"])
    if len(base64.b64decode(private, validate=True)) != 32:
        raise RuntimeError("Не удалось создать ключ AmneziaWG")
    headers = set()
    while len(headers) < 4:
        headers.add(secrets.randbelow(2**32 - 1) + 1)
    text = f"[Interface]\nPrivateKey = {private}\nAddress = {network.network_address + 1}/24\nListenPort = {port}\nMTU = 1280\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 32\nS2 = 64\n"
    text += "".join(f"H{i} = {value}\n" for i, value in enumerate(headers, 1))
    path = CONFIG_DIRS[0] / (iface + ".conf")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(text)
    return provider("native", iface, path, text)


def preserve_legacy(root):
    index = root / "servers"
    legacy = [p for p in root.glob("*.json") if CLIENT.fullmatch(p.stem)]
    if legacy and not any(json.loads(p.read_text()).get("legacy") for p in index.glob("*.json")):
        public = {json.loads(path.read_text())["public"] for path in legacy}
        matches = []
        for item in inventory():
            text = configuration_text(item)
            if all(key in text for key in public):
                matches.append(item)
        if len(matches) != 1:
            raise RuntimeError("Не удалось определить конфигурацию прежних клиентов PNT; выбор не изменён")
        previous = dict(matches[0], legacy=True)
        write(index / (previous["id"] + ".json"), json.dumps(previous))
        if not (root / "selected-server.json").exists():
            write(root / "selected-server.json", json.dumps(previous))


def save_binding(root, selected):
    preserve_legacy(root)
    index = root / "servers"
    previous_file = index / (selected["id"] + ".json")
    binding = json.loads(previous_file.read_text()) if previous_file.exists() else selected
    write(previous_file, json.dumps(binding))
    write(root / "selected-server.json", json.dumps(binding))


def forwarding():
    write("/etc/sysctl.d/99-pnt-vpn.conf", "net.ipv4.ip_forward=1\n", 0o644)
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])


def firewall_spec(binding):
    route = json.loads(run(["ip", "-j", "-4", "route", "get", "1.1.1.1"]))[0]
    outgoing = route["dev"]
    if not IFACE.fullmatch(outgoing):
        raise RuntimeError("Недопустимое имя выходного интерфейса")
    iface, subnet, port = binding["interface"], str(ipaddress.ip_interface(binding["address"]).network), binding["port"]
    incoming = None
    if binding["kind"] == "docker":
        state = json.loads(run(["docker", "inspect", binding["container"]]))[0]
        if state["HostConfig"]["NetworkMode"] != "host":
            entry = next((p for p in state["NetworkSettings"]["Ports"].get(str(port) + "/udp", []) or [] if ":" not in p["HostIp"]), None)
            if entry is None:
                raise RuntimeError("UDP порт контейнера не опубликован на IPv4")
            published = int(entry["HostPort"])
            name, net = next((name, net) for name, net in state["NetworkSettings"]["Networks"].items() if net.get("IPAddress"))
            details = json.loads(run(["docker", "network", "inspect", name]))[0]
            iface = details.get("Options", {}).get("com.docker.network.bridge.name") or ("docker0" if name == "bridge" else "br-" + details["Id"][:12])
            subnet = str(ipaddress.ip_address(net["IPAddress"])) + "/32"
            incoming = (str(ipaddress.ip_address(net["IPAddress"])), port)
            port = published
    if not IFACE.fullmatch(iface):
        raise RuntimeError("Недопустимое имя интерфейса VPN")
    return {"interface": iface, "subnet": subnet, "port": port, "outgoing": outgoing, "incoming": incoming}


def nft_rules(spec, chains, marker):
    commands = []
    for chain in chains:
        family, table, name, hook = (chain[k] for k in ("family", "table", "name", "hook"))
        if family not in ("ip", "inet") or hook not in ("input", "forward"):
            continue
        prefix = f"insert rule {family} {nft_identifier(table)} {nft_identifier(name)} "
        if hook == "input":
            commands.append(prefix + f'udp dport {spec["port"]} accept comment "{marker}"')
        else:
            commands += [prefix + f'iifname "{spec["interface"]}" ip saddr {spec["subnet"]} oifname "{spec["outgoing"]}" accept comment "{marker}"',
                         prefix + f'oifname "{spec["interface"]}" ip daddr {spec["subnet"]} ct state established,related accept comment "{marker}"']
            if spec["incoming"]:
                address, port = spec["incoming"]
                commands.append(prefix + f'ip daddr {address} udp dport {port} accept comment "{marker}"')
    commands.append(f'add rule ip pnt_vpn_nat postrouting ip saddr {spec["subnet"]} oifname "{spec["outgoing"]}" masquerade comment "{marker}"')
    return commands


def nft_identifier(value):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", value):
        raise RuntimeError("Неподдерживаемое имя таблицы или цепочки nftables")
    return value


def apply_firewall(binding):
    root = Path(os.environ["PNT_VPN_DATA"])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        configure_firewall(binding)


def configure_firewall(binding):
    spec = firewall_spec(binding)
    marker = "pnt-vpn-" + binding["id"]
    nft = shutil.which("nft")
    ipt = shutil.which("iptables")
    if nft:
        ruleset = json.loads(run([nft, "-j", "list", "ruleset"]))["nftables"]
        chains = [item["chain"] for item in ruleset if "chain" in item]
        commands = [f'delete rule {r["family"]} {nft_identifier(r["table"])} {nft_identifier(r["chain"])} handle {int(r["handle"])}'
                    for item in ruleset if "rule" in item for r in [item["rule"]] if r.get("comment") == marker]
        tables = {(item["table"]["family"], item["table"]["name"]) for item in ruleset if "table" in item}
        if ("ip", "pnt_vpn_nat") not in tables:
            commands.append("add table ip pnt_vpn_nat")
        if not any(c["family"] == "ip" and c["table"] == "pnt_vpn_nat" and c["name"] == "postrouting" for c in chains):
            commands.append("add chain ip pnt_vpn_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }")
        if not any(c.get("hook") in ("input", "forward") and c["family"] in ("ip", "inet") for c in chains):
            if ("inet", "pnt_vpn") not in tables:
                commands.append("add table inet pnt_vpn")
            for hook in ("input", "forward"):
                commands.append(f"add chain inet pnt_vpn {hook} {{ type filter hook {hook} priority filter; policy accept; }}")
                chains.append({"family": "inet", "table": "pnt_vpn", "name": hook, "hook": hook})
        commands += nft_rules(spec, chains, marker)
        run([nft, "-f", "-"], "\n".join(commands) + "\n")
    legacy = ipt and (not nft or "legacy" in run([ipt, "--version"]))
    if legacy:
        for table, chain in (("filter", "INPUT"), ("filter", "FORWARD"), ("nat", "POSTROUTING")):
            for line in run([ipt, "-w", "-t", table, "-S", chain]).splitlines():
                tokens = shlex.split(line)
                if len(tokens) > 3 and tokens[:2] == ["-A", chain] and "--comment" in tokens:
                    position = tokens.index("--comment")
                    if position + 1 < len(tokens) and tokens[position + 1] == marker:
                        run([ipt, "-w", "-t", table, "-D", chain, *tokens[2:]])
        rules = [("filter", "INPUT", ["-p", "udp", "--dport", str(spec["port"])]),
                 ("filter", "FORWARD", ["-i", spec["interface"], "-s", spec["subnet"], "-o", spec["outgoing"]]),
                 ("filter", "FORWARD", ["-o", spec["interface"], "-d", spec["subnet"], "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"])]
        if spec["incoming"]:
            address, port = spec["incoming"]
            rules.append(("filter", "FORWARD", ["-d", address, "-p", "udp", "--dport", str(port)]))
        for table, chain, args in rules + [("nat", "POSTROUTING", ["-s", spec["subnet"], "-o", spec["outgoing"]])]:
            args += ["-m", "comment", "--comment", marker, "-j", "MASQUERADE" if table == "nat" else "ACCEPT"]
            if run([ipt, "-w", "-t", table, "-C", chain, *args], check=False).returncode:
                run([ipt, "-w", "-t", table, "-I", chain, "1", *args])
    if not nft and not ipt:
        raise RuntimeError("Не найден nftables или iptables")


def setup(root, choice, source):
    if os.geteuid() != 0 or not Path("/etc/debian_version").exists():
        raise RuntimeError("Установка поддерживается от root на Debian Linux")
    configurations = inventory()
    selected = next((item for item in configurations if item["id"] == choice), None)
    if choice != "new" and (selected is None or not selected["supported"]):
        raise RuntimeError("Выбранная серверная конфигурация не найдена или непригодна")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / "server-install.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        preserve_legacy(root)
        if selected is not None and selected["kind"] == "native" and selected["active"]:
            text = Path(selected["config"]).read_text()
            public = run([shutil.which("awg"), "pubkey"], values(text)["PrivateKey"].strip() + "\n")
            actual = run([shutil.which("awg"), "show", selected["interface"], "public-key"])
            if public != actual:
                raise RuntimeError("Имя интерфейса занято другой конфигурацией; существующий интерфейс не изменён")
            addresses = json.loads(run(["ip", "-j", "-4", "address", "show", "dev", selected["interface"]]))
            expected = ipaddress.ip_interface(selected["address"])
            if not any(a.get("local") == str(expected.ip) and a.get("prefixlen") == expected.network.prefixlen
                       for item in addresses for a in item.get("addr_info", [])):
                raise RuntimeError("Адрес активного интерфейса не совпадает с конфигурацией; существующий интерфейс не изменён")
        install_tools(selected is None or selected["kind"] == "native")
        if selected is None:
            selected = create_configuration(inventory())
            stage("Создан интерфейс " + selected["interface"])
        write(root / "server_setup.py", source)
        metadata = root / "servers" / (selected["id"] + ".json")
        if not metadata.exists():
            write(metadata, json.dumps(selected))
        forwarding()
        iface = selected["interface"]
        if selected["kind"] == "native":
            existing = "awg-quick@" + iface + ".service"
            if run(["systemctl", "is-active", "--quiet", existing], check=False).returncode == 0:
                canonical = Path("/etc/amnezia/amneziawg") / (iface + ".conf")
                command = run(["systemctl", "show", "-p", "ExecStart", "--value", existing])
                explicit = re.search(r"(?<!\S)" + re.escape(selected["config"]) + r"(?=\s|;|$)", command)
                if Path(selected["config"]).resolve() != canonical.resolve() and not explicit:
                    raise RuntimeError("Активный awg-quick использует стандартный путь; выберите соответствующую конфигурацию")
                owner = existing
                run(["systemctl", "enable", owner])
            else:
                owner = "pnt-awg-" + iface + ".service"
                script, data = json.dumps(str(root / "server_setup.py")), json.dumps("PNT_VPN_DATA=" + str(root))
                unit = f"[Unit]\nDescription=PNT AmneziaWG {iface}\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment={data}\nExecStart=/usr/bin/python3 {script} up {selected['id']}\nExecStop=/usr/bin/python3 {script} down {selected['id']}\n\n[Install]\nWantedBy=multi-user.target\n"
                write("/etc/systemd/system/" + owner, unit, 0o644)
                run(["systemctl", "daemon-reload"])
                run(["systemctl", "enable", "--now", owner], timeout=120)
        else:
            owner = "docker.service"
            run(["docker", "update", "--restart", "unless-stopped", selected["container"]])
            run(["docker", "start", selected["container"]], timeout=120)
        stage("Настройка forwarding и брандмауэра")
        apply_firewall(selected)
        unit = f"[Unit]\nDescription=PNT VPN firewall {iface}\nAfter=network-online.target nftables.service netfilter-persistent.service ufw.service {owner}\nRequires={owner}\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment={json.dumps('PNT_VPN_DATA=' + str(root))}\nExecStart=/usr/bin/python3 {json.dumps(str(root / 'server_setup.py'))} firewall {selected['id']}\nExecReload=/usr/bin/python3 {json.dumps(str(root / 'server_setup.py'))} firewall {selected['id']}\n\n[Install]\nWantedBy=multi-user.target\n"
        name = "pnt-vpn-firewall-" + selected["id"] + ".service"
        write("/etc/systemd/system/" + name, unit, 0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", name])
        save_binding(root, selected)
        stage("AmneziaWG настроен: " + iface)
        return selected


def service_action(root, action, identity):
    if not IDENTITY.fullmatch(identity):
        raise ValueError("Invalid configuration ID")
    binding = json.loads((root / "servers" / (identity + ".json")).read_text())
    if action == "firewall":
        forwarding()
        apply_firewall(binding)
    elif action in ("up", "down") and binding["kind"] == "native":
        active = binding["interface"] in run([shutil.which("awg"), "show", "interfaces"]).split()
        if active != (action == "up"):
            run([shutil.which("awg-quick"), action, binding["config"]], timeout=120)
    else:
        raise ValueError("Invalid service action")


if __name__ == "__main__":
    try:
        root = Path(os.environ["PNT_VPN_DATA"])
        if len(sys.argv) == 3:
            service_action(root, sys.argv[1], sys.argv[2])
        else:
            request = json.load(sys.stdin)
            if request["action"] == "inventory":
                print(json.dumps(inventory()))
            elif request["action"] == "install":
                setup(root, request["selection"], request["source"])
            else:
                raise ValueError("Unknown installer action")
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
