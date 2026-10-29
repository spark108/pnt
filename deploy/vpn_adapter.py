import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run(args, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError("VPN container command failed: " + " ".join(args[:4]))
    return result.stdout.strip()


def execute(request):
    root = Path(os.environ["PNT_VPN_DATA"])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    action = request["action"]
    if action not in ("probe", "ensure", "stats", "reconcile"):
        raise ValueError("Unknown adapter action")
    client = request.get("client")
    if client is not None and not re.fullmatch("[0-9a-f]{16}", client):
        raise ValueError("Invalid client ID")
    if action == "reconcile" and not list(root.glob("*.json")):
        return {}
    try:
        names = run(["docker", "ps", "--format", "{{.Names}}"] ).splitlines() if shutil.which("docker") else []
    except RuntimeError:
        names = []
    candidates = [name for name in names if name in ("amnezia-awg", "amnezia-awg2")]
    native_binary = shutil.which("awg")
    native_interfaces = run([native_binary, "show", "interfaces"]).split() if native_binary else []
    if len(candidates) + len(native_interfaces) != 1:
        raise RuntimeError("Expected exactly one active AmneziaWG service (Docker or native)")
    container = candidates[0] if candidates else None
    iface = "awg0" if container else native_interfaces[0]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", iface):
        raise RuntimeError("Unsupported AWG interface name")

    def docker(args, data=None):
        return run((["docker", "exec", "-i", container] if container else []) + args, data)

    binary = "awg" if docker(["sh", "-c", "command -v awg || command -v wg"]).endswith("awg") else "wg"
    config_path = "/opt/amnezia/awg/awg0.conf"
    if not container:
        config_paths = [Path(directory) / (iface + ".conf") for directory in ("/etc/amnezia/amneziawg", "/etc/amneziawg", "/etc/wireguard", "/opt/amnezia/awg")]
        existing = [path for path in config_paths if path.is_file()]
        if len(existing) != 1:
            raise RuntimeError("Cannot uniquely locate the native AmneziaWG interface configuration")
        config_path = str(existing[0])
    config = docker(["cat", config_path])
    interface = config.split("[Peer]", 1)[0]
    values = dict(re.findall(r"^\s*([A-Za-z0-9]+)\s*=\s*(.*?)\s*$", interface, re.M))
    address = ipaddress.ip_interface(values["Address"].split(",")[0].strip())
    if address.version != 4:
        raise RuntimeError("An IPv4 AWG server subnet is required")
    internal_port = int(values["ListenPort"])
    port, local_host = internal_port, "127.0.0.1"
    if container:
        inspection = json.loads(run(["docker", "inspect", container]))[0]
        bindings = inspection["NetworkSettings"]["Ports"].get(str(internal_port) + "/udp") or []
        binding = next((item for item in bindings if ":" not in item["HostIp"]), None)
        if not binding:
            raise RuntimeError("AWG UDP port is not published on an IPv4 host address")
        port = int(binding["HostPort"])
        local_host = "127.0.0.1" if binding["HostIp"] in ("", "0.0.0.0") else binding["HostIp"]
    if action == "probe":
        docker([binary, "show", iface, "public-key"])
        return {"protocol": "awg", "port": port}

    def save(path, value):
        temp = path.with_suffix(".tmp")
        with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)

    def write_config(text):
        docker(["sh", "-c", 'umask 077; cat > "$1.pnt-new" && mv "$1.pnt-new" "$1"', "pnt", config_path], text + "\n")

    path = root / (str(client) + ".json")
    with (root / "adapter.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = docker(["cat", config_path])
        if action == "reconcile":
            allowed = set(request.get("allowed", []))
            for entry in root.glob("*.json"):
                if entry.stem in allowed:
                    continue
                profile = json.loads(entry.read_text())
                public = profile["public"]
                docker([binary, "set", iface, "peer", public, "remove"])
                blocks = config.split("[Peer]")
                config = blocks[0] + "".join("[Peer]" + block for block in blocks[1:] if not re.search(r"^\s*PublicKey\s*=\s*" + re.escape(public) + r"\s*$", block, re.M))
                write_config(config)
                entry.unlink()
            return {}
        if action == "stats":
            if not path.exists():
                return {"handshake": 0, "received": 0, "sent": 0, "exists": False}
            public = json.loads(path.read_text())["public"]
            rows = docker([binary, "show", iface, "dump"]).splitlines()[1:]
            row = next((line.split("\t") for line in rows if line.split("\t")[0] == public), None)
            return {"handshake": int(row[4]) if row else 0, "received": int(row[5]) if row else 0, "sent": int(row[6]) if row else 0, "exists": row is not None}
        if path.exists():
            profile = json.loads(path.read_text())
            if ipaddress.ip_address(profile["address"]) not in address.network:
                raise RuntimeError("VPN subnet changed; revoke and recreate this client's VPN profile")
        else:
            used = {str(address.ip)}
            for item in re.findall(r"^\s*AllowedIPs\s*=\s*(.*?)\s*$", config, re.M):
                for network in item.split(","):
                    subnet = ipaddress.ip_network(network.strip(), strict=False)
                    if subnet.version == 4:
                        if subnet.num_addresses > 65536:
                            raise RuntimeError("Server contains a broad AllowedIPs range; allocation requires manual review")
                        used.update(str(ip) for ip in subnet)
            selected = next((str(ip) for ip in address.network.hosts() if str(ip) not in used), None)
            if not selected:
                raise RuntimeError("No free VPN client address")
            private = docker([binary, "genkey"])
            public = docker([binary, "pubkey"], private + "\n")
            psk = docker([binary, "genpsk"])
            profile = {"private": private, "public": public, "psk": psk, "address": selected}
            save(path, profile)
        public = profile["public"]
        if not re.search(r"^\s*PublicKey\s*=\s*" + re.escape(public) + r"\s*$", config, re.M):
            config += "\n\n[Peer]\nPublicKey = " + public + "\nPresharedKey = " + profile["psk"] + "\nAllowedIPs = " + profile["address"] + "/32\n"
            write_config(config)
        docker(["sh", "-c", 'umask 077; p=$(mktemp); trap \'rm -f "$p"\' EXIT; cat > "$p"; "$1" set "$4" peer "$2" preshared-key "$p" allowed-ips "$3"', "pnt", binary, public, profile["address"] + "/32", iface], profile["psk"] + "\n")
        server_public = docker([binary, "show", iface, "public-key"])
        options = {k: v for k, v in values.items() if re.fullmatch(r"(?:Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies)", k)}
        native = "[Interface]\nPrivateKey = " + profile["private"] + "\nAddress = " + profile["address"] + "/32\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n"
        native += "".join(k + " = " + v + "\n" for k, v in options.items())
        native += "\n[Peer]\nPublicKey = " + server_public + "\nPresharedKey = " + profile["psk"] + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = PNT_ENDPOINT\nPersistentKeepalive = 20\n"
        return {"config": native, "host": "", "port": port, "localHost": local_host, "localPort": port}


if __name__ == "__main__":
    try:
        print(json.dumps(execute(json.load(sys.stdin))))
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
