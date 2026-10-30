import base64
import importlib.util
import io
import ipaddress
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name == "nt":
    sys.modules["fcntl"] = types.SimpleNamespace(flock=lambda *_: None, LOCK_EX=2)

source = Path(__file__).resolve().parents[2] / "deploy" / "vpn_server.py"
spec = importlib.util.spec_from_file_location("vpn_server", source)
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)
KEY = base64.b64encode(bytes(range(32))).decode()
CONFIG = "[Interface]\nPrivateKey = " + KEY + "\nAddress = 10.77.0.1/24\nListenPort = 51820\n"


class ServerChecks(unittest.TestCase):
    def test_inventory_lists_multiple_configs_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "awg0.conf").write_text(CONFIG)
            (path / "awg1.conf").write_text(CONFIG.replace("10.77.0.1", "10.78.0.1"))
            with patch.object(server, "CONFIG_DIRS", [path]), patch.object(server.shutil, "which", lambda binary: "/usr/bin/awg" if binary == "awg" else None), patch.object(server, "run", return_value="awg0"):
                configs = server.inventory()
            self.assertEqual(len(configs), 2)
            self.assertTrue(configs[0]["active"])
            self.assertFalse(configs[1]["active"])
            self.assertNotIn(KEY, json.dumps(configs))
            self.assertTrue(all(c["supported"] for c in configs))

    def test_client_config_cannot_be_adopted_as_server(self):
        config = CONFIG + "\n[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.org:443\n"
        item = server.provider("native", "awg0", "/etc/amnezia/amneziawg/awg0.conf", config)
        self.assertFalse(item["supported"])
        self.assertNotIn(KEY, json.dumps(item))

    def test_wireguard_directory_requires_amnezia_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wireguard = root / "wireguard"
            amnezia = root / "amnezia" / "amneziawg"
            wireguard.mkdir()
            amnezia.mkdir(parents=True)
            (wireguard / "wg0.conf").write_text(CONFIG)
            (wireguard / "wg1.conf").write_text(CONFIG + "# Jc = 4\n[Peer]\n# H1 = 123\n")
            (wireguard / "awg0.conf").write_text(CONFIG + "Jc = 4\n")
            (amnezia / "awg1.conf").write_text(CONFIG)
            with patch.object(server, "CONFIG_DIRS", [wireguard, amnezia]), patch.object(server.shutil, "which", return_value=None):
                configs = server.inventory()
            self.assertEqual({c["interface"] for c in configs}, {"awg0", "awg1"})
            self.assertTrue(all(c["supported"] for c in configs))

    def test_network_allocation_avoids_routes_and_other_awg_configs(self):
        routes = [{"dst": "default"}, {"dst": "10.77.0.0/24"}]
        network = server.free_network(routes, [{"address": "10.77.1.1/24"}])
        self.assertEqual(str(network), "10.77.2.0/24")
        network = server.free_network([{"dst": "10.0.0.0/8"}], [])
        self.assertEqual(str(network), "172.27.0.0/24")

    def test_only_wireguard_without_awg_leaves_inventory_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            wireguard = Path(directory) / "wireguard"
            amnezia = Path(directory) / "amnezia" / "amneziawg"
            wireguard.mkdir()
            config = wireguard / "wg0.conf"
            config.write_text(CONFIG)
            with patch.object(server, "CONFIG_DIRS", [amnezia, wireguard]), patch.object(server.shutil, "which", return_value=None), patch.object(server, "run") as command:
                self.assertEqual(server.inventory(), [])
            command.assert_not_called()
            self.assertEqual(config.read_text(), CONFIG)
            self.assertFalse(amnezia.exists())

    def test_missing_awg_tools_are_installed_before_configuration(self):
        commands = []
        def run(args, *_, **kwargs):
            commands.append(args)
            return types.SimpleNamespace(returncode=0) if kwargs.get("check") is False else ""
        with patch.object(server.shutil, "which", lambda name: "/usr/sbin/modprobe" if name == "modprobe" else None), patch.object(server, "run", run), patch.object(server, "checkout") as checkout, patch.object(server, "stage"):
            server.install_tools()
        self.assertTrue(any(args[:3] == ["apt-get", "install", "-y"] and "build-essential" in args for args in commands))
        checkout.assert_called_once()
        self.assertEqual(checkout.call_args.args[0], "https://github.com/amnezia-vpn/amneziawg-tools.git")
        self.assertTrue(any(args[0] == "make" and "install" in args and "WITH_WGQUICK=yes" in args for args in commands))

    def test_new_config_does_not_overwrite_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            existing = path / "awg0.conf"
            existing.write_text(CONFIG)
            def run(args, *_, **__):
                return "[]" if args[0] == "ip" else KEY
            with patch.object(server, "CONFIG_DIRS", [path]), patch.object(server, "run", run), patch.object(server.shutil, "which", return_value="/usr/bin/awg"):
                created = server.create_configuration([{"interface": "awg0", "address": "10.77.0.1/24"}])
            self.assertEqual(created["interface"], "awg1")
            self.assertEqual(existing.read_text(), CONFIG)
            self.assertEqual(str(ipaddress.ip_interface(created["address"]).network), "10.77.1.0/24")
            self.assertIn("Jc = 4", (path / "awg1.conf").read_text())

    def test_legacy_client_keys_remain_bound_to_original_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_file, new_file = root / "awg0.conf", root / "awg1.conf"
            old_file.write_text(CONFIG + "\n[Peer]\nPublicKey = original-client-key\nAllowedIPs = 10.77.0.2/32\n")
            new_file.write_text(CONFIG.replace("10.77.0.1", "10.77.1.1"))
            old = server.provider("native", "awg0", old_file, old_file.read_text(), True)
            new = server.provider("native", "awg1", new_file, new_file.read_text(), True)
            (root / ("a" * 16 + ".json")).write_text(json.dumps({"public": "original-client-key"}))
            with patch.object(server, "inventory", return_value=[old, new]):
                server.preserve_legacy(root)
                self.assertEqual(json.loads((root / "selected-server.json").read_text())["id"], old["id"])
                server.save_binding(root, new)
            selected = json.loads((root / "selected-server.json").read_text())
            previous = json.loads((root / "servers" / (old["id"] + ".json")).read_text())
            self.assertEqual(selected["id"], new["id"])
            self.assertTrue(previous["legacy"])
            self.assertTrue((root / ("a" * 16 + ".json")).exists())

    def test_stopped_docker_config_can_be_discovered_without_starting_it(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            entry = tarfile.TarInfo("./awg0.conf")
            entry.size = len(CONFIG.encode())
            archive.addfile(entry, io.BytesIO(CONFIG.encode()))
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            return types.SimpleNamespace(returncode=0, stdout=data.getvalue())
        with patch.object(server.subprocess, "run", command):
            configurations = server.docker_configurations("amnezia-awg")
        self.assertEqual(configurations, [("/opt/amnezia/awg/awg0.conf", CONFIG)])
        self.assertNotIn("start", calls[0])

    def test_nft_updates_only_owned_rules(self):
        binding = {"id": "a" * 24}
        marker = "pnt-vpn-" + binding["id"]
        spec = {"interface": "awg0", "subnet": "10.77.0.0/24", "port": 51820, "outgoing": "eth0", "incoming": None}
        ruleset = {"nftables": [
            {"table": {"family": "inet", "name": "filter"}},
            {"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input"}},
            {"chain": {"family": "inet", "table": "filter", "name": "forward", "hook": "forward"}},
            {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "comment": marker}},
            {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "comment": "user-rule"}}]}
        batches = []
        def run(args, data=None, **kwargs):
            if "ruleset" in args:
                return json.dumps(ruleset)
            batches.append(data)
            return ""
        with patch.object(server, "firewall_spec", return_value=spec), patch.object(server, "run", run), patch.object(server.shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None):
            server.configure_firewall(binding)
        batch = batches[0]
        self.assertIn("handle 4", batch)
        self.assertNotIn("handle 5", batch)
        self.assertIn("udp dport 51820 accept", batch)
        self.assertIn("masquerade", batch)
        self.assertIn("ct state established,related", batch)
        self.assertNotIn("flush", batch)

    def test_iptables_rules_are_idempotent(self):
        spec = {"interface": "awg0", "subnet": "10.77.0.0/24", "port": 51820, "outgoing": "eth0", "incoming": None}
        inserted, present = [], set()
        def run(args, data=None, **kwargs):
            if "--version" in args:
                return "iptables v1.8.11 (legacy)"
            if "-S" in args:
                chain = args[-1]
                return "\n".join("-A " + shlex.join(item) for item in present if item[0] == chain)
            if "-D" in args:
                position = args.index("-D")
                present.remove(tuple(args[position + 1:]))
                return ""
            if "-C" in args:
                key = tuple(args[args.index("-C") + 1:])
                return types.SimpleNamespace(returncode=0 if key in present else 1)
            inserted.append(args)
            position = args.index("-I")
            present.add(tuple([args[position + 1], *args[position + 3:]]))
            return ""
        with patch.object(server, "firewall_spec", return_value=spec), patch.object(server, "run", run), patch.object(server.shutil, "which", lambda name: "/usr/sbin/iptables" if name == "iptables" else None):
            server.configure_firewall({"id": "a" * 24})
            server.configure_firewall({"id": "a" * 24})
        self.assertEqual(len(inserted), 8)
        self.assertEqual(len(present), 4)
        self.assertTrue(any("MASQUERADE" in item for item in inserted))


if __name__ == "__main__":
    unittest.main()
