import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.name == "nt":
    sys.modules["fcntl"] = types.SimpleNamespace(flock=lambda *_: None, LOCK_EX=2)

source = Path(__file__).resolve().parents[2] / "deploy" / "vpn_adapter.py"
spec = importlib.util.spec_from_file_location("vpn_adapter", source)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class AdapterChecks(unittest.TestCase):
    def check_backend(self, backend, selected=False):
        key = lambda n: base64.b64encode(bytes([n]) * 32).decode()
        config = "[Interface]\nPrivateKey = " + key(1) + "\nAddress = 10.8.0.1/24\nListenPort = 51820\nJc = 4\nH1 = 123\n\n[Peer]\nPublicKey = " + key(2) + "\nAllowedIPs = 10.8.0.2/32\n"
        generated = 0
        active = {}

        def run(args, data=None):
            nonlocal config, generated
            if args[:2] == ["docker", "ps"]:
                return ("amnezia-awg\namnezia-awg2" if selected else "amnezia-awg") if backend == "docker" else ""
            if args[:2] == ["docker", "inspect"]:
                return json.dumps([{"NetworkSettings": {"Ports": {"51820/udp": [{"HostIp": "0.0.0.0", "HostPort": "40000"}]}}}])
            if args[:3] == ["docker", "exec", "-i"]:
                args = args[4:]
            if args == ["/usr/bin/awg", "show", "interfaces"]:
                return "awg0 awg1" if selected else "awg0"
            if args[:2] == ["sh", "-c"]:
                if "command -v" in args[2]:
                    return "/usr/bin/awg"
                if "pnt-new" in args[2]:
                    config = data
                else:
                    active[args[-3]] = True
                return ""
            if args[0] == "cat":
                return config
            if args[-1] == "genkey":
                generated += 1
                return key(10 + generated)
            if args[-1] == "pubkey":
                return key(20 + generated)
            if args[-1] == "genpsk":
                return key(30 + generated)
            if args[-1] == "public-key":
                return key(40)
            if args[-1] == "remove":
                active.pop(args[-2], None)
                return ""
            if args[-1] == "dump":
                return "private\tpublic\t51820\t0\n" + "\n".join(public + "\tpsk\t(endpoint)\t10.8.0.3/32\t12345\t100\t200\t20" for public in active)
            raise AssertionError(args)

        original_is_file = Path.is_file

        def is_file(path):
            if str(path).replace("\\", "/") == "/etc/amneziawg/awg0.conf":
                return True
            return original_is_file(path)

        with tempfile.TemporaryDirectory(prefix="pnt-adapter-check-") as root, patch.dict(os.environ, PNT_VPN_DATA=root), patch.object(adapter, "run", run), patch.object(adapter.shutil, "which", lambda name: "/usr/bin/" + name if name == "docker" or (name == "awg" and backend == "native") else None), patch.object(Path, "is_file", is_file):
            state = Path(root)
            if selected:
                binding = {"id": "c" * 24, "kind": backend, "container": "amnezia-awg" if backend == "docker" else None,
                           "interface": "awg0", "config": "/opt/amnezia/awg/awg0.conf" if backend == "docker" else "/etc/amneziawg/awg0.conf"}
                (Path(root) / "selected-server.json").write_text(json.dumps(binding))
                (Path(root) / "servers").mkdir()
                (Path(root) / "servers" / (binding["id"] + ".json")).write_text(json.dumps(binding))
                state = Path(root) / "instances" / binding["id"]
            self.assertEqual(adapter.execute({"action": "probe"})["protocol"], "awg")
            first = adapter.execute({"action": "ensure", "client": "a" * 16})
            self.assertIn("10.8.0.3/32", first["config"])
            self.assertIn("Jc = 4", first["config"])
            self.assertEqual(first["port"], 40000 if backend == "docker" else 51820)
            self.assertNotIn(key(1), first["config"])
            again = adapter.execute({"action": "ensure", "client": "a" * 16})
            self.assertEqual(first, again)
            self.assertEqual(generated, 1)
            stats = adapter.execute({"action": "stats", "client": "a" * 16})
            self.assertEqual(stats, {"handshake": 12345, "received": 100, "sent": 200, "exists": True})
            second = adapter.execute({"action": "ensure", "client": "b" * 16})
            self.assertIn("10.8.0.4/32", second["config"])
            clients = adapter.execute({"action": "clients"})
            self.assertEqual(set(clients), {"a" * 16, "b" * 16})
            self.assertEqual(clients["a" * 16], stats)
            self.assertTrue(clients["b" * 16]["exists"])
            adapter.execute({"action": "reconcile", "allowed": ["b" * 16]})
            self.assertNotIn(key(21), config)
            self.assertIn(key(22), config)
            self.assertIn(key(2), config)
            self.assertFalse((state / ("a" * 16 + ".json")).exists())
            self.assertFalse(adapter.execute({"action": "stats", "client": "a" * 16})["exists"])
            self.assertEqual(set(adapter.execute({"action": "clients"})), {"b" * 16})

    def test_native(self):
        self.check_backend("native")

    def test_docker(self):
        self.check_backend("docker")

    def test_selected_native_with_multiple_interfaces(self):
        self.check_backend("native", True)

    def test_selected_docker_with_multiple_containers(self):
        self.check_backend("docker", True)

    def test_wireguard_binary_is_not_used_when_awg_is_missing(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, PNT_VPN_DATA=root), patch.object(adapter.shutil, "which", lambda name: "/usr/bin/wg" if name == "wg" else None), patch.object(adapter, "run") as command:
            binding = {"id": "c" * 24, "kind": "native", "interface": "awg0", "config": "/etc/amnezia/amneziawg/awg0.conf"}
            (Path(root) / "selected-server.json").write_text(json.dumps(binding))
            with self.assertRaisesRegex(RuntimeError, "awg not found"):
                adapter.execute({"action": "probe"})
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
