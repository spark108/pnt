# PNT

[Русский](Readme_RU.md) · [PNT VPN client](https://github.com/spark108/amnezia-pnt)

PNT is a .NET 10 service for a trusted, decentralized cluster of Debian and Windows servers. It provides routed remote commands, TCP forwarding, monitoring, a web globe and managed AmneziaWG access for restricted VPN clients. Each node keeps its own SQLite database and persistent certificate. Encrypted connections and route discovery run in the background, including reverse connections from nodes behind NAT.

## Install and update

On Debian 12 or 13, run from a source checkout:

```sh
git clone https://github.com/spark108/pnt.git
cd pnt
sudo ./pnt.sh install
sudo ./pnt.sh start
sudo ./pnt.sh stop
sudo ./pnt.sh restart
./pnt.sh status
sudo ./pnt.sh update
```

Installation prepares the .NET 10 SDK, libmsquic, Git, SSH, PTY and firewall dependencies, publishes a self-contained binary and starts `pnt.service`. Keep the checkout: installed management commands use its installer. If address detection is wrong, set `PNT_ADVERTISE_IP` in `/etc/default/pnt` and restart before joining/initializing.

On Windows, open the source checkout in an elevated terminal:

```bat
pnt.bat install
pnt.bat update
pnt.bat start
pnt.bat stop
pnt.bat restart
pnt.bat status
```

The installer prepares Git/.NET, registers the automatic `PNT` service under LocalSystem and adds `pnt.cmd` to the machine PATH. Open a new terminal afterward. `npt.bat` is a compatibility script name. For old SQLite permission errors, update the checkout and run `pnt.bat repair` as administrator; identity/data are preserved.

The installed CLI also provides `pnt install`, `pnt update` and `pnt update --check`. Install/update uses a background worker with live logs and a progress footer; closing the viewer does not cancel it. Updates fetch sources first, reload the new installer, apply its dependencies, rebuild and restart. Failed installation stages attempt rollback.

A manual update announces an event to the cluster, even for an already installed commit. Peers apply it without a loop; offline peers receive it after reconnecting. Updating nodes display `update`. Old installations need an initial local update to gain this behavior.

### Remote Debian installation

```sh
pnt install -r root@192.0.2.20
# Script alternative:
sudo ./pnt.sh install -r root@192.0.2.20
```

PNT chooses a reachable Linux executor with SSH access to the target and returns prompts/logs through cluster routes. After SSH authentication, the installer registers the new node and sends its cluster connection credentials and certificate-pinned bootstrap state over SSH stdin. No join request, approval polling or manual acceptance is required; the new service opens the outbound cluster connection automatically. Credentials are not written to command arguments or installation logs. Existing cluster membership is never overwritten. SSH authentication is interactive when needed; PNT does not save passwords. Install Windows targets locally.

## Cluster management

```sh
# First member:
pnt node init 'replace-with-your-cluster-key'
pnt node name edge-1
# New member, with its service running:
pnt node identity --fingerprint
pnt node join 192.0.2.10
pnt node status
# Existing member:
pnt node requests
pnt node accept <new-node-id>
pnt node reject <new-node-id>

pnt node list
pnt node list <source-node>
pnt node list --interactive
pnt node routes [node]
pnt node relay enable [node]
pnt node relay disable [node]
pnt node relay status [node]
pnt node kick <node>
pnt node remove <node>
pnt node leave
pnt node <id> reboot
pnt node <id> reboot -f
```

Verify identities/certificates before approval. Bootstrap uses trust on first use: compare the pinned certificate from `node status` through a trusted channel. Pending requests expire after ten minutes. Invitations are available under `pnt node invite`.

A NAT node needs outbound access to a known member, without inbound port mapping. There is no public rendezvous service or UDP hole punching. Confirmed direct paths take priority; alternatives consider NAT transit, latency and stability.

Inter-node latency uses short PNT requests, not ICMP; relays are named. `node list <source-node>` shows that node's measurements. `--interactive` refreshes the table until Ctrl+C. `kick` requests voluntary departure and propagates removal after acknowledgement; `remove` excludes without the target's response. Reboot restarts the OS after five seconds: one-target reboot requires entering its ID; `-f` requests forced reboot without bypassing confirmation.

All nodes, including existing members, default to ordinary transit. `node relay disable [node]` makes the selected node an **emergency relay**: new routes use it as an intermediate only when no ordinary route can be established. Its own commands and incoming endpoint connections remain available. Without `[node]`, the current node is selected; `*` supports confirmed bulk changes. The setting is persisted and synchronized across the cluster. Cached/discovered routes prefer ordinary relays even if emergency routes have lower latency. Ordinary paths are searched before emergency fallback, and regain preference after recovery. Discovery and synchronization still reach emergency relays; this is a routing preference, not a firewall ban. Existing streams are allowed to finish. `node list` shows a relay column; `node routes` marks emergency transit. Update all members so older software does not ignore the policy.

## Remote commands

```sh
pnt sh <node> 'hostname'
pnt sh <linux-node> --interactive bash
pnt sh <windows-node> --interactive cmd
pnt ping example.com
```

Routes are confirmed before tasks are sent. Output streams back in real time. An uncertain result after sending a command is not retried automatically. Linux uses `/bin/sh -c`; Windows uses `cmd.exe /d /s /c`, as the service account.

Update both the CLI and target nodes for interactive terminal support. Interactive sessions use Linux PTY / [Windows ConPTY](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session). Arrows, Home/End, editing combinations and history are handled by the remote shell; ANSI colors are preserved. Bindings depend on the shell. Interactive mode requires an attached terminal and one explicit node. Linux sessions default to in-memory history without a history file.

`pnt ping <IPv4/domain>` separately measures external ICMP latency from available members and reports the fastest exit and the paths used to contact them.

## Selectors: all, lists and exclusions

Quote `*` in Unix shells to prevent filename expansion:

```sh
pnt vpn client allow '*' node-name
pnt vpn client allow '*' '*'
pnt vpn client allow '*,-<client_id>' '*'
pnt vpn client allow '<client_id>,<client2_id>' '*,-<node_id>,-<node2_id>'
pnt vpn client create NewClient --servers '*' --out=/tratsuk.pnt
pnt vpn client deny '*' node-name
pnt vpn client unbind '*'
pnt sh '*' 'hostname'
pnt node '*' reboot
```

A comma joins explicit IDs/names; `*` selects the available set; `-id` excludes an object after all positive items have been combined. Order does not affect exclusions, and duplicates are removed. Include `*` or at least one positive item; exclusion-only expressions, unknown objects and empty results are rejected before changes. The same syntax works in `--servers`, for example `--servers '*,-node-id'`. Lists and exclusions also require confirmation.

PNT shows selected objects and operation count, then requires interactive **Y/N** confirmation. Only `Y` proceeds. `N`, empty input and EOF cancel before tasks run. Redirected stdin cannot confirm a selection; there is no bypass flag.

- Multiple selectors form all combinations. `allow '*' '*'` grants each active client every registered VPN server. `--servers '*'` creates one client with that list, without subscribing to future nodes.
- General selectors include active members, including temporarily unreachable ones. Removed nodes/revoked clients are excluded. VPN-server operations select registered VPN nodes; `vpn status '*'` and `vpn server install '*'` select Linux nodes.
- `node kick '*'`, `node remove '*'` and `node routes '*'` exclude the current node. `node accept '*'` / `reject '*'` select pending requests. Reboot handles the current node last with the common Y/N confirmation.
- Selection is fixed before confirmation. Tasks/output run sequentially; failures are reported, remaining tasks continue, and any failure produces a nonzero exit code.
- `node list` and `vpn client get` do **not** accept selectors. Use `node list [--interactive]` for a list and one client for export. **`--interactive` cannot be combined with a selector**, including in `pnt sh`.
- Forwarding accepts `--listen '*:8080'`, `--to '*:80'` and `--via '*'` only when resulting rules have distinct input ports. Conflicts are rejected before creation.

Client names must remain unique: `vpn client rename '*' NewName` is rejected if more than one client is selected.

Selectors apply to existing node/client argument positions. They do not expand command text, new names, keys, file paths, external destinations, new-node IPs, SSH installation addresses, or IDs of invitations, rules and Cesium assets.

## AmneziaWG and VPN clients

```sh
pnt vpn server install <node>
pnt vpn server list
pnt vpn server rename <node> 'Netherlands #1'
pnt vpn server status <node>
pnt vpn start [node]
pnt vpn stop [node]
pnt vpn restart [node]
pnt vpn server remove <node>

pnt vpn client create alice --servers vpn-1,vpn-2 --out=alice.pnt
pnt vpn client list
pnt vpn client rename alice NewName
pnt vpn client show alice
pnt vpn client get alice
pnt vpn client get alice --out=alice-copy.pnt
pnt vpn client allow alice vpn-2
pnt vpn client deny alice vpn-2
pnt vpn client handshake alice [node]
pnt vpn client unbind <client-id>
pnt vpn client revoke alice
```

`pnt vpn server status <node>` displays the current interface/client state and cumulative connection statistics: total and active observed sessions, direct/relayed counts, per-client totals and server receive/send bytes, data routes with node IDs, and entry/transit usage per node. The exit node samples AmneziaWG every 15 seconds and stores this history in its local SQLite database; reports can be requested through cluster routes. Update the exit nodes to start collecting. History is not replicated to other nodes and remains readable when the VPN backend is stopped.

These are sampled sessions, not TCP connections or handshake counts. Rekeys, standby relays and route changes do not create extra logical connections. A disconnect observed by the collector, or a gap of more than 180 seconds, starts a new session on reconnection. Brief disconnects between samples may be missed, and direct disconnects can take up to the handshake timeout to appear. One session can use multiple modes/routes, so their counts can overlap. The initial counters establish a baseline; traffic before collection is not reconstructed. Subsequent counter resets are handled without double counting. Bytes are measured at the exit server; attribution to modes/routes is approximate between samples. Direct VPN data bypasses the cluster, so control/catalog entry nodes are not counted as data relays. Statistics survive PNT restarts; restore the exit database from backup to restore its history.

PNT installs AmneziaWG on Debian or attaches an existing native/Docker configuration, offers a choice and prepares forwarding/firewall rules. Native discovery includes `/etc/amnezia/amneziawg`, `/etc/amneziawg` and `/opt/amnezia/awg`. Only **AmneziaWG** is supported; ordinary WireGuard and `/etc/wireguard` are not used. Existing unmanaged peers are preserved.

Import `.pnt` into [PNT VPN](https://github.com/spark108/amnezia-pnt). Clients cannot administer the cluster, join its topology or relay traffic. Permission changes do not require reimporting.

A new profile binds on first connection to a separate Android Keystore / Windows CNG device key, absent from `.pnt`. A copied file is then rejected on another device. `unbind` resets the binding, invalidates the session generation and removes VPN keys on reachable servers; offline removals remain pending. The next device can claim it, including the previous one. `revoke` permanently denies the identity.

The node that created the client serializes binding decisions and must be reachable for authorization; there is no automatic authority failover. For clients predating binding support, run `unbind` once to assign an authority and invalidate old sessions. Back up that database.

Profiles contain private credentials. Repeat export preserves identity and refreshes the server list. New identities are stored encrypted in the replicated registry; older profiles predating identity storage need the original `.pnt`. Existing files are not overwritten. Connection status uses AmneziaWG handshakes and can lag a disconnect.

## Forwarding and web interface

```sh
pnt forward add --listen edge-1:8080 --to exit-1:80
pnt forward add --listen edge-1:8443 --via exit-1 --to 192.0.2.50:443
pnt forward list
pnt forward show <id>
pnt forward remove <id>
pnt web enable
pnt web disable
```

TCP streams travel through PNT routes to a node or an external IP reached from the exit. The web interface also selects entry/exit addresses and interfaces. UDP forwarding and a general L3 network are not implemented.

`web enable` asks for a password and synchronizes settings across the cluster. Open `https://<node-ip>:8016/`, username `admin`; disabling clears the password. A generated certificate is used. The full-window globe shows geolocated nodes, direct links/latency, VPN markers and selected routes. Locations support manual overrides. A collapsible sidebar, node rename/properties menus and a forwarding page provide management.

```sh
pnt cesium token
pnt cesium add <asset-id> [name]
pnt cesium list
pnt cesium enable <asset-id>
pnt cesium disable <asset-id>
pnt cesium remove <asset-id>
pnt cesium status
```

Cesium ion credentials are entered through the CLI; `pnt cesium token clear` removes them. Imagery basemaps, terrain, compatible overlays and day/night lighting are supported.

Link labels show ping and current aggregate PNT throughput in both directions (Mbps), sampled about every five seconds and shared across the cluster. Rates exclude IP/TLS/QUIC overhead and are not a bandwidth test; stale or unavailable samples show `—`.

## Cluster file access over FTPS

```sh
pnt ftp enable
pnt ftp status
pnt ftp disable
```

Enable/disable settings propagate to all members, including newly enrolled nodes. Offline members apply changes after synchronization. The gateway runs inside the PNT service, without a separate FTP server. Update all participating nodes before enabling it.

Connect FileZilla or WinSCP to any reachable gateway:

| Setting | Value |
| --- | --- |
| Protocol | FTP with **explicit TLS required** (FTPS, not SFTP or implicit TLS) |
| Control port | **440/TCP** |
| Username | `admin` |
| Password | Original shared cluster key |
| Data mode | Passive, TLS protected (`PROT P`); binary file transfers |
| Passive ports | **44100–44131/TCP** |

Protocol references: [FTP over TLS (RFC 4217)](https://www.rfc-editor.org/rfc/rfc4217), [MLSD and REST (RFC 3659)](https://www.rfc-editor.org/rfc/rfc3659).

The node certificate is self-signed. Verify its SHA-256 fingerprint against `pnt ftp status` on that gateway before trusting it. Use binary transfer mode in the client; ASCII file conversion is not supported. Plaintext login, unencrypted data connections and active FTP are rejected. The service opens/closes the gateway and passive firewall rules; upstream firewalls still need to allow these ports. For a gateway behind NAT, forward the same ports and use EPSV so the client uses the control connection's address. An external entry into PNT must be reachable; backend nodes may remain behind NAT.

The virtual root lists `Node name [node-id]` directories. Linux exposes its filesystem root; Windows exposes drives as `C`, `D`, etc. Active paths use immutable node IDs. Offline nodes stay listed and report an availability error when opened. Virtual node directories cannot be created/deleted. The owner can browse and modify real files with the permissions of the remote PNT service, normally root/LocalSystem. There are no separate FTP users or directory restrictions.

Directory listing, metadata, download, upload, mkdir, nonrecursive rmdir, file deletion and same-node rename are supported. Operations use PNT routes, including relay/reverse NAT channels. Files stream in bounded 1 MiB blocks with SHA-256 verification; interrupted transport operations retry up to twice through routing. Uploads use private staging files beside the destination and only replace it after final verification; a concurrently changed destination is not overwritten. New Linux files have mode `0600`; replacement preserves existing Unix permission bits. Ownership and Windows ACLs follow the service/staging file, not the original file. FTP does not copy filesystem metadata.

`REST` supports resuming downloads and uploads against an existing destination file. Within a running transfer, a changed source version is rejected. An unfinished staged upload cannot be resumed by a different FTP session; reconnecting clients must restart it, or explicitly resume from a complete existing destination. Staging files/receipts expire after 24 hours. If the gateway stops, reconnect to any available gateway. Cross-node rename/move, recursive deletion and permission-changing FTP extensions are not supported.

## Access, ports and state

| Port | Purpose |
| --- | --- |
| UDP 442 | Primary persistent certificate-pinned QUIC node transport; Linux needs libmsquic |
| TCP 442 | TLS fallback, compatibility, enrollment and restricted VPN-client entry |
| TCP 8016 | HTTPS panel when enabled |
| TCP 440, 44100–44131 | FTPS control and protected passive data when enabled |
| Configured AmneziaWG UDP port | Direct VPN connection to an exit |
| TCP 22 | SSH remote installation where applicable |

VPN datagrams keep their boundaries inside PNT streams. Node QUIC uses reliable streams, not QUIC DATAGRAM; client-to-entry connections use TLS/TCP. Standby relays and heartbeats recover paths while preserving the VPN interface/keys. Packets may be lost; changing the exit cannot preserve its NAT sessions.

CLI access requires root/group `pnt` on Linux, or an elevated administrator, LocalSystem or group `PNTAdmin` on Windows. Installation creates groups but does not add users:

```sh
sudo usermod -aG pnt <user>
```

```powershell
Add-LocalGroupMember -Group PNTAdmin -Member '<user>'
```

Log in again after membership changes. These groups and cluster members have full PNT administration, including certificates and remote commands. There is no member-admin quorum or automatic key rotation on removal. Disconnected partitions can retain stale membership until synchronization.

| Platform | State / logs |
| --- | --- |
| Debian | `/var/lib/pnt`; `journalctl -u pnt.service`; configuration `/etc/default/pnt` |
| Windows | `%ProgramData%\PNT\data`; `service.log` there; configuration `%ProgramData%\PNT\config` |

Back up the database, certificate and VPN state together. Keep identities unique. Joining and external forwarding use IPv4. Custom nftables/iptables layouts may need their own allow rules.

## Help and checks

```sh
pnt --help
pnt vpn client allow --help
pnt help forward add
dotnet build -c Release
dotnet run --project tests/CliChecks -c Release
dotnet run --project tests/SelectorChecks -c Release
dotnet run --project tests/TerminalChecks -c Release
dotnet run --project tests/NodeChecks -c Release
dotnet run --project tests/RelayPolicyChecks -c Release
dotnet run --project tests/FtpChecks -c Release
dotnet run --project tests/VpnChecks -c Release
python3 tests/VpnChecks/adapter_checks.py
```

Each group/command has separate help. Tests use isolated state and do not reboot real machines. Other checks are under `tests/`; some require OS/network privileges.
