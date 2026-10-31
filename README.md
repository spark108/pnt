# PNT

VPN server registration, restricted client profiles and the PNT-only Windows VPN client are documented in [VPN.md](VPN.md).

PNT is a .NET 10 cluster service for Debian and Windows. Its primary node transport is QUIC on UDP 442, with pinned TLS 1.3 and independent streams for synchronization, commands and forwarding. TCP 442 provides compatibility and fallback when QUIC is unavailable. SQLite stores local cluster state. Every node has a persistent self-signed TLS certificate and a 16-character node ID derived from its public key. Connections pin the stored certificate fingerprint. New nodes request membership and an existing member explicitly approves their identity. The shared cluster key hash is distributed to approved members over TLS.

## Command help

The CLI uses System.CommandLine. Every group and subcommand has its own help page; a group without a subcommand displays only that level. Help does not open the database or create an identity.

```sh
pnt --help
pnt node
pnt vpn client --help
pnt vpn client create --help
pnt help forward add
```

Required arguments and unknown options are checked before a command runs. Named options can be supplied in any order. Arguments after `pnt sh <node>` are passed to the remote command, including its own `--help` and flags.

Lists of nodes, routes, forwarding rules, VPN clients/servers, VPN handshakes, invitations, membership requests and external ping results use Spectre.Console tables. Active/connected states are green, disconnected/revoked states and errors are red, update/unknown/backup states are yellow, and relay mode/NAT markers are cyan. Long values wrap to the terminal width, and names containing markup characters are rendered literally. Set `NO_COLOR=1` to disable colors. Redirected output and `TERM=dumb` use plain tab-separated columns without borders or ANSI sequences. JSON output, invitation tokens, client protocol messages and remote command streams retain their formats.

`pnt vpn client list` also shows the connected VPN server's node ID and display name, the client's internal VPN IP on that server, and its current data transport route. Relay routes follow the active client tunnel from its PNT entry node to the VPN exit, independently of the route used to request statistics. Direct connections show `клиент → <exit-node>`. Concurrent connections to different VPN servers appear on separate rows. Disconnected clients show dashes; older servers may omit address/route details until updated. Existing relay tunnels obtain route tracking after reconnecting to the updated service.

## Local access

The installed CLI permits only `root` or members of `pnt` on Linux, and elevated administrators, LocalSystem, or members of the local `PNTAdmin` group on Windows. Authorization is checked before processing commands or opening cluster state, including help. Install/update creates the relevant group; it does not add ordinary users automatically.

```sh
sudo usermod -aG pnt <user>
# Log in again, or start a new shell with: newgrp pnt
```

In an elevated Windows PowerShell:

```powershell
Add-LocalGroupMember -Group PNTAdmin -Member '<user>'
# Log off and log in again to refresh the access token.
```

Members can run cluster commands without elevation. Linux data directories use setgid group `pnt` and mode `2770`; database and certificate files are group writable without access for other users. Windows grants `PNTAdmin` modify access to the protected data directory. Membership grants full PNT administration, including the node identity and remote commands; assign these groups only to trusted cluster administrators. Installing/updating system files or controlling the OS service directly still requires root/elevation.

Linux service startup and Windows service startup migrate existing state permissions, so the first update also applies group access when launched through an older installer. The migration command itself requires root/elevation.

## Install on Debian

Once the PNT binary is available, management commands are also available directly:

```sh
sudo pnt install
sudo pnt update
sudo pnt install -r root@192.0.2.20
```

These commands use the existing installation worker `pnt.sh` from the configured source checkout. Keep that checkout on disk. Remote installation checks TCP port 22 from every reachable cluster node and chooses the reachable node with the fastest connection to the target. If that node is reached through relays, installation output and SSH prompts travel back through the cluster to the original terminal. SSH passwords are entered interactively and are not saved by PNT. The selected node creates the invitation and joins the installed server to the cluster. All participating nodes must be updated to support this protocol.

Run from this source directory on Debian 12 or 13:

```sh
sudo ./pnt.sh install
```

The script installs required Debian packages, including the .NET 10 SDK, libmsquic, Git, OpenSSH client, and firewall utilities. It adds Microsoft's Debian package feed for the runtime dependencies. It then publishes a self-contained binary for the machine's architecture with native SQLite embedded, installs a `systemd` service, and starts it. The service and CLI use `/var/lib/pnt`; run CLI commands with `sudo`. Set `PNT_ADVERTISE_IP` in `/etc/default/pnt` if automatic address selection is wrong, then restart the service before creating or joining a cluster.

```sh
sudo ./pnt.sh start
sudo ./pnt.sh stop
sudo ./pnt.sh restart
./pnt.sh status

# Pulls from https://github.com/spark108/pnt.git:
sudo ./pnt.sh update

# Installs PNT over SSH and joins the remote server to this cluster:
sudo ./pnt.sh install -r root@192.0.2.20
```

`install` and `update` run in a separate systemd unit and print a checkmark when each stage finishes. Closing the terminal does not cancel the worker. `./pnt.sh status` shows the service and the latest operation. `update` first fast-forwards the local checkout from the public GitHub repository while the service is still running. The worker reloads the updated installer, preserving its operation, log and maintenance lock. The new installer announces maintenance, stops the service, installs all declared dependencies, builds, installs the binary and unit, and starts the service. A failed pull leaves the service running; a later failure restores the previous binary/unit and restarts a previously running service.

Before stopping the service for an update, the node announces its `update` status over the cluster transport. `pnt node list` shows `update` in place of that node's ping, including when viewing pings from another node. The status travels through normal cluster synchronization, then clears after the service starts or the update rolls back. A stale status expires from the display after one hour. Existing nodes need this version once before they can announce their own update status.

After each successful manual update on a cluster member, it creates a fresh event and announces the Git commit to peers over the cluster transport, even if that commit was already installed. This lets all nodes reapply dependencies and installer changes. Automatically updated members acknowledge that event without creating another one, preventing an update loop. An acknowledgement of an older event leaves a newer received event pending. Each connected member runs its own update in a separate systemd unit and relays the notice through normal cluster synchronization. A node that is offline updates after reconnecting. All existing nodes must first receive a version with this feature once by running `./pnt.sh update` locally.

`install -r root@ip` selects a Linux executor with SSH access and asks for the remote root password or SSH key passphrase when needed. It installs from public GitHub on the remote Debian server, asks the new service to initiate enrollment back to the executor, and approves the matching identity received over that connection. The new server needs outbound access to the executor on TCP 442. An incoming TCP 442 port on the new server is not required.

## Windows service

From an Administrator terminal in the source checkout:

```bat
pnt.bat install
pnt.bat update
pnt.bat start
pnt.bat stop
pnt.bat restart
pnt.bat status
pnt.bat repair
```

`npt.bat` is an alias for `pnt.bat`. Installation and update run in a hidden worker process and display completed stages. The installer prepares Git and the .NET 10 SDK when missing, publishes a self-contained executable, and registers the automatic Windows service `PNT` under LocalSystem. It adds a `pnt.cmd` launcher to the machine PATH; open a new terminal to pick up PATH changes. The service data and node identity are in `%ProgramData%\PNT\data`, configuration in `%ProgramData%\PNT\config`, and logs in `%ProgramData%\PNT\data\service.log`. Run CLI management commands as Administrator so they can access the protected data directory.

Windows nodes participate in the same cluster, routing, reverse NAT channels, HTTPS panel, TCP forwarding, and update announcements. `pnt sh <windows-node> <command>` executes `cmd.exe /d /s /c`; Unix nodes execute `/bin/sh -c`. Remote installation of `root@IPv4` remains a Debian operation performed by a reachable Linux member; a Windows requester can initiate it through that member. Install Windows targets locally with `pnt.bat`.

If an older Windows update fails with `SQLite Error 14`, open **PowerShell as Administrator**, pull the fixed installer, and repair permissions before updating:

```powershell
cd 'C:\Program Files\PNT'
git pull --ff-only
.\pnt.bat repair
.\pnt.bat update
.\pnt.bat status
```

`repair` creates `PNTAdmin` if necessary and repairs explicit permissions on the data directory and its existing files, including SQLite WAL/SHM. It preserves the database, certificates and cluster identity; it does not open SQLite or restart the old executable. Update also repairs permissions before checking cluster status and tolerates a stopped service or an unavailable status check. Service startup prepares permissions before opening SQLite. Installer error logs are read as UTF-8.

Windows ACL regression check (uses a temporary SQLite database and the current user's own files, requires no elevation): `dotnet run --project tests/WindowsAccessChecks -c Release`.

## Join from a new node, including behind NAT

On a server that already has a cluster:

```sh
pnt node init '<key>'
```

On the new server, with its PNT service running:

```sh
pnt node identity
pnt node identity --fingerprint
pnt node join <reachable-existing-node-IPv4>
pnt node status
```

On the existing server:

```sh
pnt node requests
pnt node accept <new-node-id>
# Or: pnt node reject <new-node-id>
```

Compare the requesting identity and certificate before approval. The bootstrap server certificate uses trust on first use: the new node pins the certificate it initially receives and exposes it in `pnt node status`; compare it with the trusted server identity/certificate through a trusted channel. Inactive requests expire from the pending list after ten minutes. There is no automatic membership approval.

The new node opens the connection, receives approval on that connection, and upgrades it into a persistent bidirectional encrypted channel. Existing nodes can then initiate logical requests toward the NAT node over that already open channel. The NAT node does not need an inbound port mapping. On disconnect/restart it reconnects outbound to known peers, keeping the bootstrap address as a reconnect seed. At least one known member must be reachable outbound; there is no UDP hole punching or public rendezvous server.

Confirmed direct channels have priority over relay paths even when a relay path has lower measured latency. Among relayed alternatives, paths using fewer NAT transit nodes are preferred; latency and stability break ties. Existing members can keep their identities and establish the new outbound channels after upgrading. Invitation-based enrollment is available under `pnt node invite`.

```sh
sudo pnt node init '37004389'
sudo pnt node invite create 192.0.2.20
# Run the invitation printed above on 192.0.2.20:
sudo pnt node invite accept '<invite_key>'
sudo pnt node name 'edge-1'
sudo pnt node list
sudo pnt node list 93a3655e61179794  # Ping measured by this node to every cluster member
sudo pnt node status
```

The invited machine must be able to reach the inviting machine on TCP 442. An invitation lasts one hour, is bound to the recipient IP, and can be used once. To connect a machine through a relay, issue the invitation from a cluster member that it can reach directly. After joining, state synchronization and forwarding can traverse another known node if direct access fails.

## Port forwarding

```sh
# Listen on edge-1:8080, deliver to app-1:80.
sudo pnt forward add --listen edge-1:8080 --to app-1:80 --proto tcp

# Listen on edge-1:8443, use gateway-1 as exit toward an external IP.
sudo pnt forward add --listen edge-1:8443 --via gateway-1 --to 203.0.113.10:443 --proto tcp

sudo pnt forward list
sudo pnt forward show <id>
sudo pnt forward remove <id>
```

Rules synchronize to all reachable members. The ingress service opens its listening socket and tries to add a firewall allow rule in `nftables` (`inet filter input`) or `iptables` (`INPUT`). It removes its tagged rule when a forwarding rule is removed. Keep UDP 442 and TCP 442 accessible between directly connected neighbors.

## Web interface

```sh
sudo pnt web enable     # Prompts for a password
sudo pnt web disable    # Closes the panel on every connected node and clears the password
```

Open `https://<node-ip>:8016/` and sign in with username `admin` and the chosen password. UDP 442 and TCP 442 remain reserved for encrypted communication between nodes. The web interface uses a separate self-signed HTTPS certificate for each node, so the browser will ask you to trust it. The password is stored as a salted PBKDF2 hash; only the hash and salt are synchronized between cluster members. A disconnected node applies enable or disable when it reconnects and receives the latest configuration. All nodes must run this version to host the panel.

The network map is a full-window CesiumJS globe. The menu button in the upper left opens a collapsible sidebar containing route controls, properties and forwarding rules; it is closed initially. CesiumJS 1.146.0, its workers and the Natural Earth base map are embedded in PNT, so the globe works without a CDN, Cesium ion token or external tile service. The **Поверхность** selector defaults to detailed NASA Blue Marble shaded-relief imagery from [NASA GIBS](https://nasa-gibs.github.io/gibs-api-docs/access-basics/) (online, no token). NASA tiles are fetched by the hosting PNT node through its authenticated `/api/imagery/nasa/{z}/{y}/{x}.jpg` endpoint, so browser CORS restrictions do not affect WebGL textures. The proxy validates tile coordinates and JPEG responses, limits concurrent downloads, and caches up to 32 MiB in memory for seven days. Upstream failures appear in the PNT service log as `NASA tile z/y/x`. The local base map remains underneath; a few transient errors are retried, and repeated errors or a 20-second startup timeout switch back to it. The local-only mode disables external tile requests, and the chosen mode is remembered in the browser. The custom 250 km zoom limit is removed; the camera uses Cesium’s normal surface collision protection. This imagery adds surface detail; the globe still uses an ellipsoid rather than a 3D terrain mesh. Only fresh direct connections are drawn, with RTT labels on their arcs. There are no dashed or synthetic links. Choose servers A and B, then add transit servers in order to highlight a route along existing links. The forwarding page shows ingress, exit node, and final destination for every active TCP rule. Authenticated server-sent events refresh the map every two seconds without reloading or resetting the camera. Ping data older than 30 seconds is hidden, including when the event connection is interrupted.

The **Границы и названия** overlay adds locally bundled Natural Earth country outlines, Russian country names and major-city/capital labels on either surface. It works offline and is enabled initially; its toggle is saved in the browser. Zoom and label collision filtering keep the globe readable, with PNT node names and ping labels taking priority. Successful surface loading does not show a technical status or zoom-limit caption in the sidebar.

### Cesium ion datasets

Configure ion from the CLI on any cluster member:

```sh
pnt cesium token                    # Hidden token entry
pnt cesium add 1 "Рельеф"             # Asset ID from your Cesium ion account
pnt cesium add 96188 "Здания"         # Cesium OSM Buildings, if available to your token
pnt cesium list
pnt cesium status
pnt cesium disable 96188
pnt cesium enable 96188
pnt cesium remove 96188
pnt cesium token clear              # Clear token, keep dataset definitions
```

`pnt cesium token <token>` is also supported. Use hidden entry to avoid putting the
credential in shell history. `add <ID> [name]` checks access to the asset and detects
its type through the ion endpoint API. Supported types are terrain, imagery,
3D Tiles, GeoJSON, CZML and KML. Only one terrain dataset can be enabled; enabling
another terrain automatically disables the previous one. Imagery layers follow
the configured order above the local/NASA base map. 3D and vector datasets have
a **Показать** button in the sidebar. Changes apply through the panel's live state
stream without reloading or moving the camera automatically.

The token and dataset definitions are stored in the protected local PNT database
and synchronized over authenticated cluster connections, including enrollment.
Update all members to support this setting. The primary token is omitted from
CLI status/list output, HTML and web state. The authenticated
`/api/cesium/ion/v1/assets/<ID>/endpoint` endpoint permits only configured, enabled
assets. It exchanges the stored primary token for ion's asset-specific access
information. CesiumJS then downloads asset content directly from its provider
using the asset access keys and handles their renewal through PNT. These asset
keys are visible to authenticated panel users; the primary account token is not.
This also supports ion's external imagery providers and preserves their credits.

Use a token with `assets:read` access to the selected assets. It does not need
account-wide write permissions. The assets must be available in your ion account
and token restrictions must permit server-side endpoint requests. Native content
requires internet access from the browser, and the hosting PNT node must reach
`api.cesium.com`. Provider quotas and entitlements still apply. Without a token,
or after it is cleared, ion datasets are unloaded and the ordinary globe remains
usable. Clearing the token does not delete assets from the ion account.

### Геолокация и управление узлами

IP geolocation is resolved in the background through [ipwho.is](https://ipwhois.io/documentation) over HTTPS and cached for seven days; failed lookups retry after an hour. Public node IPs are queried explicitly. A node with a private address determines its own public egress location, then synchronizes it through the cluster. Private addresses belonging to other nodes are never submitted as public IPs. IP geolocation is approximate. Unknown locations remain in the sidebar instead of appearing at invented coordinates. Right-click a node and choose **Геолокация**, use its properties, or select an unlocated node in the sidebar to set latitude/longitude manually. Manual coordinates are stored in the node's local database and synchronized through normal membership updates, take priority over automatic lookup, and can be reset with **По IP**. All nodes should be updated to preserve and exchange location fields.

The **Пробросы портов** tab can create and delete TCP rules. Select ingress node, interface/IPv4 address and listening port, then exit node, outgoing interface/IPv4 address, destination IPv4 and destination port. Interface lists are fetched from the selected nodes over their PNT routes. A rule is saved locally and applied as cluster synchronization reaches its ingress and exit nodes. Both nodes need a version supporting interface selection.

Right-click a node on the globe for **Переименовать**, **Свойства** and **Геолокация**. The sidebar also provides a properties button for selected server A. Renaming accepts 1–64 characters and synchronizes through cluster membership records. Properties open in a modal showing name, ID, IP, location, measured ping and cached main/backup routes from the node hosting the panel. Stale measurements are marked; the dialog refreshes with the map.

Ingress is bound to the chosen local address. Exit connections use the chosen source address. On Debian, the selected device is additionally enforced with Linux [SO_BINDTODEVICE](https://man7.org/linux/man-pages/man7/socket.7.html); on Windows, the source address is bound and the system routing table selects the path. For a service on the exit node itself, use destination `127.0.0.1` and automatic outgoing interface selection. Relays carry the TCP stream through PNT; they do not install NAT forwarding rules. The destination sees the exit node as the source.

## Membership and status

```sh
sudo pnt node list
sudo pnt node invite list
sudo pnt node invite revoke <id>
sudo pnt node remove <node-id-or-ip>
sudo pnt node leave
journalctl -u pnt -f
```

Nodes exchange their membership, forwarding records, and ping measurements every five seconds. `pnt node list [node-id]` shows measurements made by the specified node; values older than 30 seconds appear as `нет связи` (or `нет замера` when synchronization still succeeds locally). When a direct connection fails, the node tries reachable cluster peers as relays, preferring the route with the lowest known direct-link latency. The measured response time is shown as `28.3 ms через gateway` (or multiple relay names). Records with newer timestamps replace older ones. `node remove` creates a removal record; peers reject that certificate after receiving it. `node leave` publishes the local node's own removal. A disconnected peer can retain stale membership until it reconnects or receives an update through another peer.

Internal ping uses 16-byte nonce/echo requests inside the authenticated PNT transport on port 442, through the selected route. Channel establishment, route confirmation, synchronization and database operations are excluded from the timer. The displayed RTT is the median of three short exchanges; background route comparisons use one exchange per candidate. Relay time is included. ICMP is not needed for these measurements (the separate `pnt ping <external-address>` command still uses external ping). Update all cluster nodes to support the short-probe protocol; an older endpoint cannot provide this measurement.

## Background routes and persistent connections

```sh
sudo pnt node routes                 # Main and backup paths from this server
sudo pnt node routes <node-id>       # Paths to a particular member
```

The daemon checks direct neighbors roughly every five seconds and independently searches for alternatives to every node every 20–30 seconds with randomized scheduling. Searches continue while the main path is healthy. Each SQLite database stores up to four verified routes per destination, including latency, last verification, success/failure counters, and the main route. Routes expire after 60 seconds without verification. A stable alternative becomes the main path after three successful search rounds if it is at least 20% faster; failure of the current path allows immediate use of a backup.

Discovery floods a unique search ID and the visited path through available neighbors. Nodes exclude visited members, bound the search by a deadline and hop count, and accept at most two improving arrivals per search to limit duplicates. The destination returns the path on the same channels. The requester verifies candidates with control messages before storing them. A search is bounded to ten seconds, returns a limited set of alternatives, and does not enumerate every possible path in a large mesh. Later background rounds continue exploring alternatives.

Commands, synchronization, external ping/SSH checks, and forwarding use a fresh cached route. If all cached routes fail, the requester waits for a bounded discovery round. Relays follow the selected path exactly. A task is dispatched only after its route is confirmed, and its ID and start deadline are checked at the destination. Discovery never executes application tasks. A command whose dispatch result is uncertain is not automatically repeated. Cluster-wide ping and SSH checks still run in parallel on distinct executors and correlate their replies.

Direct neighbors prefer persistent QUIC connections on UDP 442. Each request or tunnel uses a separate native QUIC stream; packet loss in one stream does not impose TCP ordering on other streams. TLS 1.3 authenticates both ends using the existing pinned node certificates. The listener accepts only active cluster members, and each task rechecks membership, including on established connections. QUIC keepalive runs every 10 seconds and idle timeout is 45 seconds. A channel is confirmed before dispatching a task; failed transport negotiation can safely fall back without repeating the task.

QUIC connections are bidirectional: a node behind NAT opens an outbound connection, which peers reuse for reverse tasks and tunnels. TCP 442 remains available for initial enrollment, restricted VPN-client connections, older members, blocked UDP and platforms without QUIC support. A failed QUIC attempt uses TCP and delays the next UDP attempt for 30 seconds. A newly accepted reverse QUIC connection can be used immediately. Tasks already dispatched on a failed connection are not automatically repeated. On TCP fallback, PNT retains its existing multiplexing, flow control and 15-second keepalive. CLI tasks enter through the local daemon, allowing successive commands to reuse its peer sessions. Encryption is between neighboring nodes; cluster relays remain trusted with task contents.

Open both UDP 442 and TCP 442 in external firewalls. The daemon manages local allow rules for both protocols. Debian install/update installs `libmsquic` from Microsoft's package feed. Windows 11/Server 2022 and later use the QUIC library included in .NET; unsupported systems continue over TCP. Set `PNT_DISABLE_QUIC=1` in the service environment to temporarily force TCP for diagnostics. Startup logs show `QUIC/UDP and TCP` when the UDP listener is active. This is a QUIC stream transport, not an L3 interface or an unreliable QUIC DATAGRAM implementation: VPN datagrams retain framing inside reliable streams.

An installer older than the source-handoff mechanism still completes its old update sequence once. After installing this version, subsequent updates always reload the downloaded script. Each manual update now creates a fresh cluster event, so already updated members also rerun dependency installation. Windows reloads the updated PowerShell script in the background worker while passing the existing lock and operation ID.

Transport checks exercise UDP priority, connection reuse, independent streams, reverse NAT, certificate validation, member revocation and TCP fallback:

```sh
dotnet run --project tests/TransportChecks -c Release
```

Update every participating node before using these routes. New daemons continue accepting the original TLS synchronization protocol while old members are updating. The initial invitation remains a direct certificate-pinned connection.

Routing regression checks (use elevated privileges on systems requiring them to bind TCP 442):

```sh
dotnet run --project tests/RoutingChecks/RoutingChecks.csproj -c Release
```

## Remote commands

```sh
sudo pnt sh <node-id> 'uptime'
sudo pnt sh <node-id> 'journalctl -u pnt -n 20 --no-pager'
```

The CLI shows each attempted connection and the selected route. It streams stdout and stderr from the target as they are produced and returns the remote command's exit status. The command is noninteractive and runs through `/bin/sh -c` as the PNT service user (`root` in the supplied systemd unit). If the direct connection fails, PNT tries relays selected from fresh direct-link pings. Route discovery is completed before the command is sent, so an unresponsive relay can be skipped safely. All nodes on the selected route must support this protocol. After sending the command, a lost connection is treated as an uncertain result: the CLI does not retry it on another route, because the command might already have run. Every current cluster member can execute commands on every other member; protect cluster membership and node certificates accordingly.

## Ping from every node

```sh
sudo pnt ping 203.0.113.10
sudo pnt ping example.com
```

Each node sends three ICMP echo requests to the target and reports the average of successful replies. For a domain, each node resolves its own IPv4 address and the result shows that address. PNT contacts nodes directly or through relays over the encrypted cluster transport, prints the path used to reach each responding node, and marks unreachable nodes separately. The final line names the node with the lowest ICMP latency to the target; relay latency between cluster nodes is not included in that comparison. ICMP may be blocked by a target or firewall, in which case the node reports the failure.

## Current limits

- Port forwarding supports TCP only; UDP is not implemented.
- This is a trusted-member cluster: every current member can add forwarding rules and remove another member. There is no quorum or separate administrator role.
- The cluster key is not rotated on removal. A removed node's certificate is rejected for operational requests by peers that learned the removal, but the removal is not immediate across disconnected partitions.
- The firewall helper supports an existing `inet filter input` nftables chain or an iptables `INPUT` chain. Other firewall layouts need their own allow rules.
- IPv4 addresses are supported for node joining and external forwarding.

Проверить наличие новой версии без установки: `pnt update --check` (также `./pnt.sh update --check` или `pnt.bat update --check`). Проверка сравнивает SHA установленной сборки с веткой на GitHub, не меняет исходники, базу, службу или состояние кластера. Наличие обновления и актуальная версия возвращают код 0; ошибка проверки — код 1.

## Серверы AmneziaWG

```sh
pnt vpn server install <node>
pnt vpn server list
pnt vpn server rename <node> "Нидерланды #1"
pnt vpn server remove <node>
```

Перед использованием новой команды обновите PNT на управляющем и целевом узлах. `<node>` — имя или ID узла Debian Linux в кластере; команда работает и через промежуточные узлы. На Windows можно управлять установкой на Linux-узле, но сервер AmneziaWG устанавливается на Debian.

`server install` ищет нативные конфигурации в `/etc/amnezia/amneziawg`, `/etc/amneziawg`, `/opt/amnezia/awg`, а также конфигурации контейнеров `amnezia-awg*`. Поддерживается только AmneziaWG: каталог `/etc/wireguard` не сканируется, команда `wg` не используется. Выводятся только сведения об интерфейсе, адресе, UDP-порте и состоянии — ключи не выводятся. При наличии конфигураций выберите номер для привязки, `0` для создания новой или `q` для отмены. Клиентские конфигурации с маршрутом по умолчанию выбрать нельзя. Без существующих конфигураций установка начинается с создания `awg0`; если имя занято, выбирается следующее свободное `awgN`.

Для новой нативной установки команда собирает официальные `amneziawg-tools`; используется доступный модуль ядра, а при его отсутствии устанавливается официальный `amneziawg-go`. Посторонние Ubuntu PPA в Debian не добавляются. Выбираются свободные IPv4-подсеть и UDP-порт, создаются ключи и конфигурация с правами `0600`. Включаются IPv4 forwarding, необходимые правила nftables/iptables, NAT и автозапуск systemd. Существующие таблицы брандмауэра не очищаются; PNT управляет только собственными помеченными правилами.

После успешной установки и проверки выбранной конфигурации узел автоматически регистрируется в VPN-каталоге. Для уже зарегистрированного узла сохраняется прежнее имя для клиентов; для нового используется имя узла. Выбор конфигурации сохраняется локально, поэтому работа нескольких интерфейсов/контейнеров не делает привязку неоднозначной. Профили PNT разных конфигураций хранятся раздельно; отзыв доступа обрабатывает все ранее привязанные конфигурации.

`server rename` изменяет только имя VPN-сервера, отображаемое у клиентов. Оно синхронизируется по кластеру; ID, права и конфигурации подключения сохраняются. Само имя узла кластера меняется отдельно командой `pnt node name <имя>`.

`server remove` убирает узел из VPN-каталога и отзывает обслуживаемые PNT профили. Он не удаляет AmneziaWG и чужие конфигурации/профили. Старые команды `pnt vpn add server`, `pnt vpn servers` и `pnt vpn remove` заменены новой группой `vpn server`.

Update regression checks: `dotnet run --project tests/UpdateChecks -c Release`; on Linux run `python3 tests/UpdateChecks/worker_checks.py` as root in a test environment; on Windows run `powershell -NoProfile -File tests/UpdateChecks/windows_handoff.ps1`. The worker checks use temporary source/install directories and stub Git, build and service commands.

Глобус освещается по текущему положению Солнца: ночная сторона затемнена. Метки узлов расположены в 50 м над поверхностью с учётом подключённого рельефа. Узлы действующего VPN-каталога обозначены синими метками VPN, выбранные узлы — золотыми.

В списке «Поверхность» можно выбрать встроенную карту, NASA или один из включённых датасетов Cesium ion (снимки либо 3D Tiles). Одновременно отображается только выбранная подложка; выбор сохраняется в браузере. Встроенная карта служит резервной для отсутствующих тайлов. Рельеф и векторные датасеты подключаются независимо. Ночное затемнение применяется также к 3D-подложкам, включая материалы без собственного освещения.

Управление узлами объединено в `pnt node`. `pnt node --help` показывает команды для текущего состояния: до вступления доступны `init <key>`, `join <IPv4>`, `status`, `identity` и `invite accept <token>`; после вступления `init`, `join` и принятие приглашения скрываются. Для участника доступны `list [from]`, `requests`, `accept <id>`, `reject <id>`, `remove <node>`, `kick <node>`, `leave`, `name <name>`, `routes [node]`, `status`, `identity`, а также `invite create/list/revoke`. Отдельная справка: `pnt node accept --help`. `leave` регистрирует выход из кластера, а не останавливает службу. Старые команды верхнего уровня удалены, алиасов нет. Скрипты установки и обновления используют `node maintenance` и `node update`. Проверка активного членства для скриптов: `pnt node status --require-cluster`.

`pnt node kick <node>` отправляет выбранному узлу запрос добровольного выхода по подтверждённому маршруту. Узел сохраняет собственный выход и возвращает подтверждение; после этого управляющий узел распространяет запись об удалении кластеру. Недоступный узел автоматически не исключается: для принудительного исключения используйте `pnt node remove <node>`. При потере подтверждения задача не повторяется — проверьте `pnt node list`. Все узлы маршрута должны поддерживать новую команду.

Windows access repair tolerates files disappearing between directory enumeration and ACL/attribute updates (for example, SQLite SHM temporary files while the service is running). Existing-file access and I/O failures still abort the operation; database and certificate permissions remain protected.

`pnt node list --interactive` обновляет таблицу на месте каждую секунду до нажатия Ctrl+C. `pnt node list <node> --interactive` показывает динамические измерения от указанного узла. Режим читает текущие данные фоновой службы и требует терминал без перенаправления вывода.
