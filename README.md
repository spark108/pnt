# PNT

VPN server registration, restricted client profiles and the PNT-only Windows VPN client are documented in [VPN.md](VPN.md).

PNT is a .NET 10 cluster service for Debian and Windows. It uses TCP 442 for encrypted node communication, SQLite for local cluster state, and TCP streams for port forwarding. Every node has a persistent self-signed TLS certificate and a 16-character node ID derived from its public key. Connections pin the stored certificate fingerprint. New nodes request membership and an existing member explicitly approves their identity. The shared cluster key hash is distributed to approved members over TLS.

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

The script installs required Debian packages, including the .NET 10 SDK, Git, OpenSSH client, and firewall utilities. If .NET 10 is missing, it adds Microsoft's Debian package feed first. It then publishes a self-contained binary for the machine's architecture with native SQLite embedded, installs a `systemd` service, and starts it. The service and CLI use `/var/lib/pnt`; run CLI commands with `sudo`. Set `PNT_ADVERTISE_IP` in `/etc/default/pnt` if automatic address selection is wrong, then restart the service before creating or joining a cluster.

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

`install` and `update` run in a separate systemd unit and print a checkmark when each stage finishes. Closing the terminal does not cancel the worker. `./pnt.sh status` shows the service and the latest operation. `update` stops the service, fast-forwards the local checkout from the public GitHub repository, builds, installs the binary and unit, and starts the service. If pull, build, or service startup fails, the previous binary and unit are restored and a previously running service is started again.

Before stopping the service for an update, the node announces its `update` status over TCP 442. `pnt cluster nodes` shows `update` in place of that node's ping, including when viewing pings from another node. The status travels through normal cluster synchronization, then clears after the service starts or the update rolls back. A stale status expires from the display after one hour. Existing nodes need this version once before they can announce their own update status.

After a manual update on a cluster member, it announces the Git commit to peers over TCP 442. Each connected member runs its own update in a separate systemd unit and relays the notice through normal cluster synchronization. A node that is offline updates after reconnecting. All existing nodes must first receive a version with this feature once by running `./pnt.sh update` locally.

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
pnt create cluster '<key>'
```

On the new server, with its PNT service running:

```sh
pnt identity
pnt identity --fingerprint
pnt connect cluster <reachable-existing-node-IPv4>
pnt connect status
```

On the existing server:

```sh
pnt cluster requests
pnt cluster accept <new-node-id>
# Or: pnt cluster reject <new-node-id>
```

Compare the requesting identity and certificate before approval. The bootstrap server certificate uses trust on first use: the new node pins the certificate it initially receives and exposes it in `pnt connect status`; compare it with the trusted server identity/certificate through a trusted channel. Inactive requests expire from the pending list after ten minutes. There is no automatic membership approval.

The new node opens the connection, receives approval on that connection, and upgrades it into a persistent bidirectional encrypted channel. Existing nodes can then initiate logical requests toward the NAT node over that already open channel. The NAT node does not need an inbound port mapping. On disconnect/restart it reconnects outbound to known peers, keeping the bootstrap address as a reconnect seed. At least one known member must be reachable outbound; there is no UDP hole punching or public rendezvous server.

Confirmed direct channels have priority over relay paths even when a relay path has lower measured latency. Among relayed alternatives, paths using fewer NAT transit nodes are preferred; latency and stability break ties. Existing members can keep their identities and establish the new outbound channels after upgrading. The older invitation commands remain available for compatibility.

```sh
sudo pnt create cluster '37004389'
sudo pnt cluster add 192.0.2.20
# Run the invitation printed above on 192.0.2.20:
sudo pnt accept cluster '<invite_key>'
sudo pnt name 'edge-1'
sudo pnt cluster nodes
sudo pnt cluster nodes 93a3655e61179794  # Ping measured by this node to every cluster member
sudo pnt nodes                          # Short form
sudo pnt cluster status
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

Rules synchronize to all reachable members. The ingress service opens its listening socket and tries to add a firewall allow rule in `nftables` (`inet filter input`) or `iptables` (`INPUT`). It removes its tagged rule when a forwarding rule is removed. Keep TCP 442 accessible between directly connected neighbors.

## Web interface

```sh
sudo pnt web enable     # Prompts for a password
sudo pnt web disable    # Closes the panel on every connected node and clears the password
```

Open `https://<node-ip>:8016/` and sign in with username `admin` and the chosen password. TCP 442 remains reserved for encrypted communication between nodes. The web interface uses a separate self-signed HTTPS certificate for each node, so the browser will ask you to trust it. The password is stored as a salted PBKDF2 hash; only the hash and salt are synchronized between cluster members. A disconnected node applies enable or disable when it reconnects and receives the latest configuration. All nodes must run this version to host the panel.

The network map shows solid lines for fresh direct connections and dashed lines for routes through intermediate nodes. Labels show the latest measured ping for a known route or the sum of direct-link pings for an inferred route. Choose servers A and B, then add transit servers in order to highlight a route. The forwarding page shows ingress, exit node, and final destination for every active TCP rule. Ping data older than 30 seconds is ignored, so a route may temporarily disappear during an update or disconnection.

The **Пробросы портов** tab can create and delete TCP rules. Select ingress node, interface/IPv4 address and listening port, then exit node, outgoing interface/IPv4 address, destination IPv4 and destination port. Interface lists are fetched from the selected nodes over their PNT routes. A rule is saved locally and applied as cluster synchronization reaches its ingress and exit nodes. Both nodes need a version supporting interface selection.

Right-click a node on the map (or focus it and press Shift+F10) for **Переименовать** and **Свойства**. Renaming accepts 1–64 characters and synchronizes through cluster membership records. Properties open in a modal showing name, ID, IP, measured ping and cached main/backup routes from the node hosting the panel. Stale measurements are marked; the dialog refreshes with the map.

Ingress is bound to the chosen local address. Exit connections use the chosen source address. On Debian, the selected device is additionally enforced with Linux [SO_BINDTODEVICE](https://man7.org/linux/man-pages/man7/socket.7.html); on Windows, the source address is bound and the system routing table selects the path. For a service on the exit node itself, use destination `127.0.0.1` and automatic outgoing interface selection. Relays carry the TCP stream through PNT; they do not install NAT forwarding rules. The destination sees the exit node as the source.

## Membership and status

```sh
sudo pnt cluster nodes
sudo pnt cluster invites
sudo pnt cluster invite revoke <id>
sudo pnt cluster remove <node-id-or-ip>
sudo pnt cluster leave
journalctl -u pnt -f
```

Nodes exchange their membership, forwarding records, and ping measurements every five seconds. `pnt cluster nodes [node-id]` and `pnt nodes [node-id]` show measurements made by the specified node; values older than 30 seconds appear as `нет связи`. When a direct connection fails, the node tries reachable cluster peers as relays, preferring the route with the lowest known direct-link latency. The measured response time is shown as `28.3 ms через gateway` (or multiple relay names). Records with newer timestamps replace older ones. `cluster remove` creates a removal record; peers reject that certificate after receiving it. `cluster leave` publishes the local node's own removal. A disconnected peer can retain stale membership until it reconnects or receives an update through another peer. Ping is the application-level response time, including relay hops when used.

## Background routes and persistent connections

```sh
sudo pnt routes                 # Main and backup paths from this server
sudo pnt routes <node-id>       # Paths to a particular member
```

The daemon checks direct neighbors roughly every five seconds and independently searches for alternatives to every node every 20–30 seconds with randomized scheduling. Searches continue while the main path is healthy. Each SQLite database stores up to four verified routes per destination, including latency, last verification, success/failure counters, and the main route. Routes expire after 60 seconds without verification. A stable alternative becomes the main path after three successful search rounds if it is at least 20% faster; failure of the current path allows immediate use of a backup.

Discovery floods a unique search ID and the visited path through available neighbors. Nodes exclude visited members, bound the search by a deadline and hop count, and accept at most two improving arrivals per search to limit duplicates. The destination returns the path on the same channels. The requester verifies candidates with control messages before storing them. A search is bounded to ten seconds, returns a limited set of alternatives, and does not enumerate every possible path in a large mesh. Later background rounds continue exploring alternatives.

Commands, synchronization, external ping/SSH checks, and forwarding use a fresh cached route. If all cached routes fail, the requester waits for a bounded discovery round. Relays follow the selected path exactly. A task is dispatched only after its route is confirmed, and its ID and start deadline are checked at the destination. Discovery never executes application tasks. A command whose dispatch result is uncertain is not automatically repeated. Cluster-wide ping and SSH checks still run in parallel on distinct executors and correlate their replies.

Direct neighbors keep pinned TLS 1.3 sessions open on TCP 442. Independent logical streams carry requests and tunnels over those sessions; closing a stream does not close the session. Per-stream flow control limits queued data, so a stalled forwarding stream does not block control traffic. Keepalive frames run every 15 seconds, with a 45-second receive timeout. Broken sessions reconnect on the next check or request. CLI tasks enter through the local daemon, allowing successive commands to reuse its existing peer sessions. Encryption is between neighboring nodes; cluster relays remain trusted with task contents.

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

Each node sends three ICMP echo requests to the target and reports the average of successful replies. For a domain, each node resolves its own IPv4 address and the result shows that address. PNT contacts nodes directly or through relays over TCP 442, prints the path used to reach each responding node, and marks unreachable nodes separately. The final line names the node with the lowest ICMP latency to the target; relay latency between cluster nodes is not included in that comparison. ICMP may be blocked by a target or firewall, in which case the node reports the failure.

## Current limits

- Port forwarding supports TCP only; UDP is not implemented.
- This is a trusted-member cluster: every current member can add forwarding rules and remove another member. There is no quorum or separate administrator role.
- The cluster key is not rotated on removal. A removed node's certificate is rejected for operational requests by peers that learned the removal, but the removal is not immediate across disconnected partitions.
- The firewall helper supports an existing `inet filter input` nftables chain or an iptables `INPUT` chain. Other firewall layouts need their own allow rules.
- IPv4 addresses are supported for node joining and external forwarding.
