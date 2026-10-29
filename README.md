# PNT

PNT is a .NET 10 cluster service for Debian. It uses TCP 442 for encrypted node communication, SQLite for local cluster state, and TCP streams for port forwarding. Every node has a persistent self-signed TLS certificate and a 16-character node ID derived from its public key. Connections pin the stored certificate fingerprint. The shared cluster key derives one-time invitation secrets; the key hash is distributed to trusted members over TLS so any member can invite another node.

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

`install -r root@ip` opens an SSH connection and asks for the remote root password or SSH key passphrase when needed. It installs from public GitHub on the remote Debian server, then creates and accepts a one-time cluster invitation. The inviting node must be able to reach the remote node directly on TCP 442.

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
