# PNT

PNT is a .NET 10 cluster service for Debian. It uses TCP 442 for encrypted node communication, SQLite for local cluster state, and TCP streams for port forwarding. Every node has a persistent self-signed TLS certificate and a 16-character node ID derived from its public key. Connections pin the stored certificate fingerprint. The shared cluster key derives one-time invitation secrets; the key hash is distributed to trusted members over TLS so any member can invite another node.

## Install on Debian

Run from this source directory on Debian 12 or 13:

```sh
sudo ./pnt.sh install
```

The script installs required Debian packages, including the .NET 10 SDK, Git, OpenSSH client, and firewall utilities. If .NET 10 is missing, it adds Microsoft's Debian package feed first. It then publishes a self-contained binary for the machine's architecture with native SQLite embedded, installs a `systemd` service, and starts it. The service and CLI use `/var/lib/pnt`; run CLI commands with `sudo`. Set `PNT_ADVERTISE_IP` in `/etc/default/pnt` if automatic address selection is wrong, then restart the service before creating or joining a cluster.

```sh
sudo ./pnt.sh start
sudo ./pnt.sh stop
sudo ./pnt.sh restart

# Uses https://gitea.alathea.ru/spark108/pnt.git:
sudo ./pnt.sh update
```

`update` clones the repository over HTTPS using the account that invoked `sudo`, so Git can ask for a username and password or access token in the terminal. It builds before changing the running installation, replaces the binary and service unit, then restarts an active service. If activation fails, it restores the previous binary and unit. A stopped service remains stopped. An optional repository URL passed to `update` is saved for later runs.

```sh
sudo pnt create cluster 'a-long-random-cluster-key'
sudo pnt cluster add 192.0.2.20
# Run the invitation printed above on 192.0.2.20:
sudo pnt accept cluster '<invite_key>'
sudo pnt name 'edge-1'
sudo pnt cluster nodes
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

## Membership and status

```sh
sudo pnt cluster nodes
sudo pnt cluster invites
sudo pnt cluster invite revoke <id>
sudo pnt cluster remove <node-id-or-ip>
sudo pnt cluster leave
journalctl -u pnt -f
```

Nodes exchange their membership and forwarding records every five seconds. Records with newer timestamps replace older ones. `cluster remove` creates a removal record; peers reject that certificate after receiving it. `cluster leave` publishes the local node's own removal. A disconnected peer can retain stale membership until it reconnects or receives an update through another peer. Ping is the application-level response time, including relay hops when used.

## Current limits

- Port forwarding supports TCP only; UDP is not implemented.
- This is a trusted-member cluster: every current member can add forwarding rules and remove another member. There is no quorum or separate administrator role.
- The cluster key is not rotated on removal. A removed node's certificate is rejected for operational requests by peers that learned the removal, but the removal is not immediate across disconnected partitions.
- The firewall helper supports an existing `inet filter input` nftables chain or an iptables `INPUT` chain. Other firewall layouts need their own allow rules.
- IPv4 addresses are supported for node joining and external forwarding.
