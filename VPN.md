# PNT VPN clients

VPN clients use a separate identity and authorization registry. They are not cluster members, do not appear in the node topology, cannot relay traffic, and cannot execute shell commands or manage forwarding rules. The Windows client imports one signed PNT profile and retrieves its current permitted VPN servers when Connect is clicked.

## Register a server

Update the participating PNT nodes before using VPN client transport, including transit nodes. On a cluster administrator terminal:

```sh
pnt vpn server install node-name
pnt vpn server list
```

Registration probes the destination through PNT's verified routes. The first adapter supports AmneziaWG on Linux/Debian, either a native `awg` interface or an `amnezia-awg` / `amnezia-awg2` Docker container. Python 3 is required on that node and is installed by `pnt.sh`.

Installation lists existing AmneziaWG configurations and offers a choice or creation of a new server. Native discovery checks `/etc/amnezia/amneziawg`, `/etc/amneziawg`, and `/opt/amnezia/awg`. Ordinary WireGuard and its `wg` binary are not supported. Docker discovery reads configurations from `/opt/amnezia/awg` and uses the selected interface and published IPv4 UDP port. The selected provider is persisted, so multiple providers can coexist. IPv4 server addresses and client subnets are supported.

PNT installs AmneziaWG when needed or attaches an existing selected configuration, then adds managed peers to that service. It preserves existing unmanaged peers, allocates unused client addresses, and persists PNT-managed profiles under the node's `data/vpn` directory. Back up that directory along with the PNT database and node certificate.

## Issue client access

```sh
pnt vpn client create alice --servers node-name,another-node --out alice.pnt
pnt vpn client list
pnt vpn client show alice
pnt vpn client allow alice another-node
pnt vpn client deny alice another-node
pnt vpn client handshake alice
pnt vpn client handshake alice node-name
pnt vpn client revoke alice
pnt vpn server remove node-name
```

The exported profile contains a private client identity and trusted bootstrap node certificate fingerprints. Treat it as a credential; issue a different client identity for each device. Private profile identities are not stored in the replicated client registry. The profile contains an initial server list, while the server-side registry determines current permissions. Reimporting is not required when an administrator changes the list.

Handshakes are read from AmneziaWG itself, matched using the PNT-managed VPN public key. The output distinguishes a missing profile, no successful handshake, and an unavailable server. Counters are from the VPN server's perspective.

`pnt vpn client list` adds connection status and mode after the existing access state and server count: `подключён  прямое`, `подключён  транспорт`, or `отключён  —`. If a client is connected to different servers by both modes, both are listed. The command requests a batch of managed-peer statistics from each relevant server in parallel, with a 12-second overall deadline. An unavailable server produces `неизвестно` unless another server confirms an active connection. Update the administrator CLI and VPN servers to use this status API.

A peer is considered connected when AmneziaWG reports a handshake within the last 180 seconds. AmneziaWG has no immediate disconnect event, so a disconnected client may retain this status until the handshake expires. Transport mode is based on traffic forwarded through an open PNT exit session; opening an idle standby relay does not count as transport traffic. The status is observed from the exit servers and does not require a client application update.

Removing a server or denying/revoking a client triggers peer removal on the target. Each registered node also reconciles its local PNT-managed peers in the background. Offline targets report pending removal; previously issued direct VPN configurations cannot be considered invalidated until the target applies peer removal. A revoked PNT identity cannot fetch new configurations or open new PNT transport sessions.

## Windows client

Import the `.pnt` file once. Every click on Connect loads the current permitted server catalog and opens the exit-server picker. PNT obtains or creates the VPN profile on the selected destination. The native VPN configuration is generated automatically and never imported manually by the user.

The transport initially sends VPN UDP packets directly to the exit server. A successful new handshake, queried from that server, confirms the direct path. If it fails, PNT creates a tunnel using its cached/discovered cluster routes. VPN packets retain their datagram boundaries and travel to the selected server's VPN port. Initial direct-path verification takes approximately ten seconds. Outer control and transport destination addresses bypass the VPN to prevent routing loops.

Cluster hops prefer persistent certificate-pinned QUIC connections over UDP 442; TCP 442 remains the fallback. VPN datagrams retain their boundaries inside reliable QUIC streams, rather than using QUIC DATAGRAM. A lost packet can still delay its own VPN stream, while independent command and forwarding streams continue. The restricted VPN-client entry connection remains TLS over TCP. The client maintains a standby relay when another entry node is available and reconnects transport without replacing the VPN interface or keys; this does not preserve an exit server's NAT state if that server fails.

Android 5.1.0.7 also negotiates an end-to-end relay heartbeat with the entry and exit PNT services. The client probes every three seconds and replaces a channel with no replies or received data for 15 seconds, including a channel whose TCP socket has not reported an error. Idle standby channels are checked too. Heartbeats are handled by PNT and are not sent to AmneziaWG or counted as VPN traffic. Older services retain the previous framing until the entry and exit are updated. Install the new Android APK and update PNT nodes to enable this recovery mechanism.

The PNT-only client has no Premium/Free, SSH server setup, ordinary VPN-key/file/QR import, official gateway backend, website menu or official update checks. The imported PNT identity is stored in encrypted application settings. Reset Access Profile removes it locally and permits importing a replacement; it does not revoke the server-side identity.

## Regression checks

```sh
dotnet run --project tests/VpnChecks -c Release
python3 tests/VpnChecks/adapter_checks.py
```

The .NET check uses an isolated random listener port and temporary state, exercises real TLS client authorization, privilege isolation, profile signatures, revocation and a real UDP round trip. Adapter checks exercise native and Docker command paths with simulated VPN backends, profile reuse, address allocation, handshake counters and peer removal without modifying installed VPN services.
