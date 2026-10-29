# PNT VPN clients

VPN clients use a separate identity and authorization registry. They are not cluster members, do not appear in the node topology, cannot relay traffic, and cannot execute shell commands or manage forwarding rules. The Windows client imports one signed PNT profile and retrieves its current permitted VPN servers when Connect is clicked.

## Register a server

Update the participating PNT nodes before using VPN client transport, including transit nodes. On a cluster administrator terminal:

```sh
pnt vpn add server node-name "Netherlands #1"
pnt vpn servers
```

Registration probes the destination through PNT's verified routes. The first adapter supports AmneziaWG on Linux/Debian, either a native `awg` interface or an `amnezia-awg` / `amnezia-awg2` Docker container. Python 3 is required on that node and is installed by `pnt.sh`.

Exactly one active service must be discoverable. Native configuration discovery checks `/etc/amnezia/amneziawg`, `/etc/amneziawg`, `/etc/wireguard`, and `/opt/amnezia/awg`, using the active interface name. Docker discovery reads `/opt/amnezia/awg/awg0.conf` and its published IPv4 UDP port. Ambiguous services/configurations are rejected. IPv4 server addresses and client subnets are supported.

PNT adds peers to the existing service; it does not install or replace AmneziaWG. It preserves existing unmanaged peers, allocates unused client addresses, and persists PNT-managed profiles under the node's `data/vpn` directory. Back up that directory along with the PNT database and node certificate.

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
pnt vpn remove node-name
```

The exported profile contains a private client identity and trusted bootstrap node certificate fingerprints. Treat it as a credential; issue a different client identity for each device. Private profile identities are not stored in the replicated client registry. The profile contains an initial server list, while the server-side registry determines current permissions. Reimporting is not required when an administrator changes the list.

Handshakes are read from AmneziaWG itself, matched using the PNT-managed VPN public key. The output distinguishes a missing profile, no successful handshake, and an unavailable server. Counters are from the VPN server's perspective.

Removing a server or denying/revoking a client triggers peer removal on the target. Each registered node also reconciles its local PNT-managed peers in the background. Offline targets report pending removal; previously issued direct VPN configurations cannot be considered invalidated until the target applies peer removal. A revoked PNT identity cannot fetch new configurations or open new PNT transport sessions.

## Windows client

Import the `.pnt` file once. Every click on Connect loads the current permitted server catalog and opens the exit-server picker. PNT obtains or creates the VPN profile on the selected destination. The native VPN configuration is generated automatically and never imported manually by the user.

The transport initially sends VPN UDP packets directly to the exit server. A successful new handshake, queried from that server, confirms the direct path. If it fails, PNT creates a tunnel using its cached/discovered cluster routes. VPN packets retain their datagram boundaries and travel to the selected server's VPN port. Initial direct-path verification takes approximately ten seconds. Outer control and transport destination addresses bypass the VPN to prevent routing loops.

This first transport carries relayed datagrams over PNT's existing encrypted TCP streams, so packet loss can increase relay latency. A broken relay disconnects the VPN; Connect can obtain a new route. Native QUIC/UDP transport and seamless relay replacement are not implemented in this version.

The PNT-only client has no Premium/Free, SSH server setup, ordinary VPN-key/file/QR import, official gateway backend, website menu or official update checks. The imported PNT identity is stored in encrypted application settings. Reset Access Profile removes it locally and permits importing a replacement; it does not revoke the server-side identity.

## Regression checks

```sh
dotnet run --project tests/VpnChecks -c Release
python3 tests/VpnChecks/adapter_checks.py
```

The .NET check uses an isolated random listener port and temporary state, exercises real TLS client authorization, privilege isolation, profile signatures, revocation and a real UDP round trip. Adapter checks exercise native and Docker command paths with simulated VPN backends, profile reuse, address allocation, handshake counters and peer removal without modifying installed VPN services.
