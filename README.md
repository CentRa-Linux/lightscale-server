# lightscale-server

Minimal control-plane server for Lightscale. This version focuses on network, node, and token
management and returns netmap data to clients. It does not implement the data plane (WireGuard,
TURN) yet.

## Run

`lightscale-server` now requires an admin token at startup.

```sh
cargo run -- --listen 0.0.0.0:8080 --state ./state.json --admin-token <token>
```

Using env var:

```sh
export LIGHTSCALE_ADMIN_TOKEN=<token>
cargo run -- --listen 0.0.0.0:8080 --state ./state.json
```

Use a shared Postgres/CockroachDB backend for multi-server control plane:

```sh
cargo run -- --listen 0.0.0.0:8080 --db-url postgres://lightscale@127.0.0.1/lightscale?sslmode=disable
```

Use DB URL from a secret file:

```sh
echo 'postgres://lightscale@127.0.0.1/lightscale?sslmode=disable' > ./db-url.txt
cargo run -- --listen 0.0.0.0:8080 --db-url-file ./db-url.txt
```

Optional relay config (control-plane only for now):

```sh
cargo run -- --listen 0.0.0.0:8080 --state ./state.json \
  --stun stun1.example.com:3478,stun2.example.com:3478 \
  --turn turn.example.com:3478 \
  --stream-relay relay.example.com:443 \
  --udp-relay relay.example.com:3478 \
  --dns-listen 0.0.0.0:53 \
  --udp-relay-listen 0.0.0.0:3478 \
  --stream-relay-listen 0.0.0.0:443
```

These values are surfaced in the netmap for clients. A minimal UDP relay is available when
`--udp-relay-listen` is set, and a minimal stream relay is available with
`--stream-relay-listen`. For TURN, run an external TURN server and advertise it via `--turn`.
When `--dns-listen` is set, the server also runs an authoritative DNS responder for Lightscale
network domains. `--dns-server` is optional and controls advertised DNS endpoints; when omitted,
the server derives endpoints from `--control-url` hosts + the `--dns-listen` port. DNS endpoint
values accept `HOST` or `HOST:PORT` (port omitted => `53`).

## Server Mesh Relay (mTLS)

For inter-server relay forwarding, run each server with:

- a shared mesh CA cert (`--mesh-ca-cert`)
- a per-server cert/key (`--mesh-cert`, `--mesh-key`)
- stable server identity (`--mesh-server-id`)
- peer list (`--mesh-peer id=host:port`)

Both stream relay (`--stream-relay-listen`) and UDP relay (`--udp-relay-listen`) can use
the same mesh. The server prefers learned next-hop hints per destination node and falls back to
bounded flood forwarding (`--mesh-max-hops`) when no route hint exists.

Example:

```sh
cargo run -- --listen 0.0.0.0:8080 --db-url-file /run/secrets/lightscale-db-url \
  --stream-relay-listen 0.0.0.0:443 --stream-relay vpn-a.example.com:443,vpn-b.example.com:443 \
  --mesh-server-id vpn-a.example.com \
  --mesh-listen 0.0.0.0:7443 \
  --mesh-peer vpn-b.example.com=10.0.0.12:7443 \
  --mesh-ca-cert /run/secrets/mesh-ca.pem \
  --mesh-cert /run/secrets/mesh-vpn-a.pem \
  --mesh-key /run/secrets/mesh-vpn-a-key.pem \
  --mesh-max-hops 4
```

Minimal key/cert flow (offline CA + pre-generated server keys):

```sh
# 1) create CA once (offline)
openssl genrsa -out mesh-ca.key 4096
openssl req -x509 -new -key mesh-ca.key -sha256 -days 3650 \
  -subj "/CN=lightscale-mesh-ca" -out mesh-ca.pem

# 2) per server: key + CSR + cert signed by CA
openssl genrsa -out mesh-vpn-a.key 2048
openssl req -new -key mesh-vpn-a.key -subj "/CN=vpn-a.example.com" -out mesh-vpn-a.csr
openssl x509 -req -in mesh-vpn-a.csr -CA mesh-ca.pem -CAkey mesh-ca.key -CAcreateserial \
  -out mesh-vpn-a.pem -days 825 -sha256
```

Use SANs matching `mesh-server-id` values (DNS names recommended).

IPv6-only control plane is supported by binding to an IPv6 address and using IPv6 control URLs
from clients, for example:

```sh
cargo run -- --listen [::]:8080 --db-url postgres://lightscale@127.0.0.1/lightscale?sslmode=disable
```

## API quickstart

Create a network:

```sh
curl -X POST http://127.0.0.1:8080/v1/networks \
  -H 'authorization: Bearer <admin_token>' \
  -H 'content-type: application/json' \
  -d '{"name":"lab","overlay_v4":"100.120.0.0/24","overlay_v6":"fd42:120:0::/48","requires_approval":true,"bootstrap_token_ttl_seconds":3600,"bootstrap_token_uses":1,"bootstrap_token_tags":["dev"]}'
```

Create an enrollment token later:

```sh
curl -X POST http://127.0.0.1:8080/v1/networks/<network_id>/tokens \
  -H 'authorization: Bearer <admin_token>' \
  -H 'content-type: application/json' \
  -d '{"ttl_seconds":3600,"uses":1,"tags":[]}'
```

Revoke an enrollment token:

```sh
curl -X POST http://127.0.0.1:8080/v1/tokens/<token>/revoke \
  -H 'authorization: Bearer <admin_token>'
```

Register a node:

```sh
curl -X POST http://127.0.0.1:8080/v1/register \
  -H 'content-type: application/json' \
  -d '{"token":"<token>","node_name":"laptop","machine_public_key":"...","wg_public_key":"..."}'
```

Register a node using an auth URL flow:

```sh
curl -X POST http://127.0.0.1:8080/v1/register-url \
  -H 'content-type: application/json' \
  -d '{"network_id":"<network_id>","node_name":"laptop","machine_public_key":"...","wg_public_key":"..."}'
```

Then open the returned `auth_path` on the server to approve:

```sh
curl http://127.0.0.1:8080/v1/register/approve/<node_id>/<secret>
```

Manual approval endpoint (for admins):

```sh
curl -X POST http://127.0.0.1:8080/v1/admin/nodes/<node_id>/approve \
  -H 'authorization: Bearer <admin_token>'
```

List nodes in a network (admin):

```sh
curl http://127.0.0.1:8080/v1/admin/networks/<network_id>/nodes \
  -H 'authorization: Bearer <admin_token>'
```

Update a node's name or tags (admin):

```sh
curl -X PUT http://127.0.0.1:8080/v1/admin/nodes/<node_id> \
  -H 'authorization: Bearer <admin_token>' \
  -H 'content-type: application/json' \
  -d '{"name":"laptop","tags":["dev","lab"]}'
```

Heartbeat and update endpoints/routes (optional listen_port lets the server add the
observed public IP as an endpoint):

```sh
curl -X POST http://127.0.0.1:8080/v1/heartbeat \
  -H 'content-type: application/json' \
  -d '{"node_id":"<node_id>","endpoints":["203.0.113.1:51820"],"listen_port":51820,"routes":[]}'
```

Fetch netmap:

```sh
curl http://127.0.0.1:8080/v1/netmap/<node_id>
```

Long-poll for netmap updates:

```sh
curl "http://127.0.0.1:8080/v1/netmap/<node_id>/longpoll?since=0&timeout_seconds=30"
```
