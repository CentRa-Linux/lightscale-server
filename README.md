# lightscale-server

Minimal control-plane server for Lightscale. This version focuses on network, node, and token
management and returns netmap data to clients. It does not implement the data plane (WireGuard,
TURN) yet.

## Run

```sh
cargo run -- --listen 0.0.0.0:8080 --state ./state.json
```

To protect admin endpoints, set an admin token (also supports `LIGHTSCALE_ADMIN_TOKEN`):

```sh
cargo run -- --listen 0.0.0.0:8080 --state ./state.json --admin-token <token>
```

Use a shared Postgres/CockroachDB backend for multi-server control plane:

```sh
cargo run -- --listen 0.0.0.0:8080 --db-url postgres://lightscale@127.0.0.1/lightscale?sslmode=disable
```

Optional relay config (control-plane only for now):

```sh
cargo run -- --listen 0.0.0.0:8080 --state ./state.json \
  --stun stun1.example.com:3478,stun2.example.com:3478 \
  --turn turn.example.com:3478 \
  --stream-relay relay.example.com:443 \
  --udp-relay relay.example.com:3478 \
  --udp-relay-listen 0.0.0.0:3478 \
  --stream-relay-listen 0.0.0.0:443
```

These values are surfaced in the netmap for clients. A minimal UDP relay is available when
`--udp-relay-listen` is set, and a minimal stream relay is available with
`--stream-relay-listen`. TURN is still unimplemented.

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
  -d '{"name":"lab","requires_approval":true,"bootstrap_token_ttl_seconds":3600,"bootstrap_token_uses":1,"bootstrap_token_tags":["dev"]}'
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
