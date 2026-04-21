# gRPC Pentest

> Protocol-buffer–wrapped RPC over HTTP/2. Reflection enumeration, transport-security gaps, authorization bypass. Authorized testing only.

## TL;DR
- gRPC = Protocol Buffers (`.proto` schemas) + HTTP/2 + (optional) TLS. Three RPC styles: unary, server-streaming, client-streaming, bidirectional.
- Without the `.proto` (the schema), you can't compose calls — unless gRPC reflection is enabled (`grpc.reflection.v1alpha.ServerReflection`). Many internal services leave reflection on.
- Authorization in gRPC is whatever the developer wired up (interceptor reading metadata token). Common gaps: no auth on internal-only services exposed at the edge, BFLA between admin and user methods on the same server.
- Tools: `grpcurl`, `evans`, `ghz` (load test), `protoscope` (debug raw wire format).

## Detection / Discovery

### Identify gRPC traffic
- TLS port 443 (often), but `Content-Type: application/grpc` is the giveaway in HTTP/2 frames.
- ALPN advertises `h2`.
- Some deployments use gRPC-Web (browser-friendly): `Content-Type: application/grpc-web+proto` or `application/grpc-web-text`.

### Reflection check
```bash
# Probe — does the server expose reflection?
grpcurl -plaintext target:50051 list
# Returns:
#   grpc.reflection.v1alpha.ServerReflection
#   acme.UserService

# Per-service method list
grpcurl -plaintext target:50051 list acme.UserService
# Returns:
#   acme.UserService.GetUser
#   acme.UserService.DeleteUser

# Per-method schema
grpcurl -plaintext target:50051 describe acme.UserService.GetUser
# Shows request/response message types

# Per-message schema
grpcurl -plaintext target:50051 describe acme.UserRequest
```

### Without reflection — `.proto` recovery
- `.proto` files leak in:
  - Public GitHub repos for the same product
  - `.pb.go` / `*_pb2.py` Python wrappers shipped in client SDKs (decompile to recover schema)
  - Docker images — `find / -name '*.proto'`
  - Browser bundles for gRPC-Web clients
- `protoscope` decodes raw wire format without the schema (helpful for diffing).

## Exploitation

### Invoke methods (with reflection)
```bash
# Simple call
grpcurl -plaintext -d '{"user_id":"123"}' target:50051 acme.UserService/GetUser

# With auth metadata
grpcurl -plaintext -H 'authorization: Bearer ey...' -d '{"user_id":"123"}' \
        target:50051 acme.UserService/GetUser

# Streaming response
grpcurl -plaintext -d '{"watch":true}' target:50051 acme.UserService/StreamUsers
```

### Authorization bypass (BFLA — API5:2023)
On a server that has admin RPCs alongside user RPCs:
```bash
# As a regular user, try the admin method anyway
grpcurl -plaintext -H 'authorization: Bearer <regular-user-token>' \
        -d '{"user_id":"123"}' target:50051 acme.AdminService/DeleteUser
```
Common gap: the same server hosts `UserService` and `AdminService`, the interceptor checks "is authenticated" but not "is admin".

### BOLA (API1:2023)
```bash
# Authenticated as user_1; ask for user_2's data
grpcurl -plaintext -H 'authorization: Bearer <user_1-token>' \
        -d '{"user_id":"user_2"}' target:50051 acme.UserService/GetUser
```

### Method enumeration without reflection — wordlist brute
```bash
# Try common method names
for m in Login Register GetUser DeleteUser ListUsers AdminLogin RunCommand; do
  grpcurl -plaintext -d '{}' target:50051 "acme.UserService/$m" 2>&1 | head -2
  echo ---
done
# 'unknown service' vs 'method not implemented' vs 'invalid argument' reveal which exist
```

### Plaintext transport
Many internal gRPC deployments run plaintext (`-plaintext` flag in grpcurl). Mitm to enumerate, replay, modify.

### TLS without verification
Server presents TLS but doesn't enforce mTLS, accepts self-signed cert from client → ride the connection with attacker-cert if internal trust assumptions exist.

### Reflection disabled but health/channelz still on
```bash
# Channelz exposes channels/sockets/servers — useful for recon
grpcurl -plaintext target:50051 grpc.channelz.v1.Channelz/GetTopChannels

# Health-check service
grpcurl -plaintext target:50051 grpc.health.v1.Health/Check
```

### gRPC-Web specific
- Browser-side calls hit `https://target/acme.UserService/GetUser` with base64-encoded protobuf.
- Same CORS, CSRF, JWT issues as REST apply.
- BFLA still — the back-end gRPC server is the real authority; gRPC-Web is a translation layer.

## Bypasses
- WAF rules tuned for REST patterns miss gRPC payloads (binary).
- Rate-limit per-method but not per-stream — open a server-streaming call and pull until exhausted.
- `-protoset` argument lets you supply your own `.proto` set to grpcurl even when reflection is off and you found the schema elsewhere.

## Defence / Remediation
- **Disable reflection in production** (or restrict by network: reflection allowed only on localhost / internal management VLAN).
- **mTLS** between services where they sit in the same trust zone; mTLS *at the edge* if exposing gRPC to the internet at all. Bare TLS is the absolute minimum.
- **Authentication interceptor** that validates tokens centrally; **authorization** decisions per-method (don't conflate "authenticated" with "authorized").
- **Per-method authorization** as code (interceptor pattern) — explicit allow-list of roles per method; tests in CI to enforce parity with intent.
- **Rate-limit + max-message-size + max-streams-per-connection** at the gRPC server level; ResourceQuota at the K8s level if relevant.
- **Hide health/channelz** behind a separate port or filter access to it (`debug.UnaryInterceptor`-style guard).
- **Schema validation** on every field (length, regex, range) — Protocol Buffers doesn't validate beyond type.
- **Audit logs** with the gRPC method called + the principal + outcome; alert on cross-tenant pattern.

## Sources
- gRPC documentation: https://grpc.io/docs/
- grpcurl: https://github.com/fullstorydev/grpcurl
- Evans (interactive gRPC client): https://github.com/ktr0731/evans
- grpc.reflection — server-reflection protocol: https://github.com/grpc/grpc/blob/master/doc/server-reflection.md
- OWASP API Top 10 (2023) — covers gRPC by spec: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- HackTricks gRPC: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-grpc-protobuf.html
- PayloadsAllTheThings GraphQL/gRPC: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- Protoscope: https://github.com/protocolbuffers/protoscope
