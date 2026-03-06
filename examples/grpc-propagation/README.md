# gRPC Propagation Example

Two gRPC services demonstrating identity propagation with `SignedJWTPropagator`. Service A authenticates users and propagates identity to Service B via Ed25519-signed JWTs.

## Prerequisites

- Go 1.21+
- Redis running on `localhost:6379`

## Run

```bash
# Terminal 1 — Service B (backend)
go run main.go -mode=backend

# Terminal 2 — Service A (gateway)
go run main.go -mode=gateway
```
