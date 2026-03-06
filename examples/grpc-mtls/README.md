# gRPC mTLS Example

gRPC server with mutual TLS (mTLS) authentication, demonstrating workload identity via client certificates.

## Prerequisites

- Go 1.21+
- Certificates (use the test certs from `mode/mtls/testdata/` for development)

## Run

```bash
# Terminal 1 — server
go run main.go -mode=server

# Terminal 2 — client
go run main.go -mode=client
```
