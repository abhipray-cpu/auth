# Full-Stack Example

HTTP gateway + 2 gRPC backend services demonstrating all auth modes and cross-protocol identity propagation.

## Architecture

```
Browser → [HTTP Gateway :8080]
              ├── Password/OAuth/Magic Link login
              ├── Session cookie auth
              ├── API key auth
              └── SignedJWT propagation to backends
                    ├── [User Service :50051] — user operations
                    └── [Order Service :50052] — order operations (mTLS between services)
```

## Prerequisites

- Go 1.21+
- Redis running on `localhost:6379`

## Run

```bash
go run main.go
```

The example starts all three services in the same process for simplicity.
