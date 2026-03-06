# Contributing

Thank you for your interest in contributing to the Attestor.

## Development Setup

### Prerequisites

- Go 1.21+
- Docker (for integration tests) — [Colima](https://github.com/abiosoft/colima) works on macOS
- golangci-lint v2.8+

### Clone and Build

```bash
git clone https://github.com/abhipray-cpu/auth.git
cd auth
go build ./...
```

### Run Tests

```bash
# Unit tests (no Docker required)
go test ./... -count=1

# Unit tests with race detector
go test -race ./... -count=1

# Integration tests (requires Docker)
DOCKER_HOST=unix://$HOME/.colima/default/docker.sock \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
go test -race -tags=integration ./integration/ -count=1 -timeout=10m

# Specific package
go test -race ./session/... -count=1
```

### Lint

```bash
golangci-lint run
```

The project uses `.golangci.yml` with strict settings. All code must pass with zero issues.

### Benchmarks

```bash
go test -bench=. -benchmem ./hash/ ./session/ ./propagator/
```

## Code Style

- Follow standard Go conventions (gofmt, goimports)
- All exported types, functions, and methods must have godoc comments
- Use `errors.New()` for sentinel errors — never `fmt.Errorf()` for errors that callers match with `errors.Is()`
- Use `context.Context` as the first parameter for any function that does I/O
- No `log.Printf` in library code — use `log/slog` for the rare cases where logging is necessary
- No stuttering in type names (e.g., `session.Config` not `session.SessionConfig` for new types)

## Project Structure

```
auth.go              # Identity type, context accessors
interfaces.go        # UserStore, User, Hasher, Authorizer, Notifier, AuthMode
types.go             # CredentialType, Credential, AuthEvent, IdentifierConfig
errors.go            # Sentinel errors
authsetup/           # Constructor with functional options (one-line wiring)
engine/              # Core authentication orchestrator
session/             # Session manager, types, adapters
  ├── redis/         # Redis session store
  └── postgres/      # PostgreSQL session store
password/            # Password policy + validation
hash/                # Argon2id hasher
hooks/               # Lifecycle event hook system
http/                # HTTP middleware + route registration
grpc/                # gRPC interceptors (server + client)
mode/                # Auth mode implementations
  ├── password/
  ├── oauth/
  ├── magiclink/
  ├── apikey/
  └── mtls/
propagator/          # Identity propagation (SignedJWT, Session, SPIFFE)
apikey/              # API key types and store interface
integration/         # Integration and pen tests
```

## Making Changes

### 1. Create a Branch

```bash
git checkout -b feature/my-change
```

### 2. Make Your Changes

- Keep changes focused — one feature or fix per PR
- Add tests for new functionality
- Update documentation if you change public APIs

### 3. Test

```bash
# Must pass before submitting
go test -race ./... -count=1
golangci-lint run
```

### 4. Submit a Pull Request

- Write a clear description of what changed and why
- Reference any related issues
- Ensure CI passes

## Public API Policy

The following are considered part of the public API and require a major version bump to change:

- All exported types, interfaces, and functions in the `auth` package
- The `authsetup.Option` function signatures
- The `session.SessionStore` interface
- Sentinel error variables
- HTTP route paths from `RegisterRoutes`
- gRPC metadata key names

Internal packages, test utilities, and unexported types are not part of the public API.

## Adding a New Auth Mode

1. Create a package under `mode/` (e.g., `mode/webauthn/`)
2. Implement the `auth.AuthMode` interface
3. Add a `CredentialType` constant in `auth/types.go`
4. Add the mode to `engine.allCredentialTypes()`
5. Add an `authsetup.With*` option to enable the mode
6. Write unit tests in the mode package
7. Add integration tests in `integration/`
8. Document in `docs/`

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
