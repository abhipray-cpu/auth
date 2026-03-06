# HTTP Magic Link Example

HTTP server with passwordless magic link authentication, demonstrating the `auth.Notifier` implementation.

## Prerequisites

- Go 1.21+
- Redis running on `localhost:6379`

## Run

```bash
go run main.go
```

## Test

```bash
# Request magic link (check console for the link — the example prints it)
curl -X POST http://localhost:8080/auth/magic-link \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice@example.com"}'

# Click the link printed in the console (or use curl)
curl "http://localhost:8080/auth/magic-link/verify?token=<token>" -c cookies.txt

# Access protected route
curl http://localhost:8080/api/me -b cookies.txt
```
