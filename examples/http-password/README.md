# HTTP Password Example

Minimal HTTP server with password authentication — about 50 lines of application code.

## Prerequisites

- Go 1.21+
- Redis running on `localhost:6379`

## Run

```bash
# Start Redis
docker run -d -p 6379:6379 redis:7

# Run the example
go run main.go
```

## Test

```bash
# Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice@example.com", "password": "correct-horse-battery-staple"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice@example.com", "password": "correct-horse-battery-staple"}' \
  -c cookies.txt

# Access protected route
curl http://localhost:8080/api/me -b cookies.txt

# Logout
curl -X POST http://localhost:8080/auth/logout -b cookies.txt
```
