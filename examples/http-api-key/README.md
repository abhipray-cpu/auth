# HTTP API Key Example

HTTP server with API key authentication, demonstrating the `apikey.APIKeyStore` implementation.

## Prerequisites

- Go 1.21+
- Redis running on `localhost:6379`

## Run

```bash
go run main.go
```

## Test

```bash
# The example creates a test API key on startup — check console output

# Access with API key via header
curl http://localhost:8080/api/me -H "X-API-Key: <key-from-console>"

# Access with API key via Authorization header
curl http://localhost:8080/api/me -H "Authorization: Bearer <key-from-console>"

# Access with API key via query parameter
curl "http://localhost:8080/api/me?api_key=<key-from-console>"
```
