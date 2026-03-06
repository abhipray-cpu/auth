# Hooks Onboarding Example

Demonstrates using lifecycle hooks to implement user onboarding — sending welcome emails and creating default profiles on registration.

## Prerequisites

- Go 1.21+
- Redis running on `localhost:6379`

## Run

```bash
go run main.go
```

## Test

```bash
# Register — watch the console for hook output
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice@example.com", "password": "correct-horse-battery-staple"}'

# Login — audit log in console
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alice@example.com", "password": "correct-horse-battery-staple"}'
```
