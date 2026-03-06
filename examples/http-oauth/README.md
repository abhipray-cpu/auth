# HTTP OAuth Example

HTTP server with Google and Okta OAuth2/OIDC authentication.

## Prerequisites

- Go 1.21+
- Redis running on `localhost:6379`
- Google OAuth credentials (or Okta)

## Setup

```bash
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
```

## Run

```bash
go run main.go
```

## Test

1. Open `http://localhost:8080/auth/oauth/google` in your browser
2. Complete the Google login flow
3. You'll be redirected back with a session cookie
4. Access `http://localhost:8080/api/me` to see your identity
