# Custom Session Store Example

Demonstrates implementing a custom `session.SessionStore` — in this case, an in-memory store with map-based storage.

## When to Use

Use a custom session store when:
- You need a backend other than Redis or PostgreSQL
- You want to store sessions in an embedded database (SQLite, BadgerDB)
- You need special serialization or encryption

## Run

```bash
go run main.go
```
