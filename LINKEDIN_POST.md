# LinkedIn Post — 8 Open-Source Go Libraries

> Copy and paste the text below directly into LinkedIn.

---

Over the past 4 months I shipped 8 open-source Go libraries. I want to share what they are, why I built them, and what I learned along the way.

Fair warning: this is a long one. 😅

---

**A bit of context first**

I'm about 3 years into my engineering career. One pattern I've noticed in myself is that I learn best when I'm building something real — not just following a tutorial, but actually designing interfaces, writing tests, and sitting with the hard decisions that come up mid-implementation.

So I gave myself a challenge: over the next few months, pick domains I hadn't explored deeply, and build something useful in each of them. The goal was never to write the best library out there — it was to grow as an engineer, write code that someone else could pick up without needing me to explain it, and hopefully give something back to the community in the process.

Here's what came out of it.

---

**The 8 Libraries**

🔐 **Attestor** (`github.com/abhipray-cpu/auth`)
Pluggable authentication and identity propagation for Go — password, OAuth2/OIDC, magic links, API keys, mTLS, and gRPC, all behind a single interface. The gap I was trying to fill: most Go auth libraries handle one mode well and leave you stitching everything else together. Attestor lets you wire up the whole thing with one call.

⚙️ **concurx** (`github.com/abhipray-cpu/concurx`)
Production-grade concurrency primitives — Supervisor (Erlang-style fault tolerance), WorkerGroup, Group, and 11+ patterns like CircuitBreaker, Pipeline, and ScatterGather. The core promise: if a concurx API returns nil, the accepted work will finish, exactly once. I explored this domain because I kept running into "best-effort" concurrency utilities that quietly dropped work under load.

📋 **go-audit** (`github.com/abhipray-cpu/go-audit`)
A versioning and audit trail library — field-level diffs, actor/reason context, hash chains, schema migration, and GDPR-compliant PII redaction, all in a single `auditor.Version(ctx, &entity)` call. Most applications eventually need to answer "what changed, when, and by whom?" I wanted a library that made that easy to add without restructuring your data layer.

📬 **hashigo** (`github.com/abhipray-cpu/hashigo`)
A multi-channel notification library — 11 channels (email, SMS, push, WhatsApp, Slack, Discord, and more) and 25 provider adapters, with priority queues, circuit breakers, rate limiting, and a dead letter queue built in. It runs inside your process, no sidecar needed. I built this because every notification system I'd seen was either too thin (just an SMTP wrapper) or too heavy (a full external service).

🔄 **morpheus** (`github.com/abhipray-cpu/morpheus`)
A data transformation library — 50+ built-in transformers, a YAML-driven rule engine, DAG pipeline orchestration with parallel execution, and PII detection and masking. The domain felt underexplored in Go. Most teams end up with ad-hoc transformation code scattered across their codebase; I wanted a composable alternative.

🚦 **Niyantrak** (`github.com/abhipray-cpu/Niyantrak`)
A rate limiting library — 5 algorithms (Token Bucket, Leaky Bucket, Fixed Window, Sliding Window, GCRA), three backends (memory, Redis, PostgreSQL), and HTTP/gRPC middleware included. The name comes from Sanskrit: "controller." I noticed that most Go rate limiting libraries either implement one algorithm or require you to bring your own storage. I wanted all of that in one place.

🏢 **tenantkit** (`github.com/abhipray-cpu/tenantkit`)
Transparent multi-tenancy for Go — it wraps `database/sql` and automatically injects tenant conditions into your queries, so your application code doesn't need to think about it. Adapters for Gin, Echo, Chi, Fiber, GORM, and sqlx. Building this taught me a lot about SQL parsing and the tradeoffs in transparent vs. explicit isolation.

🔌 **grip** (`github.com/abhipray-cpu/grip`)
A gRPC resilience library — automatic error classification, retry and deadline management, keyed-FIFO stream ordering (per-key sequential, cross-key parallel), and OpenTelemetry/Prometheus metrics. gRPC streaming, done correctly, is surprisingly complex. grip tries to absorb that complexity so you don't have to.

---

**How I approached building them**

A few things I tried to be consistent about across all 8:

Before writing a single line of code, I wrote ADRs (Architecture Decision Records). It sounds like overhead, but it forced me to think through tradeoffs upfront, and it made the code more coherent. I could always come back and ask "why did I do it this way?" and have an honest answer.

Every library is designed not to block your core operations. The hooks, middleware, and adapters are all opt-in. If you don't need a feature, you never touch it. I'm allergic to libraries that make you restructure your application to use them.

All 8 have test coverage and end-to-end tests. I ran the race detector on every package. A few caught real bugs — the race detector more than paid for itself. Where possible I used Testcontainers for integration tests so they're reproducible.

The interfaces are the contract. I tried to make each library's public surface small, stable, and self-explanatory. Someone picking up one of these should be able to understand what it does from the interfaces alone, without needing to read the internals.

---

**Where things stand**

Honestly, these are still early. They're not battle-tested in production at scale — they're well-designed, well-tested foundations that I hope can grow into that with community feedback and adoption.

If you're working on a Go service and run into one of these problems, I'd genuinely love to hear if any of these are useful. And if you find a gap, a bug, or a better design — contributions are very welcome. All 8 are open source (MIT or Apache 2.0). Each repo has a `CONTRIBUTING.md` with setup instructions and a `docs/` folder with architecture notes and usage guides.

You don't need to contribute code to help — opening an issue, asking a question, or just trying it out and letting me know what you think all count.

---

**Links (all in one place)**

- 🔐 Auth / Attestor → https://github.com/abhipray-cpu/auth
- ⚙️ concurx → https://github.com/abhipray-cpu/concurx
- 📋 go-audit → https://github.com/abhipray-cpu/go-audit
- 📬 hashigo → https://github.com/abhipray-cpu/hashigo
- 🔄 morpheus → https://github.com/abhipray-cpu/morpheus
- 🚦 Niyantrak → https://github.com/abhipray-cpu/Niyantrak
- 🏢 tenantkit → https://github.com/abhipray-cpu/tenantkit
- 🔌 grip → https://github.com/abhipray-cpu/grip

---

In the coming weeks I'll be writing a dedicated post for each of these — why I built it, the core idea behind it, how to use it, and the guarantees it provides. If any of them caught your eye, stay tuned.

Thanks for reading. 🙏

---

#golang #go #opensource #opensourcesoftware #softwaredevelopment #softwareengineering #backenddevelopment #microservices #programming #grpc #authentication #concurrency #ratelimiting #multitenancy #dataengineering #notifications #audittrail #buildinpublic #learninginpublic #golangnews #golangdeveloper #golangcommunity #sideproject #developer #100daysofcode #techcommunity #softwarearchitecture #devops #apidevelopment #engineeringlife
