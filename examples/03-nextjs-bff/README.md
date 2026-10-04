# Sample 3 — Next.js BFF → A2 sidecar

Browser talks only to Next.js (`/api/*`). Server Route Handlers call the **gRPC sidecar**. The React page never opens a gRPC channel.

```
Browser ──HTTP──► Next.js Route Handler ──gRPC──► a2-sidecar :50051
```

## Run

```bash
# Terminal A
java -jar ../../a2-sidecar/target/a2-sidecar-1.0.0.jar --port 50051

# Terminal B
export A2_SIDECAR=localhost:50051
npm install
npm run dev
```

Open http://localhost:3000

## API

| Route | Behavior |
|-------|----------|
| `GET /api/whoami` | Reads `Authorization: Bearer`, calls sidecar `Authenticate` |
| `POST /api/authorize` | Body `{ "roles": ["admin"] }` + Bearer → sidecar `Authorize` |

## Env

| Variable | Default |
|----------|---------|
| `A2_SIDECAR` | `localhost:50051` |
| `A2_PROTO` | repo `a2-sidecar/.../a2.proto` relative path |
