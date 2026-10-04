# A2 sample apps (Node · TypeScript · React)

Three minimal apps showing how non-Java stacks use A2.

| App | Path | Pattern |
|-----|------|---------|
| **1. Node/TS sidecar client** | [`01-node-ts-sidecar`](01-node-ts-sidecar/) | gRPC → `a2-sidecar` (`Authenticate` / `Authorize` / `IssueToken`) |
| **2. React HTTP client** | [`02-react-http-client`](02-react-http-client/) | Browser → annotated Java/Spring API (Bearer / API key headers) |
| **3. Next.js BFF** | [`03-nextjs-bff`](03-nextjs-bff/) | React UI → Next Route Handlers → gRPC sidecar |

## Prerequisites

- **Node.js 18+**
- **A2 sidecar** (apps 1 & 3):

```bash
# from repo root (needs protoc for first build)
mvn -pl a2-sidecar -am package -DskipTests
java -jar a2-sidecar/target/a2-sidecar-1.0.0.jar --port 50051
```

- **Java API** (app 2): any service using `@A2Protected` / `a2-spring-boot-starter`, or the demo URL defaults in that sample.

## Quick start

```bash
# Terminal A — sidecar
java -jar a2-sidecar/target/a2-sidecar-1.0.0.jar --port 50051

# App 1
cd examples/01-node-ts-sidecar && npm install && npm start

# App 2
cd examples/02-react-http-client && npm install && npm run dev

# App 3
cd examples/03-nextjs-bff && npm install && npm run dev
```

See each folder’s `README.md` for env vars and expected responses.
