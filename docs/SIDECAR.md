# A2 Sidecar — Multi-language Access

The sidecar exposes the full A2 AuthN / AuthZ / Token lifecycle over gRPC so that **any language** can use A2 without embedding the Java runtime.

## Starting the sidecar

```bash
# after building
java -jar a2-sidecar/target/a2-sidecar-0.1.0-SNAPSHOT.jar --port 50051
```

## Proto contract

See `a2-sidecar/src/main/proto/a2.proto`.

### Services

| RPC | Purpose |
|-----|---------|
| `Authenticate` | Validate credentials / token for a given protocol |
| `Authorize` | Check roles / permissions for a principal |
| `IssueToken` | Issue a new token |
| `RotateToken` | Rotate (refresh) a token |
| `RevokeToken` | Revoke one or all tokens for a principal |
| `Introspect` | Inspect token state |

## Example (grpcurl)

```bash
grpcurl -plaintext -d '{
  "protocol": "JWT",
  "credentials": "eyJhbGciOiJub25lIn0..."
}' localhost:50051 a2.A2Service/Authenticate
```

## Client stubs

Generate stubs for your language from the `.proto` file:

- Go: `protoc --go_out=... --go-grpc_out=... a2.proto`
- Python: `python -m grpc_tools.protoc ...`
- Node: `@grpc/proto-loader` + `@grpc/grpc-js`
- Rust: `tonic-build`

## Deployment patterns

1. **Sidecar per pod** (Kubernetes) – lowest latency, language-agnostic.
2. **Central A2 service** – shared by many apps.
3. **Embedded Java** – use the Spring/Quarkus starters when the app is already on the JVM.
