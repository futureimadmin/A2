# Sample 1 — Node / TypeScript → A2 sidecar (gRPC)

Calls `a2.A2Service` on the sidecar: **Authenticate**, **Authorize**, **IssueToken**.

## Run

```bash
# Sidecar must be up on :50051
export A2_SIDECAR=localhost:50051
export A2_TOKEN=your-jwt-or-leave-empty-to-demo-error-path

npm install
npm start
```

## What it does

1. Loads `../../a2-sidecar/src/main/proto/a2.proto` (or `A2_PROTO` path).
2. `Authenticate` with `protocol=JWT` and `credentials` from `A2_TOKEN`.
3. On success, `Authorize` requiring role `user` (adjust in `src/main.ts`).
4. Optionally `IssueToken` for a short-lived service token.

This is the polyglot equivalent of `@A2Protected` + `@A2Authorize` + `@A2Token` on the JVM.
