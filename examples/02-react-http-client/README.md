# Sample 2 — React → A2-protected Java HTTP API

The browser **does not** call the gRPC sidecar. It sends normal HTTP headers to a Java service that uses `@A2Protected` / `@A2Authorize` (Spring Boot or Quarkus).

## Run

```bash
npm install
npm run dev
```

Open http://localhost:5173

## Configure

Create `.env.local` (optional):

```env
VITE_API_BASE=http://localhost:8080
```

Or use the Vite proxy: set API base to `/api` and run Spring on `:8080`.

## Java side (what this UI expects)

Example endpoint on a Spring Boot app with `a2-spring-boot-starter`:

```java
@RestController
@RequestMapping("/api")
public class OrdersController {

  @GetMapping("/orders")
  @A2Protected(protocols = {Protocol.JWT, Protocol.API_KEY}, roles = {"user"})
  @A2Authorize(permissions = {"order:read"})
  public List<Map<String, String>> orders() {
    return List.of(Map.of("id", "1", "item", "Widget"));
  }
}
```

Client headers:

- `Authorization: Bearer <jwt>` **or**
- `X-API-Key: <key>`
- optional `X-Merchant-Id` for multi-tenant routing

401 / 403 come from A2 exception mapping on the server.
