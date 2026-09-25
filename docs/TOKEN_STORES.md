# Token Store Backends

A2 supports multiple persistent token backends via the `TokenStore` SPI.

## Quick selection

```java
TokenStore store = TokenStoreFactory.create("redis", Map.of(
    "redisCommands", myRedisCommands
));
```

| Type | Config key | Implementation |
|------|------------|----------------|
| `memory` | — | `InMemoryTokenStore` |
| `jdbc` | `dataSource` | `JdbcTokenStore` |
| `redis` / `valkey` | `redisCommands` | `RedisTokenStore` |
| `vault` / `tmvault` / `openbao` | `vaultClient`, optional `mountPath` | `VaultTokenStore` |
| `gcp-secretmanager` | `gcpSecretClient` | `GcpSecretManagerTokenStore` |

## Redis / Valkey

Works with any Redis-protocol server (Redis, Valkey, KeyDB, Dragonfly).
Provide a `RedisTokenStore.RedisCommands` adapter around Jedis/Lettuce/Redisson.

## HashiCorp Vault / TMVault / OpenBao

KV v2 under `secret/data/a2/tokens/{tokenId}`.
Provide a `VaultTokenStore.VaultClient` (HTTP or Spring Vault).

## GCP Secret Manager

Best for low-volume / audit-sensitive tokens. High QPS → prefer Redis.

## JDBC

See schema in `JdbcTokenStore` javadoc.
