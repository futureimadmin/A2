# Token Store Backends

```java
TokenStore store = TokenStoreFactory.create("redis", Map.of("redisCommands", cmds));
```

| Type | Config key | Class |
|------|------------|-------|
| `memory` | — | `InMemoryTokenStore` |
| `jdbc` | `dataSource` | `JdbcTokenStore` |
| `redis` / `valkey` | `redisCommands` | `RedisTokenStore` |
| `vault` / `tmvault` / `openbao` | `vaultClient`, optional `mountPath` | `VaultTokenStore` |
| `gcp-secretmanager` | `gcpSecretClient` | `GcpSecretManagerTokenStore` |
| `aws-secretsmanager` | `awsSecretsClient` | `AwsSecretsManagerTokenStore` |
| `azure-keyvault` | `azureKeyVaultClient` | `AzureKeyVaultTokenStore` |

Thin client SPIs keep AWS/Azure/GCP/Vault SDKs optional at compile time.
