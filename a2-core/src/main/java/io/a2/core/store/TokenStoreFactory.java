package io.a2.core.store;

import io.a2.spi.TokenStore;

import javax.sql.DataSource;
import java.util.Locale;
import java.util.Map;

/**
 * Factory for TokenStore backends.
 *
 * Supported:
 * memory, jdbc, redis, valkey, vault, tmvault, openbao,
 * gcp-secretmanager, aws-secretsmanager, azure-keyvault
 */
public final class TokenStoreFactory {

    private TokenStoreFactory() {}

    public static TokenStore create(String type, Map<String, Object> config) {
        String t = type == null ? "memory" : type.toLowerCase(Locale.ROOT).trim();
        return switch (t) {
            case "memory", "inmemory", "in-memory" -> new InMemoryTokenStore();
            case "jdbc", "database", "db" -> {
                DataSource ds = (DataSource) config.get("dataSource");
                if (ds == null) throw new IllegalArgumentException("jdbc store requires config.dataSource");
                yield new JdbcTokenStore(ds);
            }
            case "redis", "valkey", "keydb", "dragonfly" -> {
                RedisTokenStore.RedisCommands cmds =
                        (RedisTokenStore.RedisCommands) config.get("redisCommands");
                if (cmds == null) throw new IllegalArgumentException(t + " store requires config.redisCommands");
                yield new RedisTokenStore(cmds);
            }
            case "vault", "tmvault", "openbao", "hashicorp-vault" -> {
                VaultTokenStore.VaultClient client =
                        (VaultTokenStore.VaultClient) config.get("vaultClient");
                if (client == null) throw new IllegalArgumentException(t + " store requires config.vaultClient");
                String mount = (String) config.getOrDefault("mountPath", "secret/data/a2/tokens");
                yield new VaultTokenStore(client, mount);
            }
            case "gcp", "gcp-secretmanager", "secretmanager" -> {
                GcpSecretManagerTokenStore.GcpSecretClient client =
                        (GcpSecretManagerTokenStore.GcpSecretClient) config.get("gcpSecretClient");
                if (client == null) throw new IllegalArgumentException("gcp store requires config.gcpSecretClient");
                yield new GcpSecretManagerTokenStore(client);
            }
            case "aws", "aws-secretsmanager", "secretsmanager" -> {
                AwsSecretsManagerTokenStore.AwsSecretsClient client =
                        (AwsSecretsManagerTokenStore.AwsSecretsClient) config.get("awsSecretsClient");
                if (client == null) throw new IllegalArgumentException("aws store requires config.awsSecretsClient");
                yield new AwsSecretsManagerTokenStore(client);
            }
            case "azure", "azure-keyvault", "keyvault" -> {
                AzureKeyVaultTokenStore.AzureKeyVaultClient client =
                        (AzureKeyVaultTokenStore.AzureKeyVaultClient) config.get("azureKeyVaultClient");
                if (client == null) throw new IllegalArgumentException("azure store requires config.azureKeyVaultClient");
                yield new AzureKeyVaultTokenStore(client);
            }
            default -> throw new IllegalArgumentException("Unknown TokenStore type: " + type
                    + ". Supported: memory, jdbc, redis, valkey, vault, tmvault, openbao, "
                    + "gcp-secretmanager, aws-secretsmanager, azure-keyvault");
        };
    }
}
