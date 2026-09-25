package io.a2.core.store;

import io.a2.annotations.TokenType;
import io.a2.spi.TokenStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

class CloudTokenStoreTest {

    @Test
    void awsSecretsManagerRoundTrip() {
        Map<String, String> backend = new ConcurrentHashMap<>();
        AwsSecretsManagerTokenStore.AwsSecretsClient client = new AwsSecretsManagerTokenStore.AwsSecretsClient() {
            @Override public void putSecret(String name, String secretString) { backend.put(name, secretString); }
            @Override public Optional<String> getSecret(String name) { return Optional.ofNullable(backend.get(name)); }
            @Override public void deleteSecret(String name) { backend.remove(name); }
            @Override public List<String> listSecrets(String namePrefix) {
                List<String> out = new ArrayList<>();
                backend.keySet().stream().filter(k -> k.startsWith(namePrefix)).forEach(out::add);
                return out;
            }
        };

        TokenStore store = new AwsSecretsManagerTokenStore(client);
        store.save(new TokenStore.TokenRecord(
                "aws-1", "tok-aws", TokenType.ACCESS, "user-aws", "a2",
                Instant.now(), Instant.now().plusSeconds(600), false, null, null, Map.of()));

        assertTrue(store.findById("aws-1").isPresent());
        assertTrue(store.findByTokenValue("tok-aws").isPresent());
        store.revoke("aws-1");
        assertTrue(store.findById("aws-1").isEmpty());
    }

    @Test
    void azureKeyVaultRoundTrip() {
        Map<String, String> backend = new ConcurrentHashMap<>();
        AzureKeyVaultTokenStore.AzureKeyVaultClient client = new AzureKeyVaultTokenStore.AzureKeyVaultClient() {
            @Override public void setSecret(String name, String value) { backend.put(name, value); }
            @Override public Optional<String> getSecret(String name) { return Optional.ofNullable(backend.get(name)); }
            @Override public void deleteSecret(String name) { backend.remove(name); }
            @Override public List<String> listSecretNames(String namePrefix) {
                List<String> out = new ArrayList<>();
                backend.keySet().stream().filter(k -> k.startsWith(namePrefix)).forEach(out::add);
                return out;
            }
        };

        TokenStore store = new AzureKeyVaultTokenStore(client);
        store.save(new TokenStore.TokenRecord(
                "az-1", "tok-az", TokenType.ACCESS, "user-az", "a2",
                Instant.now(), Instant.now().plusSeconds(600), false, null, null, Map.of()));

        assertTrue(store.findById("az-1").isPresent());
        store.revokeAllForPrincipal("user-az");
        assertTrue(store.findByPrincipal("user-az").isEmpty());
    }

    @Test
    void factoryCreatesAwsAndAzure() {
        Map<String, String> awsBackend = new HashMap<>();
        TokenStore aws = TokenStoreFactory.create("aws-secretsmanager", Map.of(
                "awsSecretsClient", (AwsSecretsManagerTokenStore.AwsSecretsClient) new AwsSecretsManagerTokenStore.AwsSecretsClient() {
                    @Override public void putSecret(String n, String v) { awsBackend.put(n, v); }
                    @Override public Optional<String> getSecret(String n) { return Optional.ofNullable(awsBackend.get(n)); }
                    @Override public void deleteSecret(String n) { awsBackend.remove(n); }
                    @Override public List<String> listSecrets(String p) { return List.copyOf(awsBackend.keySet()); }
                }));
        assertInstanceOf(AwsSecretsManagerTokenStore.class, aws);

        Map<String, String> azBackend = new HashMap<>();
        TokenStore az = TokenStoreFactory.create("azure-keyvault", Map.of(
                "azureKeyVaultClient", (AzureKeyVaultTokenStore.AzureKeyVaultClient) new AzureKeyVaultTokenStore.AzureKeyVaultClient() {
                    @Override public void setSecret(String n, String v) { azBackend.put(n, v); }
                    @Override public Optional<String> getSecret(String n) { return Optional.ofNullable(azBackend.get(n)); }
                    @Override public void deleteSecret(String n) { azBackend.remove(n); }
                    @Override public List<String> listSecretNames(String p) { return List.copyOf(azBackend.keySet()); }
                }));
        assertInstanceOf(AzureKeyVaultTokenStore.class, az);
    }
}
