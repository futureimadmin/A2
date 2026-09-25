# Publishing A2 to Maven Central

Version **1.0.0** is the first release in-repo.

## Gate rule (CI)

Publish runs **only** when:

1. Trigger is **workflow_dispatch** on `main`, **and**
2. All of these jobs **succeed**:
   - Build & Unit Tests (Java 17 and 21)
   - Integration Tests (Redis)
   - Sonar Analysis
   - Static Analysis (SpotBugs + PMD)

If any required job fails, **Publish to Maven Central is skipped**.

## Prerequisites (GitHub secrets)

| Secret | Purpose |
|--------|---------|
| `OSSRH_USERNAME` | Sonatype Central username |
| `OSSRH_TOKEN` | Sonatype Central token / password |
| `GPG_PRIVATE_KEY` | ASCII-armored private key for signing |
| `GPG_PASSPHRASE` | GPG key passphrase |

Also: namespace `io.a2` claimed at https://central.sonatype.com

## Publish via GitHub Actions

1. Set the secrets above
2. **Actions → CI → Run workflow** (branch `main`)
3. After all jobs are green, **Publish to Maven Central** runs `mvn -Prelease deploy`
4. In Central Portal, review the deployment and **Publish** (`autoPublish=false`)

## Publish locally

```bash
export OSSRH_USERNAME=...
export OSSRH_TOKEN=...
mvn -Prelease clean deploy -DskipTests
```
