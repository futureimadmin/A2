# Publishing A2 to Maven Central

The project is **release-ready** but does **not** publish automatically.

## Prerequisites

1. Sonatype Central Portal account (https://central.sonatype.com)
2. Namespace `io.a2` verified
3. GPG key pair for signing
4. `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>${env.OSSRH_USERNAME}</username>
      <password>${env.OSSRH_TOKEN}</password>
    </server>
  </servers>
</settings>
```

## Publish (manual)

```bash
# 1. Set version (remove -SNAPSHOT)
mvn versions:set -DnewVersion=0.1.0

# 2. Build, sign, deploy (does NOT auto-publish to Central)
mvn -Prelease clean deploy -DskipTests

# 3. In Central Portal UI: review & publish the deployment
```

The `release` profile attaches sources + javadoc, signs with GPG, and uses
`central-publishing-maven-plugin` with `autoPublish=false`.

## CI

The publish job in `.github/workflows/ci.yml` is **commented out**.
Uncomment and wire secrets when you are ready.
