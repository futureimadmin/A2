# SonarQube via Maven plugins

Analysis is driven entirely from the **parent POM** — no IDE plugins required.

| Plugin | Artifact | Role |
|--------|----------|------|
| **SonarQube Scanner** | `org.sonarsource.scanner.maven:sonar-maven-plugin` | Upload analysis to SonarCloud / SonarQube |
| **JaCoCo** | `org.jacoco:jacoco-maven-plugin` | Coverage agent + XML reports for Sonar |
| **SpotBugs** | `com.github.spotbugs:spotbugs-maven-plugin` | Offline static analysis (`-Pstatic-analysis`) |
| **PMD** | `org.apache.maven.plugins:maven-pmd-plugin` | Offline rules + CPD (`-Pstatic-analysis`) |

---

## Sonar properties (parent `pom.xml`)

```xml
<sonar.organization>futureimadmin</sonar.organization>
<sonar.projectKey>futureimadmin_A2</sonar.projectKey>
<sonar.projectName>A2</sonar.projectName>
<sonar.host.url>https://sonarcloud.io</sonar.host.url>
<sonar.java.source>17</sonar.java.source>
<sonar.coverage.jacoco.xmlReportPaths>…/jacoco.xml</sonar.coverage.jacoco.xmlReportPaths>
```

Override on the command line or with env:

| Property / env | Purpose |
|----------------|--------|
| `sonar.token` / `SONAR_TOKEN` | Authentication (required) |
| `sonar.host.url` / `SONAR_HOST_URL` | Server URL (default SonarCloud) |
| `sonar.organization` | SonarCloud org |
| `sonar.projectKey` | Project key |

---

## Commands

### SonarCloud / SonarQube

```bash
export SONAR_TOKEN=your_token

# Profile enables qualitygate.wait=true
mvn -Psonar clean verify sonar:sonar

# Self-hosted SonarQube
mvn -Psonar clean verify sonar:sonar \
  -Dsonar.host.url=https://sonarqube.example.com
```

`verify` runs tests + JaCoCo reports; `sonar:sonar` uploads using POM properties.

### Offline (no Sonar server)

```bash
mvn -Pstatic-analysis verify -DskipTests
```

Reports under each module `target/` (SpotBugs XML, PMD XML/HTML).

---

## CI

GitHub Actions job **SonarQube Analysis**:

```bash
mvn -B -ntp -Psonar clean verify sonar:sonar
```

Requires repository secret **`SONAR_TOKEN`**. Optional **`SONAR_HOST_URL`** for self-hosted.

Job **Static Analysis (SpotBugs + PMD)** always runs via `-Pstatic-analysis` (no token).

---

## Plugin declaration (summary)

In parent POM `<build><plugins>`:

- `jacoco-maven-plugin` — `prepare-agent` + `report` on `verify`
- `sonar-maven-plugin` — available as `sonar:sonar` (not bound to a phase)

Profile **`sonar`**: sets `sonar.qualitygate.wait=true`.

Profile **`static-analysis`**: binds SpotBugs + PMD `check` to `verify`.
