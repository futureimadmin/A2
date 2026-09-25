# SonarLint & SonarQube integration

A2 ships **both**:

| Layer | Tool | Purpose |
|-------|------|--------|
| **IDE** | SonarLint | As-you-type findings (VS Code / IntelliJ) |
| **CI** | SonarQube / SonarCloud | Server analysis, coverage, Quality Gate |
| **CI (no token)** | SpotBugs + PMD | Local static analysis when `SONAR_TOKEN` is unset |

---

## 1. SonarQube / SonarCloud (CI)

Job: **SonarQube Analysis** in `.github/workflows/ci.yml`

- Runs after unit tests
- JaCoCo coverage from `mvn verify`
- `sonar-maven-plugin` upload + Quality Gate wait
- **Skips analysis** (job still green) when `SONAR_TOKEN` is not set

### Secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `SONAR_TOKEN` | To enable analysis | SonarCloud or SonarQube token |
| `SONAR_HOST_URL` | No | Default `https://sonarcloud.io` |

### Variables (optional)

| Variable | Default |
|----------|---------|
| `SONAR_ORGANIZATION` | `futureimadmin` |
| `SONAR_PROJECT_KEY` | `futureimadmin_A2` |

### Enable SonarCloud

1. https://sonarcloud.io → import `futureimadmin/A2`
2. Create project key `futureimadmin_A2` (or set variable)
3. Generate token → GitHub secret `SONAR_TOKEN`
4. Optional: install [SonarCloud GitHub App](https://github.com/apps/sonarcloud) for PR decoration

### Self-hosted SonarQube

```text
SONAR_TOKEN=<token>
SONAR_HOST_URL=https://sonarqube.example.com
```

### Local Maven analysis

```bash
export SONAR_TOKEN=...
mvn -Psonar clean verify sonar:sonar \
  -Dsonar.token=$SONAR_TOKEN \
  -Dsonar.host.url=${SONAR_HOST_URL:-https://sonarcloud.io}
```

---

## 2. SonarLint (IDE)

Repo already includes VS Code recommendations and connected-mode project key.

### VS Code / Cursor

1. Open the repo — accept recommended extension **SonarLint** (`SonarSource.sonarlint-vscode`)
2. Command Palette → **SonarLint: Connect to SonarQube or SonarCloud**
3. Add SonarCloud (or your SQ URL) + token
4. Bind workspace to project key **`futureimadmin_A2`**

Config files:

- `.vscode/extensions.json` — recommends SonarLint
- `.vscode/settings.json` — project key for connected mode
- `.vscode/sonarlint.json` — human-readable binding notes

### IntelliJ IDEA

1. Plugins → install **SonarLint**
2. Settings → Tools → SonarLint → **Connect to SonarQube / SonarCloud**
3. Bind module to `futureimadmin_A2`

Connected mode keeps IDE rules aligned with the server Quality Profile used in CI.

---

## 3. CI static analysis without a Sonar server

Job **Static Analysis (SpotBugs + PMD)** (`-Pstatic-analysis`):

- No `SONAR_TOKEN` required
- Uploads XML/HTML reports as artifacts
- Currently non-blocking (`|| true`) until a clean baseline exists

```bash
mvn -Pstatic-analysis verify -DskipTests
```

---

## Quality Gate

When `SONAR_TOKEN` is set, CI waits for the gate (`sonar.qualitygate.wait=true`) and fails the Sonar job if the gate fails.
