# SonarLint & SonarQube integration

A2 uses **SonarQube / SonarCloud** in CI for server-side analysis and quality gates.
**SonarLint** is the IDE companion that uses the same rules locally.

---

## Architecture

| Layer | Tool | Where |
|-------|------|--------|
| IDE (as-you-type) | **SonarLint** | IntelliJ / VS Code / Eclipse |
| CI (PR + main) | **SonarQube Scanner** (Maven) | GitHub Actions `sonar` job |
| Server / SaaS | **SonarCloud** (default) or self-hosted **SonarQube** | Dashboard + Quality Gate |

---

## CI/CD (already wired)

Job **SonarQube Analysis** in `.github/workflows/ci.yml`:

1. Runs after **Build & Unit Tests**
2. Generates JaCoCo coverage
3. Runs `sonar-maven-plugin`
4. Waits for Quality Gate (`sonar.qualitygate.wait=true`)
5. **Skips** when secret `SONAR_TOKEN` is not set (forks / local clones stay green)

### Required GitHub secret

| Secret | Required | Description |
|--------|----------|-------------|
| `SONAR_TOKEN` | Yes (to enable job) | SonarCloud or SonarQube user/project token |
| `SONAR_HOST_URL` | No | Defaults to `https://sonarcloud.io`. Set for self-hosted SQ, e.g. `https://sonarqube.example.com` |

### Optional GitHub variables

| Variable | Default |
|----------|---------|
| `SONAR_ORGANIZATION` | `futureimadmin` |
| `SONAR_PROJECT_KEY` | `futureimadmin_A2` |

### Enable on SonarCloud

1. https://sonarcloud.io → import GitHub org/repo `futureimadmin/A2`
2. Create a project (key should match `futureimadmin_A2` or update the variable)
3. Generate a token → add as repo secret `SONAR_TOKEN`
4. (Optional) Install [SonarCloud GitHub App](https://github.com/apps/sonarcloud) for PR decoration

### Self-hosted SonarQube

```
SONAR_TOKEN=<sq-token>
SONAR_HOST_URL=https://sonarqube.yourcompany.com
```

For self-hosted, `sonar.organization` is ignored; set project key via variable `SONAR_PROJECT_KEY`.

---

## Local analysis

```bash
export SONAR_TOKEN=your_token
# optional for self-hosted:
# export SONAR_HOST_URL=https://sonarqube.example.com

mvn -Psonar clean verify sonar:sonar \
  -Dsonar.token=$SONAR_TOKEN \
  -Dsonar.host.url=${SONAR_HOST_URL:-https://sonarcloud.io}
```

Coverage reports are produced under each module’s `target/site/jacoco/`.

---

## SonarLint (IDE)

SonarLint does **not** run in CI; it mirrors Sonar rules in the editor.

### IntelliJ IDEA

1. Settings → Plugins → install **SonarLint**
2. Settings → Tools → SonarLint → **Connect to SonarQube / SonarCloud**
3. Add connection (SonarCloud token or SonarQube URL + token)
4. Bind project to `futureimadmin_A2` (or your project key)

### VS Code

1. Install extension **SonarLint** (`SonarSource.sonarlint-vscode`)
2. Command Palette → **SonarLint: Connect to SonarQube or SonarCloud**
3. Bind workspace folder to the same project key used in CI

Connected mode keeps IDE findings aligned with the server Quality Profile.

---

## Quality Gate

CI fails the `sonar` job if the Quality Gate fails (`sonar.qualitygate.wait=true`).
Tune the gate in SonarCloud/SonarQube (coverage on new code, duplications, ratings).

---

## Maven coordinates

- `org.jacoco:jacoco-maven-plugin` — coverage agent + XML reports
- `org.sonarsource.scanner.maven:sonar-maven-plugin` — analysis upload

Profile `-Psonar` binds the scanner plugin for local runs.
