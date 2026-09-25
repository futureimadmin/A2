# SonarCloud + SonarQube (Maven)

A2 supports **both**:

| Target | Profile | Host |
|--------|---------|------|
| **SonarCloud** (SaaS) | `-Psonar` | `https://sonarcloud.io` (default) |
| **SonarQube Server** (self-hosted) | `-Psonarqube` | Your URL, e.g. `https://sonarqube.company.com` |

Same plugin: `org.sonarsource.scanner.maven:sonar-maven-plugin` + JaCoCo.

---

## Current SonarCloud defaults (parent POM)

| Property | Value |
|----------|--------|
| `sonar.organization` | **`FutureIM`** |
| `sonar.projectKey` | **`FutureIM_A2`** |
| `sonar.projectName` | `A2` |
| `sonar.host.url` | `https://sonarcloud.io` |

**Important:** In SonarCloud, open your org URL. The path segment is the **organization key** (case-sensitive). Display name can be "FutureIM" while the key might be `futureim` or `FutureIM`. Use the **key from the URL**, not only the display name.

Same for project key: **Project Information** (or the project URL) shows the exact `projectKey`.

If yours differ, either change the POM or set GitHub **Actions variables**:

| Variable | Purpose |
|----------|--------|
| `SONAR_ORGANIZATION` | Override org key |
| `SONAR_PROJECT_KEY` | Override project key |

---

## Fix "Not authorized or project not found"

1. Token was created while logged into the account that **owns/has access to org FutureIM**.
2. Project **exists** under that org (or first analysis is allowed to create it — token needs **Execute Analysis** / admin).
3. Keys match the UI exactly:
   - Org: `https://sonarcloud.io/organizations/<KEY>`
   - Project key from project settings
4. Token type is a **user token** (My Account → Security), not a random string.

Create project if missing:

1. https://sonarcloud.io → org **FutureIM**
2. **Analyze new project** → pick GitHub repo `futureimadmin/A2`
3. Note the generated **project key** → set POM or `SONAR_PROJECT_KEY` to match

---

## SonarCloud (CI + local)

```bash
export SONAR_TOKEN=...
mvn -Psonar clean verify sonar:sonar
```

CI (with repo secret `SONAR_TOKEN`):

```text
mvn -Psonar clean verify sonar:sonar
  -Dsonar.host.url=https://sonarcloud.io
  -Dsonar.organization=FutureIM
  -Dsonar.projectKey=FutureIM_A2
  -Dsonar.token=...
```

Do **not** set an empty `SONAR_HOST_URL` secret.

---

## Self-hosted SonarQube Server

```bash
export SONAR_TOKEN=sqp_...   # or user token from your SQ instance
mvn -Psonarqube clean verify sonar:sonar \
  -Dsonar.host.url=https://sonarqube.example.com \
  -Dsonar.projectKey=A2
```

On SonarQube Server, **`sonar.organization` is not used**.

### CI against self-hosted SQ

1. Secret `SONAR_TOKEN` = token from your SonarQube
2. Secret `SONAR_HOST_URL` = `https://sonarqube.example.com`
3. Optional variable `SONAR_PROJECT_KEY` = project key on that server
4. Same CI job runs; host is no longer SonarCloud

---

## GitHub secrets / variables summary

| Name | Type | Required |
|------|------|----------|
| `SONAR_TOKEN` | Secret | Yes (to run analysis) |
| `SONAR_HOST_URL` | Secret | No (default SonarCloud); set for self-hosted SQ |
| `SONAR_ORGANIZATION` | Variable | No (default `FutureIM`) |
| `SONAR_PROJECT_KEY` | Variable | No (default `FutureIM_A2`) |

---

## Offline static analysis (no Sonar server)

```bash
mvn -Pstatic-analysis verify -DskipTests
```
