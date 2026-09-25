# SonarCloud + SonarQube

## Your SonarCloud org (from UI)

| UI field | Value |
|---------|--------|
| Display name | **FutureIM** |
| **Organization key** | **`futureimadmin`** |
| Plan | Free |
| Projects | create **A2** if still 0 |

POM / CI defaults:

```properties
sonar.organization=futureimadmin
sonar.projectKey=futureimadmin_A2
sonar.projectName=A2
sonar.host.url=https://sonarcloud.io
```

---

## Create the project (required when Projects = 0)

1. https://sonarcloud.io/organizations/futureimadmin  
2. **Analyze new project** (or **+** → analyze)  
3. Choose GitHub → repo **`futureimadmin/A2`**  
4. If asked for project key, use **`futureimadmin_A2`** (must match POM)  
5. Finish setup (new code definition can be “Previous version”)  

Then re-run CI or locally:

```bash
export SONAR_TOKEN=...
mvn -Psonar clean verify sonar:sonar
```

Dashboard: https://sonarcloud.io/project/overview?id=futureimadmin_A2

---

## Token

- My Account → Security → Generate token (user token)  
- GitHub repo secret: **`SONAR_TOKEN`** only (no environment secret)  
- Token must belong to a user in org **futureimadmin**

---

## SonarCloud vs self-hosted SonarQube

| | SonarCloud | SonarQube Server |
|--|------------|------------------|
| Profile | `-Psonar` | `-Psonarqube` |
| Host | `https://sonarcloud.io` | your URL |
| Organization | `futureimadmin` | not used |
| CI | default | set secret `SONAR_HOST_URL` |

Self-hosted example:

```bash
mvn -Psonarqube clean verify sonar:sonar \
  -Dsonar.host.url=https://sonarqube.example.com \
  -Dsonar.projectKey=A2
```
