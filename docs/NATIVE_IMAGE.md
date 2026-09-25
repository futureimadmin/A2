# GraalVM / Quarkus Native Image

Native-image configuration is shipped under:

```
a2-core/src/main/resources/META-INF/native-image/io.a2/a2-core/
  reflect-config.json
  resource-config.json
  native-image.properties

a2-annotations/.../reflect-config.json
a2-quarkus-extension/.../reflect-config.json
```

These are auto-discovered by GraalVM and Quarkus native builds.

Covers:
- A2Runtime, interceptors, token stores, SPI models
- All A2 annotations (reflection for interceptors)
- Quarkus recorder / config / CDI interceptor

Build native (Quarkus example):

```bash
mvn -pl a2-quarkus-extension -Dnative package
```
