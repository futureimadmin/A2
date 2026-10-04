# Contributing to A2

## Build

```bash
mvn -B clean verify -pl '!a2-sidecar'
```

Requires JDK 17+.

## Modules

- `a2-annotations` — declarative API
- `a2-spi` — provider SPI
- `a2-core` — runtime
- `a2-providers/*` — protocol implementations
- `a2-spring-boot-starter` / `a2-quarkus-extension`
- `a2-sidecar` — gRPC multi-language access

## Coordinates

`groupId`: `com.futureim.a2`
