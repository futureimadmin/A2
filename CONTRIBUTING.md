# Contributing to A2

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository.
2. Clone your fork.
3. Create a feature branch: `git checkout -b feature/my-feature`.
4. Build: `mvn clean install`.
5. Make your changes + add tests.
6. Push and open a Pull Request.

## Code Style

- Java 17+.
- Prefer immutable data objects.
- Keep the annotation module dependency-free.
- Document public SPI methods.

## Adding a New Protocol Provider

1. Implement `io.a2.spi.ProtocolProvider`.
2. Register it with `A2Runtime.get().register(provider)`.
3. Add an example under `a2-examples`.
4. Update the README and `docs/ANNOTATION_CONTRACT.md` if needed.

## License

By contributing you agree that your contributions will be licensed under the Apache License 2.0.
