# SBOM SCA Auditor — English documentation

SBOM SCA Auditor recursively discovers dependency metadata, obtains resolved dependency graphs with the ecosystem's standard package/build tools, builds a CycloneDX SBOM, and scans it with Trivy.

Terms used throughout the documentation:

- **lockfile** — a file that records versions already selected by the package manager;
- **manifest** — a file that declares project dependencies and version constraints;
- **transitive dependency** — a dependency introduced indirectly through another package.

The scanner does not convert an unknown source import into a guessed package version. When exact package identity or version cannot be confirmed, the evidence is written to `unresolved.json`.

Start with the root [README](../../README.md), then use:

- [Supported technologies](supported-technologies.md)
- [Architecture](architecture.md) — project source tree, responsibility of files/directories, and the end-to-end scanner pipeline.
- [Docker](docker.md)
- [Output](output.md)
- [Troubleshooting](troubleshooting.md)
