# Output

A **dependency path** is the ordered chain from the repository/module to a library. An **unresolved dependency** is dependency evidence that cannot be mapped to a confirmed package/version without guessing.

- `summary.json` — totals for modules, included dependencies, unresolved entries and vulnerabilities.
- `discovery.json` — detected modules, ecosystems, managers, dependency files and selected resolution source.
- `bom.cdx.json` — merged CycloneDX 1.6 SBOM with confirmed versions and dependency edges.
- `vulnerabilities.json` — Trivy findings and dependency paths.
- `unresolved.json` — evidence excluded from the SBOM because exact package identity/version was not confirmed.
- `dependency-graph.html` — visual graph with all dependencies and vulnerable-path mode.
- `logs/process.json` — concise structured execution history.

Components obtained through ecosystem tooling contain `sbom-sca-auditor:version-source` properties such as `gradle-resolved`, `maven-resolved`, `dotnet-restore`, `go-mod-resolved`, `conan-resolved` or `vcpkg-resolved`.
