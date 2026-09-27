# SBOM SCA Auditor

SBOM SCA Auditor is a small CLI that recursively analyzes a source repository, builds a CycloneDX SBOM, scans confirmed dependencies with Trivy, and shows how vulnerable libraries enter the project.

The scanner does not invent package names or versions. It prefers a lockfile (a file containing versions already selected by the package manager), then a manifest (a file declaring project dependencies), and uses the ecosystem's standard package or build tools when a resolved dependency graph is required.

```text
Repository
   ↓ recursive discovery
Lockfile / Manifest / ecosystem tools
   ↓ resolved dependency graph
CycloneDX SBOM
   ↓
Trivy
   ↓
JSON reports + dependency graph
```

If the available project metadata is not sufficient to confirm an exact package and version, the evidence is written to `unresolved.json` instead of being added to the SBOM with a guessed value.

## Quick start

### macOS

```bash
./scripts/install-macos.sh
sbom-sca-auditor /path/to/project
```

### Debian / Ubuntu

```bash
./scripts/install-debian.sh
sbom-sca-auditor /path/to/project
```

### Docker

```bash
docker build -t sbom-sca-auditor .

docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.scan-sca_osa:/output" \
  sbom-sca-auditor
```

The repository is mounted read-only at `/workspace`. Reports are written to `$PWD/.scan-sca_osa/result/` on the host. See [Docker documentation](docs/en/docker.md).

## CLI

```bash
sbom-sca-auditor /path/to/project
```

Only three optional scan parameters are exposed:

```text
--severity LEVELS          Severities included in the report. Default: CRITICAL,HIGH
--trivy-db-update yes|no   Update the Trivy vulnerability database before scan. Default: yes
--output PATH              Output root. Default: <project>/.scan-sca_osa
```

## How dependency resolution works

| Ecosystem | How dependencies are resolved |
|---|---|
| Python | lockfiles when present; manifest constraints can be resolved by pip at scan time, while packages without a usable version constraint remain unresolved |
| Java / Kotlin — Gradle | the project Gradle wrapper or Gradle resolves runtime/compile dependencies |
| Java / Kotlin — Maven | Maven `dependency:tree` resolves direct and transitive dependencies |
| C# / .NET | `dotnet restore` creates NuGet `project.assets.json`, which is converted into the dependency graph |
| Go | `go mod graph` provides the resolved Go module graph |
| C / C++ — Conan | `conan graph info` provides the resolved Conan dependency graph |
| C / C++ — vcpkg | vcpkg resolves the manifest in an isolated temporary install root; installed package metadata is converted into the graph |

Node.js, Rust and PHP support is also retained. See [Supported technologies](docs/en/supported-technologies.md) for the full matrix and limitations.

## Result

Without `--output`, the scanner creates:

```text
<project>/.scan-sca_osa/
├── logs/
│   └── process.json
└── result/
    ├── summary.json
    ├── discovery.json
    ├── bom.cdx.json
    ├── vulnerabilities.json
    ├── unresolved.json
    └── dependency-graph.html
```

| File | What it gives you |
|---|---|
| `summary.json` | Short machine-readable summary: detected modules, included/unresolved dependencies and vulnerability totals. |
| `discovery.json` | What was found recursively: module paths, ecosystem, package manager, dependency files and selected resolution method. |
| `bom.cdx.json` | Combined CycloneDX SBOM containing confirmed package versions and dependency relationships. |
| `vulnerabilities.json` | Trivy findings with severity, installed/fixed versions and direct/transitive dependency path. |
| `unresolved.json` | Dependency evidence that could not be mapped to a confirmed package/version without guessing. |
| `dependency-graph.html` | Standalone visual graph of dependencies and vulnerable paths. |
| `logs/process.json` | Structured execution log with scan stages and important decisions. |

## Documentation

English and Russian documentation have the same structure:

### English

- [Overview](docs/en/README.md) — installation, scan flow, CLI and report overview.
- [Supported technologies](docs/en/supported-technologies.md) — languages, package managers, lockfiles/manifests and dependency resolution behavior.
- [Architecture](docs/en/architecture.md) — project structure, source-tree responsibilities and how discovery, dependency resolution, SBOM generation, Trivy and reporting fit together.
- [Docker](docs/en/docker.md) — image build, mounts, tools inside the image and report location.
- [Output](docs/en/output.md) — report files and important fields.
- [Troubleshooting](docs/en/troubleshooting.md) — common build, registry, resolution and permission problems.

### Русский

- [Обзор](docs/ru/README.md) — установка, процесс сканирования, CLI и отчёты.
- [Поддерживаемые технологии](docs/ru/supported-technologies.md) — языки, package managers, lockfile/manifest и способы получения dependency graph.
- [Архитектура](docs/ru/architecture.md) — структура проекта, назначение файлов/директорий и взаимодействие discovery, resolution, SBOM, Trivy и отчётов.
- [Docker](docs/ru/docker.md) — сборка image, mounts, инструменты внутри контейнера и расположение отчётов.
- [Результаты](docs/ru/output.md) — назначение файлов отчёта и основные поля.
- [Решение проблем](docs/ru/troubleshooting.md) — типовые проблемы build, registry, resolution и permissions.

## License

MIT — see [LICENSE](LICENSE).
