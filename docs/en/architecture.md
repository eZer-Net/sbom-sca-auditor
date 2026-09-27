# Architecture

This document describes the project structure, the responsibility of each source directory/file, and how the scanner moves from repository discovery to SBOM generation, Trivy correlation, and final reports.

## Processing flow

```text
CLI
 ↓
recursive discovery
 ↓
project model + dependency metadata
 ↓
lockfile / manifest / ecosystem package-build tools
 ↓
module CycloneDX SBOM
 ↓
repository SBOM merge
 ↓
Trivy scan
 ↓
CVE correlation + dependency paths
 ↓
JSON reports + interactive HTML dependency graph
```

A **lockfile** records versions already selected by the package manager. A **manifest** declares project dependencies. When static project files do not contain the complete dependency graph, the scanner uses the ecosystem's standard package/build tools to resolve it.

## Project structure

```text
sbom-sca-auditor/
├── README.md                         # Main project overview, quick start, CLI, outputs and documentation links.
├── LICENSE                           # MIT license text.
├── pyproject.toml                    # Python package metadata, build backend and `sbom-sca-auditor` console entry point.
├── Dockerfile                        # Reproducible container runtime with Trivy and supported ecosystem/build tools.
├── .dockerignore                     # Files excluded from Docker build context.
├── .gitignore                        # Generated files and local artifacts excluded from Git.
├── install.sh                        # OS dispatcher: selects the macOS or Debian/Ubuntu installer.
├── sbom-sca-auditor                 # Portable shell launcher that executes `sbom_auditor.py`.
├── sbom_auditor.py                  # Direct Python entry point for the main CLI.
├── sbom_macos.py                    # Backward-compatible legacy entry point; forwards to the same CLI.
│
├── scripts/                          # Host installation scripts and prerequisite tooling setup.
│   ├── install-debian.sh             # Installs scanner prerequisites/tools on Debian/Ubuntu and creates the CLI symlink.
│   └── install-macos.sh              # Installs prerequisites/tools with Homebrew and creates the CLI symlink.
│
├── sbom_builder/                     # Core scanner implementation: discovery, resolution, SBOM, Trivy and visualization.
│   ├── __init__.py                   # Python package marker.
│   ├── __main__.py                   # Enables `python -m sbom_builder`; delegates to the CLI.
│   ├── cli.py                        # Main orchestration pipeline, CLI arguments, stages, output layout and process log.
│   ├── config.py                     # Scan configuration, severity defaults and result/log/work directories.
│   ├── model.py                      # Shared `Project` data model used by discovery and resolvers.
│   ├── detect.py                     # Recursive repository discovery: ecosystems, manifests, lockfiles and framework markers.
│   ├── identity.py                   # Stable module identifiers used while merging module-level SBOMs.
│   ├── local_generate.py             # Deterministic local parsers that build module SBOM data from lockfiles/static metadata.
│   ├── public_resolve.py             # Resolution orchestration for Python, Node.js and Gradle, including unresolved evidence.
│   ├── native_resolve.py             # Resolved dependency graphs via Maven, .NET, Go, Conan and vcpkg tooling.
│   ├── merge.py                      # Merges module CycloneDX documents into one repository SBOM and rewrites references.
│   ├── scan.py                       # Runs Trivy, correlates findings to SBOM components and reconstructs dependency paths.
│   ├── graph.py                      # Builds the standalone interactive HTML dependency explorer from SBOM + Trivy findings.
│   ├── diagnostics.py                # Converts package/build-tool failures into concise diagnostic codes and hints.
│   ├── tools.py                      # Shared command execution, environment/PATH handling and optional tool installation helpers.
│   └── platform/                     # OS-specific runtime installation helpers used when a required command is missing.
│       ├── __init__.py               # Detects/exports supported platform helpers.
│       ├── debian.py                 # apt-based installation of Trivy, .NET, Conan, vcpkg and build prerequisites.
│       └── macos.py                  # Homebrew-based command installation for macOS.
│
├── docs/                             # User and operator documentation, mirrored in English and Russian.
│   ├── en/
│   │   ├── README.md                 # English documentation index.
│   │   ├── architecture.md           # This architecture, source-tree and component-responsibility reference.
│   │   ├── supported-technologies.md # Supported ecosystems, metadata and dependency-resolution behavior.
│   │   ├── docker.md                 # Docker build/run model, mounts and cache behavior.
│   │   ├── output.md                 # Generated report files and their purpose.
│   │   └── troubleshooting.md        # Common resolution, registry, permission and build failures.
│   └── ru/
│       ├── README.md                 # Russian documentation index.
│       ├── architecture.md           # Russian mirror of the architecture/source-tree reference.
│       ├── supported-technologies.md # Russian technology/resolution matrix.
│       ├── docker.md                 # Russian Docker instructions.
│       ├── output.md                 # Russian output/report reference.
│       └── troubleshooting.md        # Russian troubleshooting reference.
│
└── tests/                            # Automated regression coverage for CLI, discovery, resolvers, SBOM merge and reports.
    ├── test_cli.py                   # CLI argument/default and report behavior.
    ├── test_cli_integration.py       # End-to-end CLI pipeline scenarios.
    ├── test_detect.py                # Recursive project/ecosystem discovery.
    ├── test_diagnostics.py           # Build/package-manager failure classification.
    ├── test_entrypoint.py            # Executable/module entry points.
    ├── test_fetch_modes.py           # Dependency fetch/resolution mode behavior.
    ├── test_graph.py                 # HTML dependency graph generation and vulnerability data embedding.
    ├── test_merge.py                 # CycloneDX module merge and reference rewriting.
    ├── test_native_resolvers.py      # Maven/.NET/Go/Conan/vcpkg graph parsing/resolution.
    ├── test_resolution_policy.py     # Conservative exact-version/unresolved policy.
    ├── test_scan.py                  # Trivy finding correlation, summaries and dependency paths.
    ├── test_source_and_gradle.py     # Source-only evidence handling and Gradle behavior.
    └── test_yarn_classic.py          # Yarn Classic lockfile dependency handling.
```

## Generated directories

The following directories can appear in a working/package build but are not part of the runtime architecture:

```text
.pytest_cache/                        # pytest cache generated by test runs.
build/                                # setuptools build output.
sbom_sca_auditor.egg-info/           # setuptools package metadata generated during packaging/install.
**/__pycache__/                       # Python bytecode caches.
```

They can be removed and regenerated; scanner logic does not depend on their checked-in contents.

## Responsibility by subsystem

- **Installation and prerequisites:** `install.sh`, `scripts/`, `Dockerfile`, and `sbom_builder/platform/` prepare Trivy and ecosystem tools.
- **Repository discovery:** `detect.py` maps the source tree into `Project` objects defined by `model.py`.
- **Dependency resolution and SBOM formation:** `local_generate.py`, `public_resolve.py`, and `native_resolve.py` obtain confirmed package/version relationships; `merge.py` combines module SBOMs.
- **Vulnerability analysis:** `scan.py` runs Trivy against the merged SBOM and maps findings back to components and dependency paths.
- **Visualization:** `graph.py` receives the merged CycloneDX SBOM plus correlated Trivy findings and emits the interactive `dependency-graph.html`.
- **Pipeline coordination:** `cli.py` connects all stages, writes `discovery.json`, `summary.json`, `unresolved.json`, logs and final reports.
- **Diagnostics/execution:** `diagnostics.py` explains common resolver failures; `tools.py` executes external commands and manages their environment.

Build and dependency-resolution operations use temporary writable work areas instead of treating the scanned repository as a build workspace.
