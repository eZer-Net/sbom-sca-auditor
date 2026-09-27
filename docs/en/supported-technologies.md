# Supported technologies

The scanner aims to build a confirmed dependency graph without guessing package identity or versions. When lockfile or manifest data is not sufficient, it uses the standard package/build tools of the detected ecosystem.

| Language | Project metadata | Resolution | Transitive graph |
|---|---|---|---|
| Python | `requirements*.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock` | lock parser or pip resolution for explicit public version constraints; bare unversioned names stay unresolved | Yes; pip-resolved manifest ranges are marked as scan-time resolution |
| Java / Kotlin | `build.gradle*`, `settings.gradle*` | Gradle build + `dependencies` | Yes |
| Java / Kotlin | `pom.xml` | Maven `dependency:tree` | Yes |
| C# / .NET | `*.sln`, `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.lock.json` | `dotnet restore` + `project.assets.json` | Yes |
| Go | `go.mod`, `go.sum` | `go mod download` + `go mod graph` | Yes |
| C / C++ | `conanfile.py`, `conanfile.txt` | Conan `graph info` | Yes |
| C / C++ | `vcpkg.json` | isolated vcpkg manifest install + package metadata | Yes when vcpkg resolution succeeds |
| Node.js | `package.json` + npm/Yarn/pnpm lockfiles | lockfile parser / exact npm resolution | Yes |
| Rust | `Cargo.toml`, `Cargo.lock` | Cargo.lock parser | Yes |
| PHP | `composer.json`, `composer.lock` | Composer lock parser | Yes |

## Source-only projects

A source-only project has source files but no supported lockfile or manifest that identifies exact packages and versions. The scanner can record imports/includes as evidence, but it does not guess their registry package or version. These observations are written to `unresolved.json`.

For C/C++, a raw `#include` is especially ambiguous because a header may come from the operating system, vendored source, Conan, vcpkg or another build mechanism. Exact C/C++ resolution therefore requires supported Conan or vcpkg metadata.

## Build execution

Gradle, Maven, `dotnet restore`, Go, Conan and vcpkg run in a temporary writable copy or isolated working directory. This avoids writing build artifacts into the scanned repository. Build files can execute project-defined logic, so untrusted repositories should be scanned inside Docker or another isolated CI environment.
