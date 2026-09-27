# Поддерживаемые технологии

Scanner стремится построить подтверждённый dependency graph без предположений о package identity или версиях. Если данных lockfile или manifest недостаточно, используются штатные package/build инструменты обнаруженной экосистемы.

| Язык | Metadata проекта | Resolution | Транзитивный graph |
|---|---|---|---|
| Python | `requirements*.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock` | parser lockfile или pip resolution для явных public version constraints; bare unversioned package остаётся unresolved | Да; manifest ranges, разрешённые pip, помечаются как resolution на момент scan |
| Java / Kotlin | `build.gradle*`, `settings.gradle*` | Gradle build + `dependencies` | Да |
| Java / Kotlin | `pom.xml` | Maven `dependency:tree` | Да |
| C# / .NET | `*.sln`, `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.lock.json` | `dotnet restore` + `project.assets.json` | Да |
| Go | `go.mod`, `go.sum` | `go mod download` + `go mod graph` | Да |
| C / C++ | `conanfile.py`, `conanfile.txt` | Conan `graph info` | Да |
| C / C++ | `vcpkg.json` | изолированный vcpkg manifest install + metadata установленных packages | Да при успешном resolution |
| Node.js | `package.json` + npm/Yarn/pnpm lockfiles | parser lockfile / exact npm resolution | Да |
| Rust | `Cargo.toml`, `Cargo.lock` | parser Cargo.lock | Да |
| PHP | `composer.json`, `composer.lock` | parser Composer lock | Да |

## Проекты только с исходным кодом

Source-only проект содержит исходники, но не содержит поддерживаемого lockfile или manifest, позволяющего определить точные packages и версии. Scanner может сохранить imports/includes как evidence, но не сопоставляет их с registry package или версией по предположению. Такие записи сохраняются в `unresolved.json`.

Для C/C++ один `#include` особенно неоднозначен: header может поступать из операционной системы, vendored source, Conan, vcpkg или другого механизма сборки. Поэтому точный C/C++ graph требует поддерживаемой metadata Conan или vcpkg.

## Выполнение build

Gradle, Maven, `dotnet restore`, Go, Conan и vcpkg запускаются во временной writable-копии или изолированной рабочей директории. Это предотвращает появление build artifacts в исходном repository. Build scripts могут выполнять код проекта, поэтому недоверенные repositories рекомендуется сканировать через Docker или изолированный CI runtime.
