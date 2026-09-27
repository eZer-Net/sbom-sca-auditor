# Результаты

**Dependency path** — цепочка от repository/module до конкретной библиотеки. **Unresolved dependency** — информация о зависимости, которую нельзя связать с подтверждённым package/version без предположений.

- `summary.json` — количество модулей, включённых зависимостей, unresolved и уязвимостей.
- `discovery.json` — найденные модули, ecosystems, managers, dependency files и выбранный способ resolution.
- `bom.cdx.json` — объединённый CycloneDX 1.6 SBOM с подтверждёнными версиями и dependency edges.
- `vulnerabilities.json` — findings Trivy и dependency paths.
- `unresolved.json` — evidence, исключённое из SBOM, потому что точные package/version не подтверждены.
- `dependency-graph.html` — визуальный graph всех зависимостей и vulnerable paths.
- `logs/process.json` — короткая структурированная история выполнения.

Компоненты, полученные через инструменты экосистемы, содержат property `sbom-sca-auditor:version-source`, например `gradle-resolved`, `maven-resolved`, `dotnet-restore`, `go-mod-resolved`, `conan-resolved` или `vcpkg-resolved`.
