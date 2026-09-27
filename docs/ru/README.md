# SBOM SCA Auditor — русская документация

SBOM SCA Auditor рекурсивно находит dependency metadata, получает resolved dependency graph через штатные package/build инструменты экосистемы, строит CycloneDX SBOM и сканирует его через Trivy.

Термины, используемые в документации:

- **lockfile** — файл с версиями, уже выбранными package manager для проекта;
- **manifest** — файл, в котором объявлены зависимости проекта и ограничения версий;
- **transitive dependency** — зависимость, подключённая косвенно через другой package.

Scanner не преобразует неизвестный import из исходного кода в предположительную версию package. Если точные package/version подтвердить нельзя, информация сохраняется в `unresolved.json`.

Начните с корневого [README](../../README.md), затем используйте:

- [Поддерживаемые технологии](supported-technologies.md)
- [Архитектура](architecture.md) — дерево исходного проекта, назначение файлов/директорий и полный pipeline scanner.
- [Docker](docker.md)
- [Результаты](output.md)
- [Решение проблем](troubleshooting.md)
