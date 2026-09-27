# Архитектура

Этот документ описывает структуру проекта, назначение каждой основной директории/файла и путь данных от обнаружения repository до формирования SBOM, корреляции Trivy и итоговых отчётов.

## Поток обработки

```text
CLI
 ↓
рекурсивный discovery
 ↓
модель проекта + dependency metadata
 ↓
lockfile / manifest / package-build инструменты экосистемы
 ↓
CycloneDX SBOM модуля
 ↓
merge общего repository SBOM
 ↓
Trivy scan
 ↓
CVE correlation + dependency paths
 ↓
JSON-отчёты + интерактивный HTML dependency graph
```

**Lockfile** хранит версии, уже выбранные package manager. **Manifest** объявляет зависимости проекта. Если статической metadata недостаточно для полного dependency graph, scanner использует штатные package/build инструменты соответствующей экосистемы.

## Структура проекта

```text
sbom-sca-auditor/
├── README.md                         # Основной обзор проекта: quick start, CLI, результаты и ссылки на документацию.
├── LICENSE                           # Текст MIT License.
├── pyproject.toml                    # Metadata Python package, build backend и console entry point `sbom-sca-auditor`.
├── Dockerfile                        # Контейнерный runtime с Trivy и поддерживаемыми package/build инструментами.
├── .dockerignore                     # Файлы, исключаемые из Docker build context.
├── .gitignore                        # Generated/local artifacts, исключаемые из Git.
├── install.sh                        # Определяет ОС и запускает installer для macOS или Debian/Ubuntu.
├── sbom-sca-auditor                 # Shell launcher, который запускает `sbom_auditor.py`.
├── sbom_auditor.py                  # Прямой Python entry point основного CLI.
├── sbom_macos.py                    # Legacy/backward-compatible entry point; перенаправляет в тот же CLI.
│
├── scripts/                          # Установка scanner и внешних инструментов на host-системе.
│   ├── install-debian.sh             # Устанавливает prerequisites/tools на Debian/Ubuntu и создаёт CLI symlink.
│   └── install-macos.sh              # Устанавливает prerequisites/tools через Homebrew и создаёт CLI symlink.
│
├── sbom_builder/                     # Основная логика scanner: discovery, resolution, SBOM, Trivy и визуализация.
│   ├── __init__.py                   # Маркер Python package.
│   ├── __main__.py                   # Поддержка `python -m sbom_builder`; передаёт управление CLI.
│   ├── cli.py                        # Главный pipeline: CLI arguments, стадии scan, output layout и process log.
│   ├── config.py                     # Scan configuration, severity defaults и пути result/log/work directories.
│   ├── model.py                      # Общая модель `Project`, используемая discovery и resolver-логикой.
│   ├── detect.py                     # Рекурсивный поиск ecosystems, manifests, lockfiles и framework markers.
│   ├── identity.py                   # Стабильные module IDs для объединения module-level SBOM.
│   ├── local_generate.py             # Детерминированные parsers lockfiles/static metadata и формирование module SBOM data.
│   ├── public_resolve.py             # Orchestration resolution для Python, Node.js и Gradle + unresolved evidence.
│   ├── native_resolve.py             # Получение resolved graph через Maven, .NET, Go, Conan и vcpkg.
│   ├── merge.py                      # Объединяет module CycloneDX SBOM в единый repository SBOM и переписывает refs.
│   ├── scan.py                       # Запускает Trivy, сопоставляет findings с SBOM components и строит dependency paths.
│   ├── graph.py                      # Генерирует standalone HTML dependency explorer из SBOM + Trivy findings.
│   ├── diagnostics.py                # Преобразует ошибки package/build tools в краткие diagnostic codes и hints.
│   ├── tools.py                      # Общий запуск внешних команд, environment/PATH и helpers установки инструментов.
│   └── platform/                     # OS-specific helpers установки недостающих runtime/build инструментов.
│       ├── __init__.py               # Определение/экспорт platform helpers.
│       ├── debian.py                 # apt-based установка Trivy, .NET, Conan, vcpkg и build prerequisites.
│       └── macos.py                  # Установка команд через Homebrew на macOS.
│
├── docs/                             # Документация пользователя/оператора на английском и русском языках.
│   ├── en/
│   │   ├── README.md                 # Индекс английской документации.
│   │   ├── architecture.md           # Архитектура, дерево source files и ответственность компонентов.
│   │   ├── supported-technologies.md # Поддерживаемые ecosystems, metadata и resolution behavior.
│   │   ├── docker.md                 # Docker build/run, mounts и cache behavior.
│   │   ├── output.md                 # Создаваемые отчёты и их назначение.
│   │   └── troubleshooting.md        # Типовые ошибки resolution, registry, permissions и build.
│   └── ru/
│       ├── README.md                 # Индекс русской документации.
│       ├── architecture.md           # Этот файл: архитектура, source tree и ответственность компонентов.
│       ├── supported-technologies.md # Матрица поддерживаемых технологий и resolution.
│       ├── docker.md                 # Работа scanner через Docker.
│       ├── output.md                 # Формат и назначение результатов.
│       └── troubleshooting.md        # Диагностика типовых проблем.
│
└── tests/                            # Regression tests CLI, discovery, resolvers, SBOM merge и отчётов.
    ├── test_cli.py                   # CLI arguments/defaults и поведение отчётов.
    ├── test_cli_integration.py       # End-to-end сценарии CLI pipeline.
    ├── test_detect.py                # Recursive project/ecosystem discovery.
    ├── test_diagnostics.py           # Классификация ошибок package/build tools.
    ├── test_entrypoint.py            # Executable/module entry points.
    ├── test_fetch_modes.py           # Поведение dependency fetch/resolution modes.
    ├── test_graph.py                 # Генерация HTML graph и embedding vulnerability data.
    ├── test_merge.py                 # CycloneDX merge и переписывание references.
    ├── test_native_resolvers.py      # Maven/.NET/Go/Conan/vcpkg resolution/parsing.
    ├── test_resolution_policy.py     # Политика exact versions и unresolved без угадывания.
    ├── test_scan.py                  # Trivy correlation, summaries и dependency paths.
    ├── test_source_and_gradle.py     # Source-only evidence и Gradle behavior.
    └── test_yarn_classic.py          # Обработка Yarn Classic lockfile.
```

## Генерируемые директории

Следующие директории могут присутствовать после test/build/install операций, но не являются частью runtime-архитектуры:

```text
.pytest_cache/                        # Cache, создаваемый pytest.
build/                                # Build output setuptools.
sbom_sca_auditor.egg-info/           # Package metadata, создаваемая setuptools.
**/__pycache__/                       # Cache Python bytecode.
```

Их можно удалить и пересоздать; логика scanner не зависит от их содержимого в repository.

## Ответственность подсистем

- **Установка и prerequisites:** `install.sh`, `scripts/`, `Dockerfile` и `sbom_builder/platform/` подготавливают Trivy и инструменты экосистем.
- **Discovery repository:** `detect.py` преобразует структуру исходного repository в объекты `Project` из `model.py`.
- **Resolution и формирование SBOM:** `local_generate.py`, `public_resolve.py` и `native_resolve.py` получают подтверждённые package/version relationships; `merge.py` объединяет module SBOM.
- **Vulnerability analysis:** `scan.py` запускает Trivy по объединённому SBOM и сопоставляет findings с components и dependency paths.
- **Визуализация:** `graph.py` получает merged CycloneDX SBOM и скоррелированные Trivy findings и формирует интерактивный `dependency-graph.html`.
- **Управление pipeline:** `cli.py` связывает стадии и записывает `discovery.json`, `summary.json`, `unresolved.json`, logs и итоговые reports.
- **Диагностика и команды:** `diagnostics.py` объясняет типовые resolver failures; `tools.py` запускает внешние команды и управляет environment.

Build и dependency-resolution операции выполняются во временных writable work areas, поэтому исходный repository не используется как рабочая директория сборки.
