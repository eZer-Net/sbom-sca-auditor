# Docker

Docker — самый простой изолированный runtime: Java/Gradle/Maven, .NET, Go, Conan, vcpkg, Node.js и Trivy уже находятся внутри image.

## Сборка

```bash
docker build -t sbom-sca-auditor .
```

## Сканирование текущего repository

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.scan-sca_osa:/output" \
  sbom-sca-auditor
```

`/workspace` подключён read-only. `/output` writable и соответствует `$PWD/.scan-sca_osa` на host. Финальные отчёты находятся в `$PWD/.scan-sca_osa/result/`.

## CLI параметры

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.scan-sca_osa:/output" \
  sbom-sca-auditor /workspace --severity CRITICAL,HIGH --trivy-db-update yes
```

## Кеш Trivy

```bash
docker volume create sbom-trivy-cache

docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.scan-sca_osa:/output" \
  -v sbom-trivy-cache:/root/.cache/trivy \
  sbom-sca-auditor
```

Package/build инструменты могут скачивать зависимости при вычислении graph. Работа идёт во временных writable-директориях контейнера; исходный repository остаётся read-only.
