# Docker

Docker is the simplest isolated runtime because Java/Gradle/Maven, .NET, Go, Conan, vcpkg, Node.js and Trivy are already available in the image.

## Build

```bash
docker build -t sbom-sca-auditor .
```

## Scan current repository

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.scan-sca_osa:/output" \
  sbom-sca-auditor
```

`/workspace` is read-only. `/output` is writable and maps to `$PWD/.scan-sca_osa` on the host. Final reports are therefore in `$PWD/.scan-sca_osa/result/`.

## CLI options

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.scan-sca_osa:/output" \
  sbom-sca-auditor /workspace --severity CRITICAL,HIGH --trivy-db-update yes
```

## Trivy cache

```bash
docker volume create sbom-trivy-cache

docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.scan-sca_osa:/output" \
  -v sbom-trivy-cache:/root/.cache/trivy \
  sbom-sca-auditor
```

Package/build tools may download project dependencies while calculating the graph. They work in temporary writable directories inside the container; the mounted source remains read-only.
