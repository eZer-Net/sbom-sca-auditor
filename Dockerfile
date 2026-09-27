FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    VCPKG_DISABLE_METRICS=1 \
    DOTNET_ROOT=/opt/dotnet \
    PATH=/opt/dotnet:/opt/vcpkg:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       nodejs npm wget curl gnupg ca-certificates git \
       default-jdk-headless gradle maven golang-go \
       cmake ninja-build build-essential zip unzip tar \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
       | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
       > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends trivy \
    && curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel 8.0 --install-dir /opt/dotnet \
    && pip install --no-cache-dir conan \
    && git clone --depth 1 https://github.com/microsoft/vcpkg.git /opt/vcpkg \
    && /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics \
    && rm -f /tmp/dotnet-install.sh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sbom-sca-auditor
COPY pyproject.toml README.md LICENSE ./
COPY sbom_builder ./sbom_builder
RUN pip install --no-cache-dir .

RUN mkdir -p /workspace /output
ENV SBOM_AUDITOR_DOCKER=1
WORKDIR /workspace

ENTRYPOINT ["sbom-sca-auditor"]
