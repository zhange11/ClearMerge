FROM python:3.12-slim

ARG SEMGREP_VERSION=1.142.0
ARG GITLEAKS_VERSION=8.28.0

RUN pip install --no-cache-dir semgrep==${SEMGREP_VERSION} \
    && apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
       | tar -xz -C /usr/local/bin gitleaks \
    && chmod 0755 /usr/local/bin/gitleaks \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
ENTRYPOINT ["/bin/sh", "-c"]
