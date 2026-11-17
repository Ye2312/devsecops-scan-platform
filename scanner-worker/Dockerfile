# Build from the repository root: docker build -f scanner-worker/Dockerfile .
FROM python:3.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git clones the target repository; curl is only needed to fetch Trivy and is removed afterwards.
COPY scripts/install-trivy.sh /tmp/install-trivy.sh
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && sh /tmp/install-trivy.sh /usr/local/bin \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/* /tmp/install-trivy.sh

WORKDIR /app

COPY shared/ shared/
COPY scanner-worker/ scanner-worker/
RUN pip install ./shared ./scanner-worker

# Semgrep keeps settings under $HOME; Trivy keeps its vulnerability DB in a cache volume.
RUN useradd --system --uid 10001 --create-home --home-dir /home/scanner scanner \
    && mkdir -p /var/cache/trivy \
    && chown scanner /var/cache/trivy
ENV HOME=/home/scanner \
    TRIVY_CACHE_DIR=/var/cache/trivy
USER 10001

HEALTHCHECK NONE
CMD ["python", "-m", "worker.main"]
