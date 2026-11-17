# Build from the repository root: docker build -f app-api/Dockerfile .
FROM python:3.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY shared/ shared/
COPY app-api/ app-api/
RUN pip install ./shared ./app-api

# The same image runs `alembic upgrade head` as a one-off migration job.
COPY alembic.ini ./

RUN useradd --system --uid 10001 --no-create-home api
USER 10001

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=2)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
