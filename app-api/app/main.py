from fastapi import FastAPI

app = FastAPI(
    title="devsecops-scan-platform",
    description="SAST + SCA scanning platform for GitHub repositories",
    version="0.1.0",
)


@app.get("/healthz", tags=["ops"])
def healthz() -> dict[str, str]:
    """Liveness probe: process is up. Does not touch the database."""
    return {"status": "ok"}
