from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://scanner:scanner@localhost:5432/scanner"
    log_level: str = "INFO"

    # How often an idle worker checks the queue.
    worker_poll_interval_seconds: float = 2.0
    # A scan still RUNNING after this long is assumed orphaned by a dead worker and is
    # re-queued. Must exceed the worst-case scan time: clone 120s + semgrep 300s + trivy 300s.
    worker_stale_after_seconds: int = 1800


settings = Settings()
