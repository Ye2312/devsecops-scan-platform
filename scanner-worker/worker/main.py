import logging
import signal
import sys
from types import FrameType

from devsecops_shared.config import settings

log = logging.getLogger("worker")

_shutdown = False


def _handle_sigterm(signum: int, frame: FrameType | None) -> None:
    global _shutdown
    log.info("received signal %s, finishing current task", signum)
    _shutdown = True


def main() -> None:
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    signal.signal(signal.SIGTERM, _handle_sigterm)
    log.info("worker started")
    sys.exit(0)


if __name__ == "__main__":
    main()
