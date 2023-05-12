import uvicorn
from famautils.logger import structlog

from external_interface.app import make_app

logger = structlog.get_logger()


def run() -> None:
    try:
        logger.info("Starting Server")
        app = make_app()
        uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")  # nosec
    except Exception as e:
        logger.info(f"Error Starting Server {e}")


if __name__ == "__main__":
    run()
