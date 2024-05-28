import logging

logging.basicConfig(
    filename="logs_system.log",
    filemode="a",
    format="%(asctime)s, %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)


def log_info(message: str, *args):
    logging.info(message.format(*args))
