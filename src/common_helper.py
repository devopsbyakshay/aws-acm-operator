import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def log_function_entry_exit(func):
    def wrapper(*args, **kwargs):
        logger.info(f"started executing {func.__name__}")
        result = func(*args, **kwargs)
        logger.info(f"end executing {func.__name__}")
        return result
    return wrapper