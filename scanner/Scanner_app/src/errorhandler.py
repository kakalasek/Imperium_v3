import logging

log_format = '%(asctime)s - %(message)s'
logging.basicConfig(format=log_format)
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

def handle_error(e):
    log.error(e)
