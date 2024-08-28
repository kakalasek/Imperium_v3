from flask import render_template
import logging
import sys

log_format = '%(asctime)s - %(message)s'
logging.basicConfig(format=log_format)
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

def handle_error(code, e):
    match code:
        case "ParameterException":
            log.error(f'Parameter Exception\n{e}')
        case "DatabaseError":
            log.error(f'Database Error\n{e}')
        case _:
            log.error(f'Unknown Error\n{e}')