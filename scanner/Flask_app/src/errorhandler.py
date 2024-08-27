from flask import render_template
import logging
import sys

log_format = '%(asctime)s - %(message)s'
logging.basicConfig(format=log_format)
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

def handle_error(code, e):
    match code:
        case _:
            log.error(f'Unknown Error\n{e}')
            return render_template('unkown_exception'), 500