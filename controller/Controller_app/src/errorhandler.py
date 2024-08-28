from flask import render_template
import logging
import sys

log_format = '%(asctime)s - %(message)s'
logging.basicConfig(format=log_format)
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

def handle_error(code, e):
    match code:
        case "EndpointNotSet":
            log.info(f'Endpoint not set\n{e}')
            return render_template('endpoint_not_set.html'), 402
        case "DatabaseError":
            log.error(f'Database Error\n{e}')
            return render_template('database_error'), 500
        case "RequestException":
            log.error(f'Request Exception\n{e}')
            return render_template('404.html'), 400 
        case _:
            log.error(f'Unknown Error\n{e}')
            return render_template('unkown_exception'), 500