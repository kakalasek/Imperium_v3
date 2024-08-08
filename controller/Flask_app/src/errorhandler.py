from flask import render_template
import logging

log_format = '%(asctime)s - %(message)s'
logging.basicConfig(format=log_format)
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

def handle_error(code, e):
    match code:
        case "EndpointNotSet":
            log.info(f'Endpoint not set\n{e}')
            return render_template('endpoint_not_set.html'), 402
        case _:
            log.error(f'Unknown Error\n{e}')
            return render_template('unkown_exceptino'), 500