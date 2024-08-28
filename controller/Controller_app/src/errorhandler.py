from flask import render_template
import logging

log_format = '%(asctime)s - %(message)s'
logging.basicConfig(format=log_format)
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

def handle_error(e):
    log.error(e)
    return render_template('err.html', message=e), 400