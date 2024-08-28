# Imports #
from flask import request, Flask
from models import db, Scan
import subprocess
import json
import xmltodict
import os
from celery import shared_task
from util import celery_init_app
from sqlalchemy.exc import OperationalError
from errorhandler import handle_error
from exceptions import ParameterException

# App config #
app = Flask(__name__)
app.config['SECRET_KEY'] = "73eeac3fa1a0ce48f381ca1e6d71f077"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URI']
app.config.from_mapping(
    CELERY=dict(
        broker_url="redis://redis",
        result_backend="redis://redis",
        task_ignore_results=True,
    ),
)

db.init_app(app)
celery_app = celery_init_app(app)

# Routes #

@shared_task()
def add_scan(options, range, scan_type) -> None:    # This function initiates the scan and writes its output to the database
    try:
        with app.app_context():
            Scan.query.all()
    
        xml_content = subprocess.getoutput(f"nmap -oX - {options} {range}") # Run the scan and create an XML
        data_dict = xmltodict.parse(xml_content)    # Convert the XML to dict

        json_output = data_dict['nmaprun']
        json_output = json.dumps(json_output)   # Convert the dict to JSON
                
        new_scan = Scan(name=scan_type, target=range, scan_json=json_output)    # Add scan to database
        db.session.add(new_scan)
        db.session.commit()
    
    except OperationalError as e:
        handle_error(e)
    except Exception as e:
        handle_error(e)

@app.route("/@test")    # This route is used to test if the scanner is alive and functional
def test():
    return '', 200

@app.route("/@scan", methods=["POST"])  # This route is used to start the scan
def scan():
    try:
        if 'options' not in request.args:
            raise ParameterException("Options parameter is missing from the request")
        
        if 'range' not in request.args:
            raise ParameterException("Range parameter is missing from the request")
        
        if 'scan_type' not in request.args:
            raise ParameterException("Scan type parameter is missing from the request")

        options = request.args.get('options')   # Get the options of the scan
        range = request.args.get('range')   # Get the range of the scan
        scan_type = request.args.get('scan_type')   # Get the scan type

        add_scan.delay(options, range, scan_type)   # Call Celery to execute and add the scan

        return '', 201
    except ParameterException as e:
        handle_error(e)
    except Exception as e:
        handle_error(e)


# App starts #
if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all() # Create the tables
        app.run(debug=True, port=3001, host="0.0.0.0") # Start the application
    except OperationalError as e:
        handle_error(e)
    except Exception as e:
        handle_error(e)