# Imports #
from flask import request, Flask
from models import db, Scan
import subprocess
import json
import xmltodict
import os
from celery import shared_task
from util import celery_init_app

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
    
    xml_content = subprocess.getoutput(f"nmap -oX - {options} {range}") # Run the scan and create an XML
    data_dict = xmltodict.parse(xml_content)    # Convert the XML to dict

    json_output = data_dict['nmaprun']
    json_output = json.dumps(json_output)   # Convert the dict to JSON
            
    new_scan = Scan(name=scan_type, target=range, scan_json=json_output)
    db.session.add(new_scan)
    db.session.commit()

@app.route("/@test")    # This route is used to test if the scanner is alive and functional
def test():
    return '', 200

@app.route("/@scan", methods=["POST"])  # This route is used to start the scan
def scan():
    options = request.args.get('options')   # Get the option of the scan
    range = request.args.get('range')   # Get the range of the scan
    scan_type = request.args.get('scan_type')   # Get the scan type

    add_scan.delay(options, range, scan_type)   # Call Celery to execute and add the scan

    return '', 201


# App starts #
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create the tables
    app.run(debug=True, port=3001, host="0.0.0.0") # Start the application