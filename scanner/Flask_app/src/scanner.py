from flask import request, Flask
from models import db, Scan
import subprocess
import json
import xmltodict
from celery import shared_task
from util import celery_init_app

app = Flask(__name__)
app.config['SECRET_KEY'] = "73eeac3fa1a0ce48f381ca1e6d71f077"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/pipa/Personal/Projects/Imperium/v2/controller/instance/db.sqlite3'
app.config.from_mapping(
    CELERY=dict(
        broker_url="redis://localhost",
        result_backend="redis://localhost",
        task_ignore_results=True,
    ),
)

db.init_app(app)
celery_app = celery_init_app(app)

@shared_task()
def add_scan(options, range, scan_type) -> None:
    
    xml_content = subprocess.getoutput(f"sudo nmap -oX - {options} {range}")
    data_dict = xmltodict.parse(xml_content)

    json_output = data_dict['nmaprun']
    json_output = json.dumps(json_output)
            
    new_scan = Scan(name=scan_type, target=range, scan_json=json_output)
    db.session.add(new_scan)
    db.session.commit()

@app.route("/@test")
def test():
    return '', 200

@app.route("/@scan", methods=["POST"])
def scan():
    options = request.args.get('options')
    range = request.args.get('range')
    scan_type = request.args.get('scan_type')

    add_scan.delay(options, range, scan_type)

    return '', 201


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=3001)