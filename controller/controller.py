# This file is the main entrypoint of this app. It contains all the routes #

# Imports #
from flask import Flask, render_template, url_for, redirect, request
from forms import ScanForm
from models import db, Scan
from flask_config import ApplicationConfig
from config import read_config
import json
import requests

# Configuration #
app = Flask(__name__)
app.config.from_object(ApplicationConfig)
db.init_app(app)

config_data = read_config()

# Global variables #
scans = [] 
endpoints = {
    'scanner': config_data['scanner_endpoint']
}

def get_scans():
    global scans
    scans = []

    for scan in Scan.query.all():
            scans.append({
                'id': scan.id,
                'name': scan.name,
                'target': scan.target,
                'scan_json': scan.scan_json
            })

# Routes #

# Home route ## So far unused
@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

# The scanner route
@app.route("/scanner", methods=['GET', 'POST'])
def scanner():

    test = requests.get(f"{endpoints['scanner']}/@test")

    # Loading the forms
    scanform = ScanForm()

    if test.status_code == 200:
        endpoint_set = True

        get_scans()    

        # Returns for POST requests
        if request.method == 'POST' and scanform.validate():    # Scan has been initiated
            options = scanform.scan_type.data
            scan_name = 'Scan'

            match options:
                case '-sS':
                    scan_name = 'SYN Scan'
                case '-sV':
                    scan_name = 'Version Scan'
                case '-O':
                    scan_name = 'System Scan'
                case '-sF':
                    scan_name = 'Fin Scan'
                case '-sU':
                    scan_name = 'UDP Scan'
                case '-sT':
                    scan_name = 'Connect Scan'

            if scanform.no_ping.data:
                options += " -Pn"
            if scanform.randomize_hosts.data:
                options += " --randomize-hosts"
            if scanform.fragment_packets.data:
                options += " -f"

            requests.post(f"{endpoints["scanner"]}/@scan?range={scanform.ip.data}&options={options}&scan_type={scan_name}")
            return redirect(url_for("scanner"))
    
    else:
        endpoint_set = False

    # Default template return for GET requests
    return render_template('scanner.html', scanform=scanform, endpoint_set=endpoint_set, scans=scans)

# The scan route
@app.route("/scanner/scan")
def scan():
    global scans
    scan_id = request.args.get('scan_id')
    scan_json = {}

    get_scans()

    for entry in scans:
        if entry["id"] == int(scan_id):
            scan_json = json.loads(entry["scan_json"])
            break

    return render_template('scan.html', scan_json=scan_json, scan_id=scan_id)

# The host route
@app.route("/scanner/host")
def host():
    global scans
    without_mac = True
    scan_id = request.args.get('scan_id')
    host_ip = request.args.get('host_ip')
    host_json = {}

    for entry in scans:
        if entry["id"] == int(scan_id):
            scan_json = json.loads(entry["scan_json"])
            if isinstance(scan_json['host'], dict):
                if "@addr" in scan_json['host']['address']:
                    host_json = scan_json['host']
                else:
                    host_json = scan_json['host']
                    without_mac = False
            else:
                for host in scan_json['host']:
                    if "@addr" in host['address']:
                        if host['address']['@addr'] == host_ip:
                            host_json = host
                            break
                    elif host['address'][0]['@addr'] == host_ip:
                        host_json = host
                        without_mac = False
                        break

            break

    return render_template('host.html', data=host_json, without_mac=without_mac, scan_id =scan_id, host_ip=host_ip)

@app.route("/scanner/scan/show_json")
def show_json():
    global scans
    scan_id = request.args.get('scan_id')

    if request.args.get('host_ip'):
        host_ip = request.args.get('host_ip')

        for entry in scans:
            if entry["id"] == int(scan_id):
                scan_json = json.loads(entry["scan_json"])
                if isinstance(scan_json['host'], dict):
                    if "@addr" in scan_json['host']['address']:
                        host_json = scan_json['host']
                        return host_json, 200
                    else:
                        host_json = scan_json['host']
                        return host_json, 200
                else:
                    for host in scan_json['host']:
                        if "@addr" in host['address']:
                            if host['address']['@addr'] == host_ip:
                                host_json = host
                                return host_json, 200
                        elif host['address'][0]['@addr'] == host_ip:
                            host_json = host
                            return host_json, 200
                break
            
    else:

        for entry in scans:
            if entry["id"] == int(scan_id):
                scan_json = json.loads(entry["scan_json"])
                return scan_json, 200
        
    return '', 404

## THE REST
## WORK IN PROGRESS

"""
@app.route("/diagnostics", methods=['GET', 'POST'])
def diagnostics():
    form = ApiForm()
    if request.method == 'POST' and form.validate():
        try:
            if requests.get(form.endpoint.data).json()["state"] == "Diagnostics":
                endpoints[1] = True
            return redirect(url_for("diagnostics"))
        except:
            return redirect(url_for("diagnostics"))
    return render_template('diagnostics.html', form=form, endpoint_set=endpoints[1])

@app.route("/password_cracker", methods=['GET', 'POST'])
def password_cracker():
    form = ApiForm()
    if request.method == 'POST' and form.validate():
        try:
            if requests.get(form.endpoint.data).json()["state"] == "Password_cracker":
                endpoints[2] = True
            return redirect(url_for("password_cracker"))
        except:
            return redirect(url_for("password_cracker"))
    return render_template('password_cracker.html', form=form, endpoint_set=endpoints[2])

@app.route("/social_engineering", methods=['GET', 'POST'])
def social_engineering():
    form = ApiForm()
    if request.method == 'POST' and form.validate():
        try:
            if requests.get(form.endpoint.data).json()["state"] == "Social_engineering":
                endpoints[3] = True 
            return redirect(url_for("social_engineering"))
        except:
            return redirect(url_for("social_engineering"))
    return render_template('social_engineering.html', form=form, endpoint_set=endpoints[3])
"""

if __name__ == '__main__':
    app.run(debug=True)