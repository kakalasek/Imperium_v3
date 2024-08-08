# This file is the main entrypoint of this app. It contains all the routes #

# Imports #
from flask import Flask, render_template, url_for, redirect, request, abort
from forms import ScanForm
from models import db, Scan
from flask_config import ApplicationConfig
from config import read_config
import json
import requests
from errorhandler import handle_error

# Configuration #
app = Flask(__name__)   # Initializing the flask app
app.config.from_object(ApplicationConfig) # Configuring the flask app from the configuration class
db.init_app(app)    # Initializing the database

config_data = read_config() # Loading data from the config file 

# Global variables #
scans = [] # Used to store all the scans
endpoints = {   # Dictionary which stores all set and unset endpoints
    'scanner': config_data['scanner_endpoint']
} 

# Special functions #
def get_scans():    # Used to retrieve scans from the database
    global scans
    scans = []  # Sets scans to an empty array, so the scans wont be added there twice

    for scan in Scan.query.all():   # Fills the 'scans' array with scans from the database
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
@app.route("/scanner", methods=['GET', 'POST']) # This route is the default page for the scanner extension
def scanner():
    try:
        test = requests.get(f"{endpoints['scanner']}/@test")    # Check if the scanner node is alive
                                                                # If not, it throws a ConnectionError, which is handled at the end

        # Loading the forms
        scanform = ScanForm()

        # Checking the returned status code, just to be sure
        if test.status_code == 200:

            get_scans() # Updating the scans array with data from the database 

            # Returns for POST requests
            if request.method == 'POST' and scanform.validate():    # Scan has been initiated
                options = scanform.scan_type.data   # Options for the scan
                scan_name = 'Scan'  # Default name for the scan .. only if something went wrong for some reason, programming is kinda bullshit, you never know

                match options:  # Checking for the type of scan .. the name gets displayed only for the user comfort, has no other use beyond that
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

                # Cheking for any special checkbox options
                if scanform.no_ping.data:   
                    options += " -Pn"
                if scanform.randomize_hosts.data:
                    options += " --randomize-hosts"
                if scanform.fragment_packets.data:
                    options += " -f"

                requests.post(f"{endpoints["scanner"]}/@scan?range={scanform.ip.data}&options={options}&scan_type={scan_name}") # Making a request to the scanner
                return redirect(url_for("scanner"))
        
        # Default template return for GET requests
        return render_template('scanner.html', scanform=scanform, scans=scans), 200

    # Exception handling
    except requests.exceptions.ConnectionError as e:    # This exception is thrown if endpoint for this extension is not set
        r = handle_error('EndpointNotSet', e)   # Handling the error
        return r    # Rendering the output
    except Exception as e:  # This is for any other unforseen exception
        r = handle_error('', e)
        return r

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

        if scan_id == None:
            abort(404)

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

        abort(404)            

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)