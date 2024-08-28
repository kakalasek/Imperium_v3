# This file is the main entrypoint of this app. It contains all the routes #

# Imports #
from flask import Flask, render_template, url_for, redirect, request
from forms import ScanForm
from models import db, Scan
from flask_config import ApplicationConfig
from config import read_config
import json
import requests
from errorhandler import handle_error
from sqlalchemy.exc import OperationalError

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
    try:
        # Variables
        global scans
        scans = []  # Sets scans to an empty array, so the scans wont be added there twice

        for scan in Scan.query.all():   # Fills the 'scans' array with scans from the database
                scans.append({
                    'id': scan.id,
                    'name': scan.name,
                    'target': scan.target,
                    'scan_json': scan.scan_json
                })
    except Exception as e:  # Probably only database error can arise here, so I am calling every error a database error. Without a database, the app cant work, so this shut down the application
        r = handle_error("DatabaseError", e)

# Routes #

# Here to handle the 404 error, dont need to log that, so the default Flask errorhandler will do
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

# Home route ## So far unused
@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

# The scanner route
@app.route("/scanner", methods=['GET', 'POST']) # This route is the default page for the scanner extension
def scanner():
    try:
        # Variables
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
@app.route("/scanner/scan") # This route is a page for a particular scan
def scan():
    try:
        # Variables
        global scans
        scan_id = request.args.get('scan_id')

        if scan_id == None: # If no scan id is provided, this page raises an exception
            raise requests.exceptions.RequestException("Invalid Scan ID")

        scan_json = {}  # JSON for this particular scan will be stored here

        get_scans() # Refresh the scans table

        for entry in scans: # Check for each entry in the scans table. If the scan is found, load it into 'scan_json' and break
            if entry["id"] == int(scan_id):
                scan_json = json.loads(entry["scan_json"])
                break
        
        if not scan_json:   # If provided scan id was not found, this page raises an exception
            raise requests.exceptions.RequestException("Invalid Scan ID")

        return render_template('scan.html', scan_json=scan_json, scan_id=scan_id), 200
    
    except requests.exceptions.RequestException as e:
        r = handle_error('RequestException', e)
        return r
    except Exception as e:
        r = handle_error('', e)
        return r

# The host route
@app.route("/scanner/host") # This route is a page for a particular host
def host():
    try:
        # Variables
        global scans
        without_mac = True  # Is here because the json looks differently depending on if the scan was able to determine the MAC address or not
        scan_id = request.args.get('scan_id')
        host_ip = request.args.get('host_ip')
        host_json = {}

        if scan_id == None: # If no scan id is provided, this page raises an exception
            raise requests.exceptions.RequestException("Invalid Scan ID")
        
        if host_ip == None: # If no host_ip is provided, this page raises an exception
            raise requests.exceptions.RequestException("Invalid Host IP")
        
        for entry in scans: # Looking through scans for scan with the id
            if entry["id"] == int(scan_id): # There right scan was found
                scan_json = json.loads(entry["scan_json"])
                if isinstance(scan_json['host'], dict): # If scan_json['host'] is a dictionary a single host was scanned, so there is no need for further ip control
                    if "@addr" in scan_json['host']['address']: # Determine if MAC address was found
                        host_json = scan_json['host']
                    else:
                        host_json = scan_json['host']
                        without_mac = False
                else:   # Multiple hosts were scanned, so the right one must be found
                    for host in scan_json['host']:  # Find the right host
                        if "@addr" in host['address']:  # After finding the host, determine if MAC address was found too
                            if host['address']['@addr'] == host_ip:
                                host_json = host
                                break
                        elif host['address'][0]['@addr'] == host_ip:
                            host_json = host
                            without_mac = False
                            break
                break

        if not host_json:   # If provided scan id was not found, this page raises an exception
            raise requests.exceptions.RequestException("Invalid Scan ID or Host IP")

        return render_template('host.html', data=host_json, without_mac=without_mac, scan_id =scan_id, host_ip=host_ip), 200
    
    except requests.exceptions.RequestException as e:
        r = handle_error('RequestException', e)
        return r
    except Exception as e:
        r = handle_error('', e)
        return r

# The scan JSON route
@app.route("/scanner/scan/show_json")   # This route show the raw JSON of a particular scan or host
def show_json():
    try:
        # Variables
        global scans
        scan_id = request.args.get('scan_id')
        host_json = {}
        scan_json = {}

        if scan_id == None: # If no scan ID was provided, this page raises an exception
            raise requests.exceptions.RequestException("Invalid Scan ID")

        if request.args.get('host_ip'): # For JSON of a host
            host_ip = request.args.get('host_ip')

            for entry in scans: # Looking through scans for scan with the id
                if entry["id"] == int(scan_id): # There right scan was found
                    scan_json = json.loads(entry["scan_json"])
                    if isinstance(scan_json['host'], dict): # If scan_json['host'] is a dictionary a single host was scanned, so there is no need for further ip control
                        if "@addr" in scan_json['host']['address']: # Determine if MAC address was found
                            host_json = scan_json['host']
                            return host_json, 200
                        else:
                            host_json = scan_json['host']
                            return host_json, 200
                    else:   # Multiple hosts were scanned, so the right one must be found
                        for host in scan_json['host']:  # Find the right host
                            if "@addr" in host['address']:  # After finding the host, determine if MAC address was found too
                                if host['address']['@addr'] == host_ip:
                                    host_json = host
                                    return host_json, 200
                            elif host['address'][0]['@addr'] == host_ip:
                                host_json = host
                                return host_json, 200
                    break

            if not host_json:   # If an invalid host IP was provided, this page raises an exception
                raise requests.exceptions.RequestException("Invalid Scan ID or Host IP")
                
        else:   # For JSON of a scan

            for entry in scans: # Looking through scans for scan with the id
                if entry["id"] == int(scan_id): # The right scan was found
                    scan_json = json.loads(entry["scan_json"])
                    return scan_json, 200
                
            if not scan_json:   # If the scan ID is invalid, thsi page raises an exception
                raise requests.exceptions.RequestException("Invalid Scan ID")
                
    except requests.exceptions.RequestException as e:
        r = handle_error('RequestException', e)
        return r
    except Exception as e:
        r = handle_error('', e)
        return r


# The start of the program
if __name__ == '__main__':
    try:    # Checking for database error
        with app.app_context():
            Scan.query.all()

        app.run(host="0.0.0.0", port=5000, debug=True)
    except OperationalError as e:
        handle_error("DatabaseError", e)
    except Exception as e:
        handle_error("", e)