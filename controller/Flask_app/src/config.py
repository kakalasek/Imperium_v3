# This class only has a function for 
import configparser
import os

def read_config():
    # Create a configparser object
    config = configparser.ConfigParser()

    # Since this app is going to run in a container, we need to specify the path of the .ini file in this way
    script_dir = os.path.dirname(os.path.abspath(__file__)) # Get this directories absolute path
    config_file_path = os.path.join(script_dir, 'config.ini') # Append 'config.ini' to it

    # Read the config file
    config.read(config_file_path)

    # This dictionary will be returned. For every object in the config file, there will be an object here also
    config_values = {
        'scanner_endpoint': config.get('Endpoints', 'scanner_endpoint'),
        'db_uri': config.get('Database', 'database_uri')
    }

    return config_values

