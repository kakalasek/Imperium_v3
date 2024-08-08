import configparser
import os

def read_config():
    # Create a configparser object
    config = configparser.ConfigParser()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file_path = os.path.join(script_dir, 'config.ini')

    # Read the config file
    config.read(config_file_path)

    config_values = {
        'scanner_endpoint': config.get('Endpoints', 'scanner_endpoint'),
        'db_uri': config.get('Database', 'database_uri')
    }

    return config_values

