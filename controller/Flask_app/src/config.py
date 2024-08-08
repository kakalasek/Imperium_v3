import configparser

def read_config():
    # Create a configparser object
    config = configparser.ConfigParser()

    # Read the config file
    config.read('config.ini')

    config_values = {
        'scanner_endpoint': config.get('Endpoints', 'scanner_endpoint'),
        'db_uri': config.get('Database', 'database_uri')
    }

    return config_values

