# This file contains the class with all flask base configuration

# Imports #
from config import read_config

config_data = read_config() # Read data from the config file

# This class represents the config for all flask base configuration
class ApplicationConfig:
    SECRET_KEY = "73eeac3fa1a0ce48f381ca1e6d71f077" # Setting the secret key

    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Dunno what exactly this does, but it was recommended by Flask to set to False, so I did
    SQLALCHEMY_DATABASE_URI = rf"{config_data['db_uri']}"   # Setting the database URI. The database URI is loaded from our config file

