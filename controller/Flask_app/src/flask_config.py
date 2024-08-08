from config import read_config

config_data = read_config()

class ApplicationConfig:
    SECRET_KEY = "73eeac3fa1a0ce48f381ca1e6d71f077"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = rf"{config_data['db_uri']}"

