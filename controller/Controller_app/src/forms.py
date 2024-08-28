# This file defines forms used in this app #

# Imports #
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired

# Forms #
class ScanForm(FlaskForm):  # This form is used in the Scanner part of of this app. It is a simple form for specifying the target and type of scan
    ip = StringField('IP Adress or Range',
                       validators=[DataRequired()])
    scan_type = SelectField("Scan Type", choices=[('-sS', 'Syn Scan'), ('-sV', 'Version Scan'), ('-O', 'System Scan'), ('-sF', 'Fin Scan'), ('-sU', 'UDP Scan'), ('-sT', 'Connect Scan')])
    no_ping = BooleanField("No Ping")
    randomize_hosts = BooleanField("Randomize Hosts")
    fragment_packets = BooleanField("Fragment Packets")
    submit = SubmitField('Scan')