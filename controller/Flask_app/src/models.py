from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    target = db.Column(db.String(100), nullable=False)
    scan_json = db.Column(db.Text, nullable=False)