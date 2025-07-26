from werkzeug.security import generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    items = db.relationship("Item", backref="owner", lazy=True)
    is_admin = db.Column(db.Boolean, default=False)
    reported = db.Column(db.Boolean, default=False)
    banned_from_messaging = db.Column(db.Boolean, default=False)
    reports_received = db.relationship('UserReport', backref='reported_user', foreign_keys='UserReport.reported_user_id', lazy='dynamic')
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class UserReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    reported_user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    reporter = db.relationship('User', foreign_keys=[reporter_id], backref='reports_made')
    reported = db.relationship('User', foreign_keys=[reported_user_id])    

class Item(db.Model):
    item_id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(10))  # "lost" or "found"
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    date_reported = db.Column(db.DateTime)
    location = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"))
    contact_info = db.Column(db.String(100))

    user = db.relationship("User", backref=db.backref("reported_items", lazy=True))

class Message(db.Model):
    message_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    flagged = db.Column(db.Boolean, default=False)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    read = db.Column(db.Boolean, default=False)

