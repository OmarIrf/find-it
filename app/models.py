
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

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    read = db.Column(db.Boolean, default=False)

