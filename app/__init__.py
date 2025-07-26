from flask import Flask
from .extensions import socketio
from .routes import routes
from .models import db
import os



def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///findit.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    socketio.init_app(app)
    
    with app.app_context():
        db.create_all() 

    from .routes import routes
    app.register_blueprint(routes)

    return app



__all__ = ['create_app', 'socketio']
