import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)

    # Configuration settings
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'  # Replace with your actual database URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Set the secret key (make it unique and secure)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-key')  # Use fallback if not set

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints or routes
    from .routes import main
    app.register_blueprint(main)

    return app
