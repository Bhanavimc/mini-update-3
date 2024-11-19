# app/config.py
import os

class Config:
    SECRET_KEY = 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'  # This creates app.db in your project root
    SQLALCHEMY_TRACK_MODIFICATIONS = False
