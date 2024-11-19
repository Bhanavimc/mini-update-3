from app import db
from datetime import datetime
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    skills = db.Column(db.String(200), nullable=True)  # New field for user skills

    def __repr__(self):
        return f"<User {self.username}>"

class Opportunity(db.Model):
    __tablename__ = 'opportunity'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    skills_required = db.Column(db.String(200), nullable=False)
    posted_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, title, description, skills_required, posted_date=None):
        self.title = title
        self.description = description
        self.skills_required = skills_required
        self.posted_date = posted_date or datetime.utcnow()  # default to current time if not passed

