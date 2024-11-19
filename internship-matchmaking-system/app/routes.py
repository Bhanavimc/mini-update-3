from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from .models import User, Opportunity
from datetime import datetime
import os

# Define a Blueprint for routes
main = Blueprint('main', __name__)

# Middleware to check if the user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in first.", "warning")
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

# Middleware to check if the user is admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash("Access denied. Admins only.", "danger")
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

# Home page route
@main.route('/')
def index():
    return render_template('index.html')

# Admin creation route
@main.route('/create_admin', methods=['GET'])
def create_admin():
    # Admin credentials (You can set this dynamically, e.g., via environment variables)
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@gmail.com')
    admin_password = os.getenv('ADMIN_PASSWORD', 'admin')

    # Check if the admin already exists
    admin = User.query.filter_by(email=admin_email).first()
    if admin:
        flash('Admin user already exists!', 'info')
        return redirect(url_for('main.index'))

    # Create the admin user
    hashed_password = generate_password_hash(admin_password, method='sha256')
    new_admin = User(username='Admin', email=admin_email, password=hashed_password, role='admin')
    db.session.add(new_admin)
    db.session.commit()

    flash('Admin user created successfully!', 'success')
    return redirect(url_for('main.index'))

# Registration Route
@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        skills = request.form['skills']

        # Hash the password for security
        hashed_password = generate_password_hash(password, method='sha256')

        # Add the new user to the database
        new_user = User(username=username, email=email, password=hashed_password, skills=skills)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html')

# Login Route
@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the user exists in the database
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Store user data in session after successful login
            session['user_id'] = user.id
            session['role'] = user.role if hasattr(user, 'role') else 'user'  # Ensure 'role' handling
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

# Dashboard Route
@main.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    user_skills = set(user.skills.split(',')) if user.skills else set()

    opportunities = Opportunity.query.all()
    matching_opportunities = [
        opp for opp in opportunities if user_skills & set(opp.skills_required.split(','))
    ]

    return render_template('dashboard.html', user=user, opportunities=matching_opportunities)

# Create Opportunity Route
@main.route('/create_opportunity', methods=['GET', 'POST'])
@login_required
@admin_required
def create_opportunity():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        skills_required = request.form['skills_required']
        posted_date = datetime.now()

        new_opportunity = Opportunity(
            title=title,
            description=description,
            skills_required=skills_required,
            posted_date=posted_date
        )
        db.session.add(new_opportunity)
        db.session.commit()

        flash('Opportunity created successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('create_opportunity.html')

# Logout Route
@main.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.login'))
