from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
import os
from datetime import timedelta

app = Flask(__name__)

# ===================== CONFIGURATION =====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

db = SQLAlchemy(app)

# ===================== DATABASE MODELS =====================
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# ===================== INPUT VALIDATION =====================
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, "Username is valid"

# ===================== AUTH DECORATORS =====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ===================== ROUTES =====================

@app.route('/')
def index():
    return redirect(url_for('login') if 'user_id' not in session else url_for('dashboard'))

# -------- REGISTRATION --------
@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        errors = []

        # Validate inputs
        if not username:
            errors.append('Username is required.')
        else:
            is_valid, msg = validate_username(username)
            if not is_valid: errors.append(msg)

        if not email:
            errors.append('Email is required.')
        elif not validate_email(email):
            errors.append('Invalid email format.')

        if not password:
            errors.append('Password is required.')
        else:
            is_valid, msg = validate_password(password)
            if not is_valid: errors.append(msg)

        if password != confirm_password:
            errors.append('Passwords do not match.')

        # Check if user exists
        if not errors:
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
            if existing_user:
                if existing_user.username == username:
                    errors.append('Username already exists.')
                if existing_user.email == email:
                    errors.append('Email already registered.')

        if errors:
            for e in errors: flash(e, 'danger')
            return render_template('registration.html')

        # Create user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('registration.html')

# -------- LOGIN --------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email: flash('Email is required.', 'danger'); return render_template('login.html')
        if not password: flash('Password is required.', 'danger'); return render_template('login.html')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session.permanent = True
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            return render_template('login.html')

    return render_template('login.html')

# -------- DASHBOARD --------
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

# -------- ADMIN PANEL --------
@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    return render_template('admin.html', users=users)

# -------- PROFILE --------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST' and user.role == 'admin':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()

        if not username or not email:
            flash("Username and email are required.", "danger")
        elif User.query.filter(User.username == username, User.id != user.id).first():
            flash("Username already taken.", "danger")
        elif User.query.filter(User.email == email, User.id != user.id).first():
            flash("Email already taken.", "danger")
        else:
            user.username = username
            user.email = email
            db.session.commit()
            flash("Admin account updated successfully!", "success")
            return redirect(url_for('profile'))
        
    return render_template('profile.html', user=user)


@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_admin(user_id):
    admin = User.query.get_or_404(user_id)  # keep variable name 'admin' to match template

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()

        if not username or not email:
            flash("Username and email are required.", "danger")
            return render_template('edit_admin.html', admin=admin)

        # Check uniqueness
        if User.query.filter(User.username == username, User.id != admin.id).first():
            flash("Username already taken.", "danger")
            return render_template('edit_admin.html', admin=admin)
        if User.query.filter(User.email == email, User.id != admin.id).first():
            flash("Email already taken.", "danger")
            return render_template('edit_admin.html', admin=admin)

        admin.username = username
        admin.email = email
        db.session.commit()
        flash("Admin account updated successfully!", "success")
        return redirect(url_for('edit_admin'))

    return render_template('edit_admin.html', admin=admin)

# -------- CHANGE PASSWORD --------
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        errors = []
        if not current: errors.append('Current password is required.')
        elif not user.check_password(current): errors.append('Current password is incorrect.')
        if not new: errors.append('New password is required.')
        else:
            is_valid, msg = validate_password(new)
            if not is_valid: errors.append(msg)
        if new != confirm: errors.append('New passwords do not match.')

        if errors:
            for e in errors: flash(e, 'danger')
            return render_template('change_password.html')

        user.set_password(new)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('change_password.html')

# -------- LOGOUT --------
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ===================== ERROR HANDLERS =====================
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(403)
@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# ===================== DATABASE INIT =====================
def init_db():
    with app.app_context():
        db.create_all()
        # Create admin if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin_db@gmail.com', role='admin')
            admin.set_password('Admin_IAS444')
            db.session.add(admin)
            db.session.commit()
            print("Admin created: username=admin, password=Admin_IAS444")
        print("Database initialized!")

# ===================== RUN APP =====================
if __name__ == '__main__':
    init_db()
    app.run(debug=True, ssl_context='adhoc' if os.environ.get('ENV') == 'production' else None)
