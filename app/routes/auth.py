from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify, make_response
from app import get_bcrypt
from app.utils.decorators import login_required, no_cache
from app.utils.helpers import ROLES, create_notification, create_admin_notification, log_activity, schoolDepartments, departmentCourses
from app.models.user_models import users_collection, user_sessions_collection, admin_users_collection
from datetime import datetime, timedelta
import uuid

auth_bp = Blueprint('auth', __name__)

# Admin credentials
ADMIN_CREDENTIALS = {
    "username": "admin.computer", 
    "password": get_bcrypt().generate_password_hash("admin123").decode('utf-8')
}

@auth_bp.route('/')
def index():
    """Home page"""
    from app.utils.helpers import get_user_stats
    
    is_logged_in = bool(session.get('scholar_id') or session.get('username'))
    user = None
    if is_logged_in and session.get('role') == 'student':
        user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
        if user:
            user_stats = get_user_stats(session['scholar_id'])
            user.update(user_stats)
    return render_template('index.html', is_logged_in=is_logged_in, user=user)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Student login with Date of Birth"""
    if request.method == 'POST':
        identifier = request.form['identifier']
        dob = request.form['dob']
        
        # Validate date format
        if not is_valid_dob_format(dob):
            flash("Invalid date format. Please use DD/MM/YYYY", "error")
            return render_template('login.html')
        
        user = users_collection.find_one({"scholar_id": identifier})
        if user and user.get('dob') == dob:
            session['role'] = 'student'
            session['scholar_id'] = identifier
            session['workspace'] = str(uuid.uuid4())
            user_sessions_collection.insert_one({
                "scholar_id": identifier,
                "workspace_id": session['workspace'],
                "start_time": datetime.now()
            })
            
            # Update last login
            users_collection.update_one(
                {"scholar_id": identifier},
                {"$set": {"last_login": datetime.now()}}
            )
            
            return redirect(url_for('student.student_dashboard'))
        flash("Invalid scholar ID or date of birth", "error")
        return render_template('login.html')
    return render_template('login.html')

@auth_bp.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    """Admin panel login with role selection"""
    if request.method == 'POST':
        role = request.form.get('role')
        identifier = request.form['identifier']
        password = request.form['password']
        
        # Check if it's the super admin (original admin)
        if role == 'admin' and identifier == ADMIN_CREDENTIALS["username"]:
            if get_bcrypt().check_password_hash(ADMIN_CREDENTIALS["password"], password):
                session['role'] = 'admin'
                session['username'] = identifier
                session['user_type'] = 'super_admin'
                session['permissions'] = ROLES['admin']['permissions']
                session['dashboard_access'] = ROLES['admin']['dashboard_access']
                return redirect(url_for('admin.admin_dashboard'))
        
        # Check in admin_users collection for other roles
        admin_user = admin_users_collection.find_one({
            "username": identifier, 
            "role": role,
            "active": True
        })
        
        if admin_user and get_bcrypt().check_password_hash(admin_user['password'], password):
            session['role'] = admin_user['role']
            session['username'] = admin_user['username']
            session['user_id'] = str(admin_user['_id'])
            session['user_type'] = 'admin_user'
            session['permissions'] = ROLES.get(admin_user['role'], {}).get('permissions', [])
            session['dashboard_access'] = ROLES.get(admin_user['role'], {}).get('dashboard_access', [])
            
            # Update last login
            admin_users_collection.update_one(
                {"_id": admin_user['_id']},
                {"$set": {"last_login": datetime.now()}}
            )
            
            return redirect(url_for('admin.admin_dashboard'))
        
        flash('Invalid credentials for selected role', 'error')
        return render_template('admin_login.html', roles=ROLES.keys())
    
    return render_template('admin_login.html', roles=ROLES.keys())

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Student registration with Date of Birth"""
    if request.method == 'POST':
        try:
            scholar_id = request.form.get('scholar_id', '').strip()
            name = request.form.get('name', '').strip()
            school = request.form.get('school', '')
            department = request.form.get('department', '')
            course = request.form.get('course', '')
            semester = request.form.get('semester', '')
            email = request.form.get('email', '').strip()
            dob = request.form.get('dob', '').strip()
            confirm_dob = request.form.get('confirm-dob', '').strip()
            
            # Basic validation
            required_fields = {
                'scholar_id': scholar_id,
                'name': name,
                'school': school,
                'department': department,
                'course': course,
                'semester': semester,
                'email': email,
                'dob': dob
            }
            
            missing_fields = [field for field, value in required_fields.items() if not value]
            
            if missing_fields:
                flash(f"Missing required fields: {', '.join(missing_fields)}", "error")
                return render_template('signup.html', 
                                    school_departments=schoolDepartments,
                                    department_courses=departmentCourses)
            
            if dob != confirm_dob:
                flash("Date of Birth does not match", "error")
                return render_template('signup.html', 
                                    school_departments=schoolDepartments,
                                    department_courses=departmentCourses)
            
            # Validate date format
            if not is_valid_dob_format(dob):
                flash("Invalid date format. Please use DD/MM/YYYY", "error")
                return render_template('signup.html', 
                                    school_departments=schoolDepartments,
                                    department_courses=departmentCourses)
            
            if users_collection.find_one({"scholar_id": scholar_id}):
                flash("Scholar ID already exists", "error")
                return render_template('signup.html', 
                                    school_departments=schoolDepartments,
                                    department_courses=departmentCourses)
            
            if users_collection.find_one({"email": email}):
                flash("Email already registered", "error")
                return render_template('signup.html', 
                                    school_departments=schoolDepartments,
                                    department_courses=departmentCourses)
            
            users_collection.insert_one({
                "scholar_id": scholar_id,
                "name": name,
                "school": school,
                "department": department,
                "course": course,
                "semester": semester,
                "email": email,
                "dob": dob,  # Store date of birth in DD/MM/YYYY format
                "created_at": datetime.now(),
                "last_login": None,
                "blocked": False
            })
            
            session['role'] = 'student'
            session['scholar_id'] = scholar_id
            session['workspace'] = str(uuid.uuid4())
            user_sessions_collection.insert_one({
                "scholar_id": scholar_id,
                "workspace_id": session['workspace'],
                "start_time": datetime.now()
            })
            
            create_notification(
                scholar_id,
                "Welcome to Quiz System",
                f"Hello {name}, welcome to the DSVV Quiz System! You can now participate in quizzes for your courses.",
                "success"
            )
            
            create_admin_notification(
                "New User Registration",
                f"{name} ({scholar_id}) from {course} has registered in the system",
                "info",
                scholar_id
            )
            
            log_activity(
                "user_registered",
                f"New user registered: {name} ({scholar_id}) - {course}",
                scholar_id
            )
            
            return redirect(url_for('student.student_dashboard'))
        
        except Exception as e:
            print(f"Error in signup: {str(e)}")
            flash("An error occurred during registration. Please try again.", "error")
            return render_template('signup.html', 
                         school_departments=schoolDepartments,
                         department_courses=departmentCourses)
    
    return render_template('signup.html', 
                         school_departments=schoolDepartments,
                         department_courses=departmentCourses)

@auth_bp.route('/logout')
def logout():
    """Logout user"""
    if 'workspace' in session:
        user_sessions_collection.delete_one({"workspace_id": session.get('workspace')})
    
    session.clear()
    return redirect(url_for('auth.index'))

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password functionality - Not needed for students now"""
    from app import get_db
    db = get_db()
    
    if request.method == 'POST':
        email = request.form['email']
        
        user = users_collection.find_one({"email": email})
        if not user:
            flash("No account found with that email address", "error")
            return render_template('forgot_password.html')
        
        # Since we're using DOB instead of password, we can't reset it
        flash("Password reset is not available. Please contact administrator if you've forgotten your date of birth.", "info")
        return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token - Not needed for students now"""
    from app import get_db
    db = get_db()
    
    reset_record = db.password_resets.find_one({
        "token": token,
        "expires_at": {"$gt": datetime.now()},
        "used": False
    })
    
    if not reset_record:
        flash("Invalid or expired token", "error")
        return render_template('reset_password.html')
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template('reset_password.html', token=token)
        
        hashed_password = get_bcrypt().generate_password_hash(new_password).decode('utf-8')
        users_collection.update_one(
            {"email": reset_record['email']},
            {"$set": {"password": hashed_password}}
        )
        
        db.password_resets.update_one(
            {"_id": reset_record['_id']},
            {"$set": {"used": True}}
        )
        
        flash("Password updated successfully. You can now login with your new password.", "success")
        return render_template('reset_password.html')
    
    return render_template('reset_password.html', token=token)

def is_valid_dob_format(dob_string):
    """Validate date of birth format (DD/MM/YYYY)"""
    import re
    pattern = r'^\d{2}/\d{2}/\d{4}$'
    if not re.match(pattern, dob_string):
        return False
    
    try:
        day, month, year = map(int, dob_string.split('/'))
        # Basic date validation
        if month < 1 or month > 12:
            return False
        if day < 1 or day > 31:
            return False
        if year < 1900 or year > datetime.now().year:
            return False
        
        # Check for valid days in month
        if month in [4, 6, 9, 11] and day > 30:
            return False
        if month == 2:
            # Simple leap year check
            if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                if day > 29:
                    return False
            else:
                if day > 28:
                    return False
        return True
    except ValueError:
        return False