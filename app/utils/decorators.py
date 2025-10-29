from functools import wraps
from flask import session, redirect, url_for, abort, make_response
from app.utils.helpers import ROLES
from app.models.user_models import users_collection

def login_required(role="any"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is logged in
            if 'username' not in session and 'scholar_id' not in session:
                return redirect(url_for('auth.login'))
            
            # For admin routes, check if user has admin role
            if role == "admin":
                user_role = session.get('role')
                # Allow all admin roles (admin, faculty, coordinator)
                if user_role not in ['admin', 'faculty', 'coordinator']:
                    abort(403)
            
            # For student routes
            if role == "student" and session.get('role') != 'student':
                abort(403)
            
            # Check if user is blocked (for students)
            if session.get('role') == 'student':
                user = users_collection.find_one({'scholar_id': session['scholar_id']})
                if user and user.get('blocked', False):
                    session.clear()
                    return redirect(url_for('auth.login'))
            
            # Set cache control headers to prevent back button issues
            response = make_response(f(*args, **kwargs))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            response.headers['X-Accel-Expires'] = '0'
            return response
        return decorated_function
    return decorator

def permission_required(permission):
    """Decorator to check if user has specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('user_type') == 'super_admin':
                return f(*args, **kwargs)
            
            user_permissions = session.get('permissions', [])
            if permission not in user_permissions:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def role_required(min_role_level):
    """Decorator to check if user has minimum role level"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('user_type') == 'super_admin':
                return f(*args, **kwargs)
            
            user_role = session.get('role')
            user_level = ROLES.get(user_role, {}).get('level', 0)
            
            if user_level < min_role_level:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def no_cache(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return decorated_function