from flask import Flask
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from datetime import timedelta

# Extensions
bcrypt = Bcrypt()
client = None
db = None

def create_app():
    app = Flask(__name__)
    
    # Load environment variables
    load_dotenv()
    
    # Set secret key from environment
    app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key-for-development")
    
    # Database configuration
    global client, db
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise ValueError("MONGO_URI not set in environment variables")
    
    client = MongoClient(mongo_uri)
    db = client.quiz_db
    
    # Initialize extensions
    bcrypt.init_app(app)
    
    # Configuration
    app.config['UPLOAD_FOLDER'] = 'static/uploads'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Create upload folder
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Import and initialize database
    from app.utils.helpers import initialize_database
    with app.app_context():
        initialize_database()
    
    # Register blueprints - fix import paths
    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.student import student_bp
    from app.routes.questions import questions_bp
    from app.routes.quizzes import quizzes_bp
    from app.routes.results import results_bp
    from app.routes.api import api_bp
    from app.routes.notifications import notifications_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(student_bp)
    app.register_blueprint(questions_bp, url_prefix='/admin/questions')
    app.register_blueprint(quizzes_bp, url_prefix='/admin/quizzes')
    app.register_blueprint(results_bp, url_prefix='/admin/results')
    app.register_blueprint(api_bp)
    app.register_blueprint(notifications_bp)
    
    # Global after_request handler
    @app.after_request
    def after_request(response):
        """Set cache control headers for sensitive pages"""
        from flask import request
        if request.path.startswith('/admin') or request.path.startswith('/student') or request.path == '/quiz':
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        from flask import render_template
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template
        return render_template('500.html'), 500
    
    @app.errorhandler(403)
    def forbidden(error):
        from flask import render_template, session
        user_role = session.get('role', 'Unknown')
        user_permissions = session.get('permissions', [])
        return render_template('403.html', 
                             user_role=user_role,
                             user_permissions=user_permissions,
                             error_message="You don't have sufficient permissions to access this resource."), 403
    
    return app

def get_db():
    return db

def get_bcrypt():
    return bcrypt