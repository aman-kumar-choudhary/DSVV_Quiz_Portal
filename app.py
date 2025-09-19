from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort, send_file, flash
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from flask_bcrypt import Bcrypt
import uuid
import json
from datetime import datetime, timedelta
import pandas as pd
from io import BytesIO
import random
import re
from bson import ObjectId
from bson.json_util import dumps, loads
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

# Upload folder configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load environment variables
load_dotenv()
mongo_uri = os.getenv("MONGO_URI")
if not mongo_uri:
    raise ValueError("MONGO_URI not set in .env file")
client = MongoClient(mongo_uri)
db = client.quiz_db

# Collections
questions_collection = db.questions
users_collection = db.users
results_collection = db.results
user_sessions_collection = db.user_sessions
quiz_settings_collection = db.quiz_settings
feedback_collection = db.feedback
notifications_collection = db.notifications
admin_notifications_collection = db.admin_notifications
activities_collection = db.activities
question_review_collection = db.question_review
question_bank_collection = db.question_bank
quizzes_collection = db.quizzes
quiz_participants_collection = db.quiz_participants

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Admin credentials
ADMIN_CREDENTIALS = {"username": "admin.computer", "password": bcrypt.generate_password_hash("admin123").decode('utf-8')}

# Question difficulty tags
QUESTION_TAGS = ['beginner', 'easy', 'intermediate', 'advanced', 'expert']

def create_indexes():
    users_collection.create_index("scholar_id", unique=True)
    users_collection.create_index("email", unique=True)
    questions_collection.create_index("question_id", unique=True)
    question_review_collection.create_index("question_id", unique=True)
    question_bank_collection.create_index("question_id", unique=True)
    quizzes_collection.create_index("quiz_id", unique=True)
    results_collection.create_index("scholar_id")
    results_collection.create_index("workspace_id")
    results_collection.create_index([("scholar_id", 1), ("timestamp", -1)])
    user_sessions_collection.create_index("workspace_id", unique=True)
    user_sessions_collection.create_index("scholar_id")
    quiz_settings_collection.create_index([("course", 1), ("semester", 1)], unique=True)
    feedback_collection.create_index("scholar_id")
    feedback_collection.create_index([("course", 1), ("semester", 1)])
    notifications_collection.create_index("scholar_id")
    notifications_collection.create_index("timestamp")
    users_collection.create_index("blocked")
    admin_notifications_collection.create_index("timestamp")
    admin_notifications_collection.create_index("read")
    activities_collection.create_index("timestamp")
    quiz_participants_collection.create_index([("quiz_id", 1), ("scholar_id", 1)], unique=True)

def cleanup_duplicate_emails():
    pipeline = [
        {"$group": {
            "_id": "$email",
            "count": {"$sum": 1},
            "ids": {"$push": "$_id"}
        }},
        {"$match": {
            "count": {"$gt": 1}
        }}
    ]
    
    duplicates = list(users_collection.aggregate(pipeline))
    
    for dup in duplicates:
        keep_id = dup["ids"][0]
        remove_ids = dup["ids"][1:]
        users_collection.delete_many({"_id": {"$in": remove_ids}})

cleanup_duplicate_emails()
create_indexes()

def add_blocked_field():
    users_collection.update_many(
        {"blocked": {"$exists": False}},
        {"$set": {"blocked": False}}
    )

add_blocked_field()

def create_notification(scholar_id, title, message, notification_type="info"):
    notification = {
        "scholar_id": scholar_id,
        "title": title,
        "message": message,
        "type": notification_type,
        "read": False,
        "timestamp": datetime.now()
    }
    notifications_collection.insert_one(notification)
    return notification

def create_admin_notification(title, message, notification_type="info", scholar_id=None, course=None, semester=None):
    notification = {
        "title": title,
        "message": message,
        "type": notification_type,
        "read": False,
        "timestamp": datetime.now(),
        "scholar_id": scholar_id,
        "course": course,
        "semester": semester
    }
    admin_notifications_collection.insert_one(notification)
    return notification

def get_admin_notifications(limit=20):
    notifications = list(admin_notifications_collection.find().sort("timestamp", -1).limit(limit))
    for notification in notifications:
        notification['_id'] = str(notification['_id'])
        if 'timestamp' in notification and isinstance(notification['timestamp'], datetime):
            notification['timestamp'] = notification['timestamp'].isoformat()
    return notifications

def mark_admin_notifications_read():
    admin_notifications_collection.update_many(
        {"read": False},
        {"$set": {"read": True}}
    )

def get_notifications(scholar_id, limit=10):
    notifications = list(notifications_collection.find(
        {"scholar_id": scholar_id}
    ).sort("timestamp", -1).limit(limit))
    for notification in notifications:
        notification['_id'] = str(notification['_id'])
        if 'timestamp' in notification and isinstance(notification['timestamp'], datetime):
            notification['timestamp'] = notification['timestamp'].isoformat()
    return notifications

def get_user_stats(scholar_id):
    quiz_attempts = results_collection.count_documents({"scholar_id": scholar_id, "published": True})
    pipeline = [
        {"$match": {"scholar_id": scholar_id, "published": True}},
        {"$group": {
            "_id": None,
            "average_score": {"$avg": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}},
            "highest_score": {"$max": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}}
        }}
    ]
    stats = list(results_collection.aggregate(pipeline))
    if stats:
        return {
            "quiz_attempts": quiz_attempts,
            "average_score": round(stats[0].get("average_score", 0), 1),
            "highest_score": round(stats[0].get("highest_score", 0), 1)
        }
    else:
        return {
            "quiz_attempts": 0,
            "average_score": 0,
            "highest_score": 0
        }

def add_created_at_to_users():
    users_collection.update_many(
        {"created_at": {"$exists": False}},
        {"$set": {"created_at": datetime.now()}}
    )

def is_quiz_active(course, semester):
    """Check if there's an active quiz for the given course/semester"""
    # Check if there's an active quiz for this specific course/semester
    specific_quiz = quizzes_collection.find_one({
        "course": course,
        "semester": semester,
        "status": "active"
    })
    
    # Check if there's an active quiz with "all" for course and/or semester
    all_course_quiz = quizzes_collection.find_one({
        "course": "all",
        "semester": semester,
        "status": "active"
    })
    
    all_semester_quiz = quizzes_collection.find_one({
        "course": course,
        "semester": "all",
        "status": "active"
    })
    
    all_course_semester_quiz = quizzes_collection.find_one({
        "course": "all",
        "semester": "all", 
        "status": "active"
    })
    
    # Return True if any quiz is active (don't check for active questions)
    return (specific_quiz is not None or 
            all_course_quiz is not None or 
            all_semester_quiz is not None or 
            all_course_semester_quiz is not None)

def find_active_quiz(course, semester):
    """Find an active quiz for the given course/semester, handling 'all' values"""
    # Try exact match first
    quiz = quizzes_collection.find_one({
        "course": course,
        "semester": semester,
        "status": "active"
    })
    if quiz:
        return quiz
    
    # Try course="all" with specific semester
    quiz = quizzes_collection.find_one({
        "course": "all",
        "semester": semester,
        "status": "active"
    })
    if quiz:
        return quiz
    
    # Try specific course with semester="all"
    quiz = quizzes_collection.find_one({
        "course": course,
        "semester": "all",
        "status": "active"
    })
    if quiz:
        return quiz
    
    # Try both "all"
    quiz = quizzes_collection.find_one({
        "course": "all",
        "semester": "all",
        "status": "active"
    })
    return quiz

def log_activity(activity_type, description, scholar_id=None, course=None, semester=None):
    activity = {
        "type": activity_type,
        "description": description,
        "scholar_id": scholar_id,
        "course": course,
        "semester": semester,
        "timestamp": datetime.now()
    }
    activities_collection.insert_one(activity)
    return activity

add_created_at_to_users()

@app.route('/')
def index():
    is_logged_in = bool(session.get('scholar_id') or session.get('username'))
    user = None
    if is_logged_in and session.get('role') == 'student':
        user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
        if user:
            user_stats = get_user_stats(session['scholar_id'])
            user.update(user_stats)
    return render_template('index.html', is_logged_in=is_logged_in, user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        identifier = request.form['identifier']
        password = request.form['password']
        user = users_collection.find_one({"scholar_id": identifier})
        if user and bcrypt.check_password_hash(user['password'], password):
            session['role'] = 'student'
            session['scholar_id'] = identifier
            session['workspace'] = str(uuid.uuid4())
            user_sessions_collection.insert_one({
                "scholar_id": identifier,
                "workspace_id": session['workspace'],
                "start_time": datetime.now()
            })
            return redirect(url_for('student_dashboard'))
        flash("Invalid student credentials", "error")
        return render_template('login.html')
    return render_template('login.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        role = request.form.get('role')
        identifier = request.form['identifier']
        password = request.form['password']
        if role == 'admin':
            if identifier == ADMIN_CREDENTIALS["username"] and bcrypt.check_password_hash(ADMIN_CREDENTIALS["password"], password):
                session['role'] = 'admin'
                session['username'] = identifier
                return redirect(url_for('admin'))
        flash('Invalid admin credentials', 'error')
        return render_template('admin_login.html')
    return render_template('admin_login.html')

school_departments = {
    "School of Technology, Communication and Management": [
        "Department of Computer Sciences",
        "Department of Tourism Management",
        "Department of Journalism & Mass Communication",
        "Department of Animation and Visual Effects",
    ],
    "School of Biological Sciences and Sustainability": [
        "Department of Rural Studies and Sustainability",
    ],
    "School of Indology": [
        "Department of Sanskrit and Vedic Studies",
        "Department of Hindi",
        "Department of Indian Classical Music",
        "Department of History and Indian Culture",
    ],
    "School of Humanities, Social Sciences and Foundation Courses": [
        "Department of English",
        "Department of Education",
        "Department of Psychology",
        "Department of Life Management",
        "Department of Scientific Spirituality",
        "Department of Oriental Studies, Religious Studies & Philosophy",
        "Department of Yogic Sciences and Human Consciousness",
    ],
}

department_courses = {
    "Department of Computer Sciences": [
        "B.Sc. Information Technology (Honors)",
        "Bachelor of Computer Application (Honors)",
        "Master of Computer Application (Data Science)",
    ],
    "Department of Tourism Management": [
        "B.B.A Tourism & Travel Management (Honors)",
        "M.B.A. Tourism & Travel Management",
    ],
    "Department of Journalism & Mass Communication": [
        "B.A. Journalism and Mass Communication (Honors)",
        "M. A. Journalism and Mass Communication",
        "M. A. Spiritual Journalism",
    ],
    "Department of Animation and Visual Effects": [
        "B.Voc. (Bachelor of Vocation) in 3D Animation and VFX (Honors)",
    ],
    "Department of Rural Studies and Sustainability": [
        "Bachelor of Rural Studies (Honors)",
    ],
    "Department of English": ["B.A. English (Honors)"],
    "Department of Education": ["B.Ed. (Bachelor of Education)"],
    "Department of Psychology": [
        "B.A. Psychology (Honors)",
        "M.A. Counselling Psychology",
        "M.Sc. Counselling Psychology",
    ],
    "Department of Life Management": [
        "Life Management - Compulsory Program for PG and UG",
    ],
    "Department of Scientific Spirituality": [
        "M.Sc. Herbal Medicine and Natural Product Chemistry",
        "M.Sc. Molecular Physiology and Traditional Health Sciences",
        "M.Sc. Indigenous Approaches for Child Development & Generational Dynamics",
        "M.Sc. Indian Knowledge Systems",
        "M.A. Indian Knowledge Systems",
    ],
    "Department of Oriental Studies, Religious Studies & Philosophy": [
        "M.A. Hindu Studies",
        "M.A. Philosophy",
    ],
    "Department of Yogic Sciences and Human Consciousness": [
        "B.Sc. Yogic Science (Honors)",
        "M.Sc. Yoga Therapy",
        "M.A. Human Consciousness & Yogic Science",
        "M.Sc. Human Consciousness & Yogic Science",
        "P. G. Diploma Human Consciousness, Yoga & Alternative Therapy",
        "Certificate In Yoga And Alternative Therapy",
    ],
    "Department of Sanskrit and Vedic Studies": [
        "B.A. Sanskrit (Honors)",
        "M.A. Sanskrit",
    ],
    "Department of Hindi": ["B.A. Hindi (Honors)", "M.A. Hindi"],
    "Department of Indian Classical Music": [
        "B.A. Music (Vocal) (Honors)",
        "M.A. Music (Vocal)",
        "B.A. Music Instrumental Mridang/Tabla (Honors)",
        "M.A. Music (Tabla, Pakhaawaj)",
    ],
    "Department of History and Indian Culture": [
        "B.A. History (Honors)",
        "M. A. History and Indian Culture",
    ],
}

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            scholar_id = request.form.get('scholar_id', '').strip()
            name = request.form.get('name', '').strip()
            school = request.form.get('school', '')
            department = request.form.get('department', '')
            course = request.form.get('course', '')
            semester = request.form.get('semester', '')
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            retype_password = request.form.get('retype-password', '')
            
            # Basic validation - check if required fields are present
            required_fields = {
                'scholar_id': scholar_id,
                'name': name,
                'school': school,
                'department': department,
                'course': course,
                'semester': semester,
                'email': email,
                'password': password
            }
            
            missing_fields = [field for field, value in required_fields.items() if not value]
            
            if missing_fields:
                flash(f"Missing required fields: {', '.join(missing_fields)}", "error")
                return render_template('signup.html', 
                                    school_departments=school_departments,
                                    department_courses=department_courses)
            
            if password != retype_password:
                flash("Passwords do not match", "error")
                return render_template('signup.html', 
                                    school_departments=school_departments,
                                    department_courses=department_courses)
            
            if users_collection.find_one({"scholar_id": scholar_id}):
                flash("Scholar ID already exists", "error")
                return render_template('signup.html', 
                                    school_departments=school_departments,
                                    department_courses=department_courses)
            
            if users_collection.find_one({"email": email}):
                flash("Email already registered", "error")
                return render_template('signup.html', 
                                    school_departments=school_departments,
                                    department_courses=department_courses)
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users_collection.insert_one({
                "scholar_id": scholar_id,
                "name": name,
                "school": school,
                "department": department,
                "course": course,
                "semester": semester,
                "email": email,
                "password": hashed_password,
                "created_at": datetime.now(),
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
            
            # Create welcome notification
            create_notification(
                scholar_id,
                "Welcome to Quiz System",
                f"Hello {name}, welcome to the DSVV Quiz System! You can now participate in quizzes for your courses.",
                "success"
            )
            
            # Create admin notification for new registration
            create_admin_notification(
                "New User Registration",
                f"{name} ({scholar_id}) from {course} has registered in the system",
                "info",
                scholar_id
            )
            
            # Log activity
            log_activity(
                "user_registered",
                f"New user registered: {name} ({scholar_id}) - {course}",
                scholar_id
            )
            
            return redirect(url_for('student_dashboard'))
        
        except Exception as e:
            print(f"Error in signup: {str(e)}")
            flash("An error occurred during registration. Please try again.", "error")
            return render_template('signup.html', 
                         school_departments=school_departments,
                         department_courses=department_courses)
    
    # For GET request, pass the school and department data to the template
    return render_template('signup.html', 
                         school_departments=school_departments,
                         department_courses=department_courses)

@app.route('/quiz')
def quiz():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    if 'questions' not in session:
        return redirect(url_for('student_dashboard'))
    
    return render_template('quiz.html')

@app.route('/api/get_questions', methods=['GET'])
def get_questions():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    if 'questions' not in session:
        return jsonify({"error": "No questions available"}), 400
    
    return jsonify(session['questions'])

@app.route('/api/students/filter', methods=['POST'])
def filter_students():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        filters = request.json
        query = {}
        
        # Build query based on filters
        for key, value in filters.items():
            if value and value != "all":
                query[key] = value
        
        students = list(users_collection.find(query, {'_id': 0, 'scholar_id': 1, 'name': 1, 'course': 1, 'semester': 1}))
        return jsonify(students)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/submit_answer', methods=['POST'])
def submit_answer():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    answer_data = request.json
    answer = answer_data.get('answer')
    question_index = answer_data.get('question_index')
    
    if answer is None or question_index is None:
        return jsonify({"error": "No answer or question index provided"}), 400
    
    if 'answers' not in session:
        session['answers'] = {}
    
    session['answers'][str(question_index)] = answer
    session.modified = True
    
    print(f"Stored answer for question {question_index}: {answer}")
    
    questions = session['questions']
    if question_index < len(questions):
        current_question = questions[question_index]
        is_correct = answer == current_question['correct_answer']
        
        return jsonify({
            "success": True, 
            "is_correct": is_correct,
            "correct_answer": current_question['correct_answer']
        })
    else:
        return jsonify({"error": "Invalid question index"}), 400

@app.route('/api/notifications')
def get_notifications_api():
    if 'scholar_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    notifications = get_notifications(session['scholar_id'], 10)
    return jsonify({"notifications": notifications})

@app.route('/api/notifications/read', methods=['POST'])
def mark_notifications_read():
    if 'scholar_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    notifications_collection.update_many(
        {"scholar_id": session['scholar_id'], "read": False},
        {"$set": {"read": True}}
    )
    
    return jsonify({"success": True, "message": "Notifications marked as read"})

@app.route('/api/next_question', methods=['POST'])
def next_question():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    session['current_question'] += 1
    current_index = session['current_question']
    questions = session['questions']
    
    if current_index >= len(questions):
        score = sum(1 for i, q in enumerate(questions) 
                  if session['answers'].get(str(i)) == q['correct_answer'])
        
        results_collection.insert_one({
            "scholar_id": session['scholar_id'],
            "user_name": users_collection.find_one({'scholar_id': session['scholar_id']})['name'],
            "course": session['course'],
            "semester": session['semester'],
            "score": score,
            "total": len(questions),
            "timestamp": datetime.now(),
            "workspace_id": session.get('workspace'),
            "published": False,
            "completion_time": (datetime.now() - datetime.fromisoformat(session['quiz_start_time'])).total_seconds()
        })
        
        return jsonify({"finished": True})
    
    return jsonify(questions[current_index])

@app.route('/api/finish_quiz', methods=['POST'])
def finish_quiz():
    try:
        if 'scholar_id' not in session or session['role'] != 'student':
            return jsonify({"error": "Unauthorized"}), 401
        
        if 'questions' not in session:
            return jsonify({"error": "No questions available"}), 400
        
        questions = session['questions']
        answers = session.get('answers', {})
        
        score = 0
        for i, question in enumerate(questions):
            answer_key = str(i)
            if answer_key in answers and answers[answer_key] == question['correct_answer']:
                score += 1
        
        user = users_collection.find_one({'scholar_id': session['scholar_id']})
        user_name = user['name'] if user else 'Unknown'
        
        quiz_start = datetime.fromisoformat(session['quiz_start_time'])
        completion_time = (datetime.now() - quiz_start).total_seconds()
        
        quiz_data = {
            "scholar_id": session['scholar_id'],
            "user_name": user_name,
            "course": session.get('course', ''),
            "semester": session.get('semester', ''),
            "score": score,
            "total": len(questions),
            "timestamp": datetime.now(),
            "workspace_id": session.get('workspace'),
            "published": False,
            "completion_time": completion_time,
            "quiz_id": session.get('quiz_id')
        }
        
        existing_result = results_collection.find_one({"workspace_id": session.get('workspace')})
        
        if existing_result:
            results_collection.update_one(
                {"workspace_id": session.get('workspace')},
                {"$set": quiz_data}
            )
        else:
            results_collection.insert_one(quiz_data)
        
        create_admin_notification(
            "Quiz Completed",
            f"{user_name} ({session['scholar_id']}) has completed the {session.get('course', '')} Semester {session.get('semester', '')} quiz with score {score}/{len(questions)}",
            "success",
            session['scholar_id'],
            session.get('course', ''),
            session.get('semester', '')
        )
        
        log_activity(
            "quiz_completed",
            f"{user_name} completed {session.get('course', '')} Semester {session.get('semester', '')} quiz with score {score}/{len(questions)}",
            session['scholar_id'],
            session.get('course', ''),
            session.get('semester', '')
        )
        
        session_keys = ['questions', 'answers', 'current_question', 'quiz_start_time', 'course', 'semester', 'quiz_duration', 'quiz_id']
        for key in session_keys:
            session.pop(key, None)
        
        return jsonify({
            "success": True,
            "score": score,
            "total": len(questions),
            "redirect": url_for('feedback')
        })
        
    except Exception as e:
        print(f"Error in finish_quiz: {str(e)}")
        return jsonify({
            "redirect": url_for('feedback'),
            "error": str(e)
        }), 500

@app.route('/check_time', methods=['GET'])
def check_time():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    if 'quiz_start_time' not in session:
        return jsonify({"error": "Quiz not started"}), 400
    
    quiz_start = datetime.fromisoformat(session['quiz_start_time'])
    duration = session.get('quiz_duration', 600)
    time_elapsed = (datetime.now() - quiz_start).total_seconds()
    time_left = max(0, duration - time_elapsed)
    
    return jsonify({
        "time_up": time_elapsed >= duration,
        "time_left": time_left,
        "time_left_minutes": int(time_left // 60),
        "time_left_seconds": int(time_left % 60)
    })


@app.route('/api/admin_notifications')
def get_admin_notifications_api():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    notifications = get_admin_notifications(50)
    return jsonify({"notifications": notifications})

@app.route('/api/admin_notifications/read', methods=['POST'])
def mark_admin_notifications_read_api():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    mark_admin_notifications_read()
    return jsonify({"success": True, "message": "All notifications marked as read"})

@app.route('/api/admin_notifications/clear', methods=['POST'])
def clear_admin_notifications_api():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_notifications_collection.delete_many({})
    return jsonify({"success": True, "message": "All notifications cleared"})

@app.route('/api/quiz_stats')
def quiz_stats():
    active_quizzes = questions_collection.distinct("course", {"active": True})
    
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    completed_today = results_collection.count_documents({
        "timestamp": {"$gte": today_start},
        "published": True
    })
    
    active_quizzes_list = []
    for course in active_quizzes:
        activated_question = questions_collection.find_one(
            {"course": course, "active": True},
            sort=[("activated_at", -1)]
        )
        
        if activated_question and 'activated_at' in activated_question:
            active_quizzes_list.append({
                "course": course,
                "semester": activated_question.get('semester', 'N/A'),
                "start_time": activated_question['activated_at'].isoformat() if isinstance(activated_question['activated_at'], datetime) else activated_question['activated_at']
            })
    
    return jsonify({
        "active_quizzes": len(active_quizzes),
        "completed_today": completed_today,
        "active_quizzes_list": active_quizzes_list
    })

@app.route('/admin/end_quiz', methods=['POST'])
def end_quiz():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    course = request.json.get('course')
    semester = request.json.get('semester')
    
    if not course or not semester:
        return jsonify({"error": "Course and semester are required"}), 400
    
    result = questions_collection.update_many(
        {"course": course, "semester": semester},
        {"$set": {"active": False}}
    )
    
    students = users_collection.find({"course": course, "semester": semester})
    for student in students:
        create_notification(
            student['scholar_id'],
            "Quiz Ended",
            f"The quiz for {course} Semester {semester} has ended. Results will be published soon.",
            "info"
        )
    
    create_admin_notification(
        "Quiz Ended",
        f"Quiz for {course} Semester {semester} has been ended",
        "info",
        course=course,
        semester=semester
    )
    
    log_activity(
        "quiz_ended",
        f"Quiz for {course} Semester {semester} ended",
        course=course,
        semester=semester
    )
    
    return jsonify({
        "success": True,
        "message": f"Quiz ended for {course} - Semester {semester}",
        "modified_count": result.modified_count
    })

@app.route('/admin/start_quiz', methods=['POST'])
def start_quiz_admin():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    course = request.json.get('course')
    semester = request.json.get('semester')
    
    if not course or not semester:
        return jsonify({"error": "Course and semester are required"}), 400
    
    result = questions_collection.update_many(
        {"course": course, "semester": semester},
        {"$set": {"active": True, "activated_at": datetime.now()}}
    )
    
    students = users_collection.find({"course": course, "semester": semester})
    for student in students:
        create_notification(
            student['scholar_id'],
            "Quiz Started",
            f"A new quiz for {course} Semester {semester} has started. You can now take the quiz.",
            "info"
        )
    
    create_admin_notification(
        "Quiz Started",
        f"Quiz for {course} Semester {semester} has been started",
        "info",
        course=course,
        semester=semester
    )
    
    log_activity(
        "quiz_started",
        f"Quiz for {course} Semester {semester} started",
        course=course,
        semester=semester
    )
    
    return jsonify({
        "success": True,
        "message": f"Quiz started for {course} - Semester {semester}",
        "modified_count": result.modified_count
    })

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    
    if request.method == 'POST':
        rating = request.form.get('rating')
        feedback_text = request.form.get('feedback_text', '').strip()
        
        if not rating:
            flash("Please provide a rating", "error")
            return render_template('feedback.html', user=user)
        
        feedback_data = {
            "scholar_id": session['scholar_id'],
            "name": user.get('name', ''),
            "rating": int(rating),
            "text": feedback_text,
            "timestamp": datetime.now(),
            "course": session.get('course', ''),
            "semester": session.get('semester', '')
        }
        
        feedback_collection.insert_one(feedback_data)
        
        create_admin_notification(
            "Feedback Received",
            f"{user.get('name', '')} ({session['scholar_id']}) submitted feedback for {session.get('course', '')} Semester {session.get('semester', '')} quiz",
            "info",
            session['scholar_id'],
            session.get('course', ''),
            session.get('semester', '')
        )
        
        log_activity(
            "feedback_submitted",
            f"{user.get('name', '')} submitted feedback for {session.get('course', '')} Semester {session.get('semester', '')} quiz",
            session['scholar_id'],
            session.get('course', ''),
            session.get('semester', '')
        )
        
        session_keys = ['questions', 'answers', 'current_question', 'quiz_start_time', 'course', 'semester', 'quiz_duration']
        for key in session_keys:
            session.pop(key, None)
        
        flash('Thank you for your feedback! Your quiz experience has been recorded.', 'success')
        return redirect(url_for('index'))
    
    return render_template('feedback.html', user=user)

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    if 'scholar_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    name = request.json.get('name')
    email = request.json.get('email')
    
    if not name:
        return jsonify({"error": "Name is required"}), 400
    
    if email:
        existing_user = users_collection.find_one({
            "email": email,
            "scholar_id": {"$ne": session['scholar_id']}
        })
        if existing_user:
            return jsonify({"error": "Email already registered with another account"}), 400
    
    update_data = {"name": name}
    if email:
        update_data["email"] = email
    
    users_collection.update_one(
        {"scholar_id": session['scholar_id']},
        {"$set": update_data}
    )
    
    return jsonify({"success": True, "message": "Profile updated successfully"})

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        user = users_collection.find_one({"email": email})
        if not user:
            flash("No account found with that email address", "error")
            return render_template('forgot_password.html')
        
        reset_token = str(uuid.uuid4())
        
        db.password_resets.insert_one({
            "email": email,
            "token": reset_token,
            "expires_at": datetime.now() + timedelta(hours=24),
            "used": False
        })
        
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        
        flash(f"Password reset link has been sent to {email}. For demo purposes: {reset_link}", "info")
        return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
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
        
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
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

@app.route('/view_score')
def view_score():
    if 'scholar_id' not in session and 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') == 'student':
        user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
        
        results = list(results_collection.find(
            {"scholar_id": session['scholar_id'], "published": True},
            {'_id': 0}
        ).sort('timestamp', -1))
        
        latest_result = results_collection.find_one(
            {"scholar_id": session['scholar_id'], "published": True},
            {'_id': 0},
            sort=[('timestamp', -1)]
        )
        
        return render_template(
            'result.html',
            user=user,
            latest_result=latest_result,
            all_results=results
        )
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    # Get accurate stats
    total_students = users_collection.count_documents({})
    total_questions = question_bank_collection.count_documents({})
    total_quizzes = results_collection.count_documents({"published": True})
    
    # Calculate average score
    pipeline = [
        {"$match": {"published": True}},
        {"$group": {
            "_id": None,
            "avg_score": {"$avg": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}}
        }}
    ]
    
    avg_score_result = list(results_collection.aggregate(pipeline))
    average_score = avg_score_result[0]['avg_score'] if avg_score_result else 0
    
    # Get active quizzes from the quizzes collection
    active_quizzes = []
    quizzes = quizzes_collection.find({"status": "active"})
    for quiz in quizzes:
        active_quizzes.append({
            "title": quiz.get('title', 'Untitled Quiz'),
            "course": quiz.get('course', 'N/A'),
            "semester": quiz.get('semester', 'N/A'),
            "duration": quiz.get('duration', 0) // 60,  # Convert seconds to minutes
            "started_at": quiz.get('started_at', datetime.now())
        })
    
    # Get leaderboard
    pipeline = [
        {"$match": {"published": True}},
        {"$sort": {"score": -1, "completion_time": 1, "timestamp": 1}},
        {"$limit": 10},
        {"$lookup": {
            "from": "users",
            "localField": "scholar_id",
            "foreignField": "scholar_id",
            "as": "user_info"
        }},
        {"$unwind": "$user_info"},
        {"$project": {
            "scholar_id": 1,
            "user_name": "$user_info.name",
            "course": 1,
            "semester": 1,
            "score": 1,
            "total": 1,
            "timestamp": 1,
            "completion_time": 1,
            "percentage": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}
        }}
    ]
    
    leaderboard = list(results_collection.aggregate(pipeline))
    
    # Format dates in leaderboard as DD/MM/YY
    for item in leaderboard:
        if 'timestamp' in item and isinstance(item['timestamp'], datetime):
            item['formatted_date'] = item['timestamp'].strftime('%d/%m/%y')
    
    # Get recent feedback and activities
    recent_feedback = list(feedback_collection.find({}, {'_id': 0}).sort('timestamp', -1).limit(5))
    recent_activities = list(activities_collection.find({}, {'_id': 0}).sort('timestamp', -1).limit(10))
    
    stats = {
        'total_students': total_students,
        'total_questions': total_questions,
        'total_quizzes': total_quizzes,
        'average_score': round(average_score, 2),
        'leaderboard': leaderboard,
        'recent_feedback': recent_feedback,
        'recent_activities': recent_activities,
        'active_quizzes': active_quizzes
    }
    
    return render_template('admin.html', stats=stats)

@app.route('/api/daily_leaderboard')
def daily_leaderboard_api():
    # if 'username' not in session or session['role'] != 'admin':
    #     return jsonify({"error": "Unauthorized"}), 401
    
    try:
        # Get dates with quiz results
        pipeline = [
            {"$match": {"published": True}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": -1}},
            {"$limit": 7}
        ]
        
        dates_with_results = list(results_collection.aggregate(pipeline))
        
        dates_data = []
        for date_info in dates_with_results:
            date_str = date_info['_id']
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            
            # Format date as DD/MM/YY
            formatted_date = f"{date_obj.day:02d}/{date_obj.month:02d}/{date_obj.year % 100:02d}"
            
            # Get top performers for this date
            pipeline = [
                {"$match": {
                    "published": True,
                    "timestamp": {
                        "$gte": datetime(date_obj.year, date_obj.month, date_obj.day),
                        "$lt": datetime(date_obj.year, date_obj.month, date_obj.day) + timedelta(days=1)
                    }
                }},
                {"$sort": {"score": -1, "completion_time": 1, "timestamp": 1}},
                {"$limit": 10},
                {"$lookup": {
                    "from": "users",
                    "localField": "scholar_id",
                    "foreignField": "scholar_id",
                    "as": "user_info"
                }},
                {"$unwind": "$user_info"},
                {"$project": {
                    "scholar_id": 1,
                    "user_name": "$user_info.name",
                    "course": 1,
                    "semester": 1,
                    "score": 1,
                    "total": 1,
                    "timestamp": 1,
                    "completion_time": 1,
                    "percentage": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}
                }}
            ]
            
            leaders = list(results_collection.aggregate(pipeline))
            
            # Convert ObjectId to string for JSON serialization
            for leader in leaders:
                if '_id' in leader:
                    leader['_id'] = str(leader['_id'])
                if 'timestamp' in leader and isinstance(leader['timestamp'], datetime):
                    leader['timestamp'] = leader['timestamp'].isoformat()
            
            dates_data.append({
                "date": date_str,
                "formatted_date": formatted_date,
                "leaders": leaders
            })
        
        return jsonify({"dates": dates_data})
    
    except Exception as e:
        print(f"Error in daily_leaderboard_api: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/results')
def admin_results():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    course_filter = request.args.get('course', '')
    semester_filter = request.args.get('semester', '')
    
    query = {}
    if course_filter and course_filter != 'All':
        query['course'] = course_filter
    if semester_filter and semester_filter != 'All':
        query['semester'] = semester_filter
    
    results = list(results_collection.find(query, {'_id': 0}).sort('timestamp', -1))
    
    for result in results:
        user = users_collection.find_one({'scholar_id': result['scholar_id']}, {'_id': 0, 'name': 1})
        result['user_name'] = user['name'] if user else 'Unknown'
    
    top_students = []
    if course_filter and course_filter != 'All':
        pipeline = [
            {"$match": {"course": course_filter, "published": True}},
            {"$sort": {"score": -1, "completion_time": 1, "timestamp": 1}},
            {"$limit": 5},
            {"$lookup": {
                "from": "users",
                "localField": "scholar_id",
                "foreignField": "scholar_id",
                "as": "user_info"
            }},
            {"$unwind": "$user_info"},
            {"$project": {
                "scholar_id": 1,
                "user_name": "$user_info.name",
                "course": 1,
                "semester": 1,
                "score": 1,
                "total": 1,
                "timestamp": 1,
                "completion_time": 1,
                "percentage": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}
            }}
        ]
        
        if semester_filter and semester_filter != 'All':
            pipeline[0]["$match"]["semester"] = semester_filter
        
        top_students = list(results_collection.aggregate(pipeline))
    
    stats = {
        'total_quizzes': results_collection.count_documents(query),
        'total_students': len(set([r['scholar_id'] for r in results])),
        'average_score': results_collection.aggregate([
            {"$match": query},
            {"$group": {"_id": None, "avg_score": {"$avg": "$score"}}}
        ]).next().get('avg_score', 0) if results_collection.count_documents(query) > 0 else 0
    }
    
    return render_template('admin_results.html', 
                         results=results, 
                         stats=stats, 
                         selected_course=course_filter, 
                         selected_semester=semester_filter,
                         top_students=top_students)

@app.route('/student_dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    user_stats = get_user_stats(session['scholar_id'])
    user.update(user_stats)
    
    # Check if quiz is active for the student's registered course/semester
    quiz_active = is_quiz_active(user['course'], user['semester'])
    user['quiz_active'] = quiz_active
    
    if user.get('blocked', False):
        flash("You have been blocked from participating in quizzes. Contact admin.", "error")
        return render_template('student_dashboard.html', user=user)
    
    if request.method == 'POST':
        try:
            # Get the submitted course and semester
            submitted_course = request.form['course'].strip()
            submitted_semester = request.form['semester'].strip()
            
            # Verify they match the student's registered course/semester
            if user['course'].strip() != submitted_course or str(user['semester']).strip() != submitted_semester:
                flash("Invalid course or semester selection. Please select your registered course and semester.", "error")
                return render_template('student_dashboard.html', user=user)
            
            # Debug output
            print(f"Student {session['scholar_id']} attempting quiz for {submitted_course} Semester {submitted_semester}")
            
            if not is_quiz_active(submitted_course, submitted_semester):
                print("Quiz not active according to is_quiz_active()")
                flash("No active quiz for your course and semester at the moment.", "error")
                return render_template('student_dashboard.html', user=user)
            
            # Find active quiz using the helper function (handles "all" values)
            active_quiz = find_active_quiz(submitted_course, submitted_semester)
            print(f"Found active quiz: {active_quiz is not None}")
            
            if active_quiz:
                participants = active_quiz.get('participants', [])
                print(f"Quiz participants: {participants}")
                print(f"Student ID: {session['scholar_id']}")
                print(f"'all' in participants: {'all' in participants}")
                print(f"Student in participants: {session['scholar_id'] in participants}")
                
                # Allow if 'all' is in participants OR student is specifically listed
                if 'all' not in participants and session['scholar_id'] not in participants:
                    print("Student not enrolled in quiz")
                    flash("You are not enrolled in this quiz. Please contact your instructor.", "error")
                    return render_template('student_dashboard.html', user=user)
            else:
                print("No active quiz found despite is_quiz_active() returning True")
                flash("No active quiz for your course and semester at the moment.", "error")
                return render_template('student_dashboard.html', user=user)
            
            session['course'] = submitted_course
            session['semester'] = submitted_semester
            
            # Get quiz settings from the quiz document
            if active_quiz:
                duration = active_quiz.get('duration', 600)  # Duration in seconds
            else:
                # Fallback to old system
                quiz_settings = quiz_settings_collection.find_one({
                "course": submitted_course,
                "semester": submitted_semester
                })
                duration = quiz_settings['duration'] if quiz_settings and 'duration' in quiz_settings else 600

            session['quiz_duration'] = duration
            
            # Get questions from the active quiz's question list
            if active_quiz and 'questions' in active_quiz and active_quiz['questions']:
                # Get questions from the question bank using the IDs stored in the quiz
                question_ids = active_quiz['questions']
                questions = list(question_bank_collection.find({
                    "question_id": {"$in": question_ids}
                }, {'_id': 0}))
            else:
                # Fallback to old system
                questions = list(questions_collection.find({
                    "course": submitted_course,
                    "semester": submitted_semester,
                    "active": True
                }, {'_id': 0}))
            
            if not questions:
                flash("No questions available for this quiz. Please contact your instructor.", "error")
                return render_template('student_dashboard.html', user=user)
            
            session['quiz_duration'] = duration
            session['total_questions'] = len(questions)
            session['quiz_id'] = active_quiz['quiz_id'] if active_quiz else None
            
            create_admin_notification(
                "Quiz Started by Student",
                f"{user['name']} ({session['scholar_id']}) has started the {submitted_course} Semester {submitted_semester} quiz",
                "info",
                session['scholar_id'],
                submitted_course,
                submitted_semester
            )
            
            log_activity(
                "quiz_started_by_student",
                f"{user['name']} started {submitted_course} Semester {submitted_semester} quiz",
                session['scholar_id'],
                submitted_course,
                submitted_semester
            )
            
            return redirect(url_for('instructions'))
            
        except Exception as e:
            print(f"Error in student_dashboard: {str(e)}")
            import traceback
            traceback.print_exc()
            flash("An error occurred. Please try again.", "error")
            return render_template('student_dashboard.html', user=user)
    
    return render_template('student_dashboard.html', user=user)

@app.route('/api/course_leaderboard/<course>/<semester>')
def course_leaderboard(course, semester):
    if 'scholar_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        # Get dates with quiz results for this specific course/semester
        pipeline = [
            {"$match": {
                "published": True,
                "course": course,
                "semester": semester
            }},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": -1}},
            {"$limit": 7}
        ]
        
        dates_with_results = list(results_collection.aggregate(pipeline))
        
        dates_data = []
        for date_info in dates_with_results:
            date_str = date_info['_id']
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            
            # Format date as DD/MM/YY
            formatted_date = f"{date_obj.day:02d}/{date_obj.month:02d}/{date_obj.year % 100:02d}"
            
            # Get top performers for this date and course/semester
            pipeline = [
                {"$match": {
                    "published": True,
                    "course": course,
                    "semester": semester,
                    "timestamp": {
                        "$gte": datetime(date_obj.year, date_obj.month, date_obj.day),
                        "$lt": datetime(date_obj.year, date_obj.month, date_obj.day) + timedelta(days=1)
                    }
                }},
                {"$sort": {"score": -1, "completion_time": 1, "timestamp": 1}},
                {"$limit": 10},
                {"$lookup": {
                    "from": "users",
                    "localField": "scholar_id",
                    "foreignField": "scholar_id",
                    "as": "user_info"
                }},
                {"$unwind": "$user_info"},
                {"$project": {
                    "scholar_id": 1,
                    "user_name": "$user_info.name",
                    "course": 1,
                    "semester": 1,
                    "score": 1,
                    "total": 1,
                    "timestamp": 1,
                    "completion_time": 1,
                    "percentage": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}
                }}
            ]
            
            leaders = list(results_collection.aggregate(pipeline))
            
            # Convert ObjectId to string for JSON serialization
            for leader in leaders:
                if '_id' in leader:
                    leader['_id'] = str(leader['_id'])
                if 'timestamp' in leader and isinstance(leader['timestamp'], datetime):
                    leader['timestamp'] = leader['timestamp'].isoformat()
            
            dates_data.append({
                "date": date_str,
                "formatted_date": formatted_date,
                "leaders": leaders
            })
        
        return jsonify({"dates": dates_data})
    
    except Exception as e:
        print(f"Error in course_leaderboard: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/instructions')
def instructions():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    user_stats = get_user_stats(session['scholar_id'])
    user.update(user_stats)
    
    if 'course' not in session or 'semester' not in session:
        return redirect(url_for('student_dashboard'))
    
    return render_template('instructions.html', user=user)

@app.route('/start_quiz', methods=['POST'])
def start_quiz():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    if 'course' not in session or 'semester' not in session:
        return jsonify({"error": "Course and semester not selected"}), 400
    
    course = session['course']
    semester = session['semester']
    
    try:
        # Get the active quiz first
        active_quiz = find_active_quiz(course, semester)
        
        if not active_quiz:
            return jsonify({"error": "No active quiz found"}), 400
        
        # Get questions from the active quiz's question list
        if active_quiz and 'questions' in active_quiz and active_quiz['questions']:
            # Get questions from the question bank using the IDs stored in the quiz
            question_ids = active_quiz['questions']
            questions = list(question_bank_collection.find({
                "question_id": {"$in": question_ids}
            }, {'_id': 0}))
        else:
            # Fallback to old system
            questions = list(questions_collection.find({
                "course": course,
                "semester": semester,
                "active": True
            }, {'_id': 0}))
        
        if not questions:
            return jsonify({"error": "No active questions available"}), 400
        
        random.shuffle(questions)
        session['questions'] = questions
        session['current_question'] = 0
        session['answers'] = {}
        session['quiz_start_time'] = datetime.now().isoformat()
        
        # Get duration from quiz document and handle both formats
        duration = active_quiz.get('duration', 600)
        
        # If duration is less than 60, assume it's in minutes and convert to seconds
        if duration < 60:
            duration = duration * 60
            print(f"Converted duration from {duration//60} minutes to {duration} seconds")
        
        session['quiz_duration'] = duration
        
        print(f"Quiz started with {len(questions)} questions, duration: {duration} seconds ({duration//60} minutes)")
        
        return jsonify({"success": True, "redirect": url_for('quiz')})
        
    except Exception as e:
        print(f"Error in start_quiz: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# @app.route('/admin/set_quiz_time', methods=['POST'])
# def set_quiz_time():
#     if 'username' not in session or session['role'] != 'admin':
#         return jsonify({"error": "Unauthorized"}), 401
    
#     course = request.json.get('course')
#     semester = request.json.get('semester')
#     duration = request.json.get('duration')
    
#     if not all([course, semester, duration]):
#         return jsonify({"error": "Course, semester, and duration are required"}), 400
    
#     duration_seconds = int(duration) * 60
    
#     quiz_settings_collection.update_one(
#         {"course": course, "semester": semester},
#         {"$set": {"duration": duration_seconds}},
#         upsert=True
#     )
    
#     log_activity(
#         "quiz_time_set",
#         f"Set quiz time to {duration} minutes for {course} Semester {semester}",
#         course=course,
#         semester=semester
#     )
    
#     return jsonify({"success": True, "message": f"Quiz duration set to {duration} minutes for {course} Semester {semester}"})

@app.route('/publish_results', methods=['POST'])
def publish_results():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    workspace_id = request.json.get('workspace_id')
    if not workspace_id:
        return jsonify({"error": "Workspace ID is required"}), 400
    
    result = results_collection.update_many(
        {"workspace_id": workspace_id},
        {"$set": {"published": True}}
    )
    
    if result.modified_count > 0:
        published_result = results_collection.find_one({"workspace_id": workspace_id})
        if published_result:
            create_notification(
                published_result['scholar_id'],
                "Results Published",
                f"Your quiz results for {published_result['course']} Semester {published_result['semester']} have been published. Score: {published_result['score']}/{published_result['total']}",
                "success"
            )
            
            create_admin_notification(
                "Results Published",
                f"Published results for {published_result['user_name']} ({published_result['scholar_id']}) - {published_result['course']} Semester {published_result['semester']}",
                "success",
                published_result['scholar_id'],
                published_result['course'],
                published_result['semester']
            )
            
            log_activity(
                "results_published",
                f"Published results for {published_result['user_name']} - {published_result['course']} Semester {published_result['semester']}",
                published_result['scholar_id'],
                published_result['course'],
                published_result['semester']
            )
        
        return jsonify({"success": True, "message": f"Results for workspace {workspace_id} published successfully"})
    
    return jsonify({"error": "Result not found"}), 404

@app.route('/api/bulk_publish_results', methods=['POST'])
def bulk_publish_results():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.json
        workspace_ids = data.get('workspace_ids', [])
        
        if not workspace_ids:
            return jsonify({"error": "No workspace IDs provided"}), 400
        
        # Convert to list if it's not already
        if not isinstance(workspace_ids, list):
            workspace_ids = [workspace_ids]
        
        print(f"Attempting to publish {len(workspace_ids)} results: {workspace_ids}")
        
        # Use a different variable name for the update result
        update_result = results_collection.update_many(
            {"workspace_id": {"$in": workspace_ids}},
            {"$set": {"published": True}}
        )
        
        print(f"Modified count: {update_result.modified_count}")
        
        if update_result.modified_count > 0:
            # Create notifications for all published results
            published_results = list(results_collection.find(
                {"workspace_id": {"$in": workspace_ids}}
            ))
            
            for result_doc in published_results:  # Changed variable name here too
                create_notification(
                    result_doc['scholar_id'],
                    "Results Published",
                    f"Your quiz results for {result_doc['course']} Semester {result_doc['semester']} have been published. Score: {result_doc['score']}/{result_doc['total']}",
                    "success"
                )
                
                create_admin_notification(
                    "Results Published",
                    f"Published results for {result_doc['user_name']} ({result_doc['scholar_id']}) - {result_doc['course']} Semester {result_doc['semester']}",
                    "success",
                    result_doc['scholar_id'],
                    result_doc['course'],
                    result_doc['semester']
                )
                
                log_activity(
                    "results_published",
                    f"Published results for {result_doc['user_name']} - {result_doc['course']} Semester {result_doc['semester']}",
                    result_doc['scholar_id'],
                    result_doc['course'],
                    result_doc['semester']
                )
            
            return jsonify({
                "success": True, 
                "message": f"Published {update_result.modified_count} results successfully"  # Use update_result here
            })
        
        return jsonify({"error": "No results found to publish"}), 404
        
    except Exception as e:
        print(f"Error in bulk_publish_results: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/api/debug_answers', methods=['GET'])
def debug_answers():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    if 'questions' not in session:
        return jsonify({"error": "No questions available"}), 400
    
    questions = session['questions']
    answers = session.get('answers', {})
    
    debug_info = []
    for i, question in enumerate(questions):
        answer_key = str(i)
        student_answer = answers.get(answer_key, "NOT ANSWERED")
        is_correct = student_answer == question['correct_answer']
        
        debug_info.append({
            'question_index': i,
            'question_text': question['text'][:50] + "..." if len(question['text']) > 50 else question['text'],
            'student_answer': student_answer,
            'correct_answer': question['correct_answer'],
            'is_correct': is_correct
        })
    
    return jsonify({
        'total_questions': len(questions),
        'answered_questions': len(answers),
        'debug_info': debug_info
    })

@app.route('/api/clear_quiz_data', methods=['POST'])
def clear_quiz_data():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    session.pop('questions', None)
    session.pop('answers', None)
    session.pop('current_question', None)
    session.pop('quiz_start_time', None)
    session.pop('course', None)
    session.pop('semester', None)
    session.pop('quiz_duration', None)
    
    return jsonify({"success": True})

@app.route('/export_results', methods=['GET'])
def export_results():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    course = request.args.get('course', '')
    semester = request.args.get('semester', '')
    query = {}
    if course and course != 'All':
        query['course'] = course
    if semester and semester != 'All':
        query['semester'] = semester
    
    results = list(results_collection.find(query, {'_id': 0}))
    df = pd.DataFrame(results)
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='quiz_results.csv')

@app.route('/logout')
def logout():
    if 'workspace' in session:
        user_sessions_collection.delete_one({"workspace_id": session.get('workspace')})
    
    session.clear()
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.route('/admin/users')
def admin_users():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    course_filter = request.args.get('course', '')
    semester_filter = request.args.get('semester', '')
    
    query = {}
    if course_filter and course_filter != 'All':
        query['course'] = course_filter
    if semester_filter and semester_filter != 'All':
        query['semester'] = semester_filter
    
    students = list(users_collection.find(query, {'_id': 0, 'password': 0}).sort('scholar_id', 1))
    
    stats = {
        'total_students': users_collection.count_documents(query),
    }
    
    return render_template('admin_users.html', 
                           students=students, 
                           stats=stats, 
                           selected_course=course_filter, 
                           selected_semester=semester_filter)

@app.route('/api/edit_user', methods=['POST'])
def edit_user():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    scholar_id = data.get('scholar_id')
    updates = {
        "name": data.get('name'),
        "course": data.get('course'),
        "semester": data.get('semester'),
        "email": data.get('email')
    }
    
    updates = {k: v for k, v in updates.items() if v is not None}
    
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    result = users_collection.update_one({"scholar_id": scholar_id}, {"$set": updates})
    
    if result.modified_count > 0:
        log_activity(
            "user_updated",
            f"Updated user details for {scholar_id}",
            scholar_id=scholar_id
        )
        
        return jsonify({"success": True, "message": "User updated successfully"})
    return jsonify({"error": "No changes made or user not found"}), 404

@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    scholar_id = request.json.get('scholar_id')
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    users_collection.delete_one({"scholar_id": scholar_id})
    results_collection.delete_many({"scholar_id": scholar_id})
    feedback_collection.delete_many({"scholar_id": scholar_id})
    notifications_collection.delete_many({"scholar_id": scholar_id})
    user_sessions_collection.delete_many({"scholar_id": scholar_id})
    
    log_activity(
        "user_deleted",
        f"Deleted user {scholar_id} and all related data",
        scholar_id=scholar_id
    )
    
    return jsonify({"success": True, "message": "User and related data deleted successfully"})

@app.route('/api/block_user', methods=['POST'])
def block_user():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    scholar_id = data.get('scholar_id')
    block = data.get('block', True)
    
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    users_collection.update_one({"scholar_id": scholar_id}, {"$set": {"blocked": block}})
    
    if block:
        create_notification(scholar_id, "Account Blocked", "You have been blocked from participating in quizzes. Contact the admin for more details.", "warning")
        
        log_activity(
            "user_blocked",
            f"Blocked user {scholar_id}",
            scholar_id=scholar_id
        )
    else:
        create_notification(scholar_id, "Account Unblocked", "Your account has been unblocked. You can now participate in quizzes.", "success")
        
        log_activity(
            "user_unblocked",
            f"Unblocked user {scholar_id}",
            scholar_id=scholar_id
        )
    
    return jsonify({"success": True, "message": f"User {'blocked' if block else 'unblocked'} successfully"})

@app.route('/api/user_results/<scholar_id>')
def user_results(scholar_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    results = list(results_collection.find({"scholar_id": scholar_id}, {'_id': 0}.sort('timestamp', -1)))
    return jsonify({"results": results})

@app.route('/api/recent_activities')
def api_recent_activities():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    activities = list(activities_collection.find({}, {'_id': 0}).sort('timestamp', -1).limit(20))
    return jsonify({"activities": activities})

# ==================== NEW QUESTION MANAGEMENT ROUTES ====================

@app.route('/admin/questions/management')
def admin_questions_management():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    # Get counts from the database
    pending_count = question_review_collection.count_documents({})
    bank_count = question_bank_collection.count_documents({})
    
    return render_template('admin_questions_main.html', 
                         pending_count=pending_count,
                         bank_count=bank_count)

@app.route('/admin/questions/upload', methods=['GET', 'POST'])
def admin_question_upload():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'json_file' in request.files and request.files['json_file'].filename != '':
                file = request.files['json_file']
                if file.filename.endswith('.json'):
                    data = json.load(file)
                    for question_data in data:
                        question_id = str(uuid.uuid4())
                        question = {
                            "question_id": question_id,
                            "text": question_data.get('question'),
                            "options": question_data.get('options', []),
                            "correct_answer": question_data.get('correct_answer'),
                            "created_at": datetime.now(),
                            "status": "pending_review"
                        }
                        question_review_collection.insert_one(question)
                    return jsonify({"success": True, "message": f"{len(data)} questions uploaded for review"})
            
            elif 'csv_file' in request.files and request.files['csv_file'].filename != '':
                file = request.files['csv_file']
                if file.filename.endswith('.csv'):
                    df = pd.read_csv(file)
                    for _, row in df.iterrows():
                        question_id = str(uuid.uuid4())
                        question = {
                            "question_id": question_id,
                            "text": row['question'],
                            "options": [row['option1'], row['option2'], row['option3'], row['option4']],
                            "correct_answer": row['correct_answer'],
                            "created_at": datetime.now(),
                            "status": "pending_review"
                        }
                        question_review_collection.insert_one(question)
                    return jsonify({"success": True, "message": f"{len(df)} questions uploaded for review"})
            
            else:
                question_text = request.form.get('question_text')
                options = [
                    request.form.get('option1'),
                    request.form.get('option2'),
                    request.form.get('option3'),
                    request.form.get('option4')
                ]
                correct_answer_index = request.form.get('correct_answer')
                
                if not all([question_text, options[0], options[1], options[2], options[3], correct_answer_index]):
                    return jsonify({"error": "All fields are required"}), 400
                
                # Get the correct answer text based on the selected index
                correct_answer = options[int(correct_answer_index) - 1] if correct_answer_index.isdigit() else correct_answer_index
                
                if correct_answer not in options:
                    return jsonify({"error": "Correct answer must be one of the options"}), 400
                
                question_id = str(uuid.uuid4())
                question = {
                    "question_id": question_id,
                    "text": question_text,
                    "options": options,
                    "correct_answer": correct_answer,
                    "created_at": datetime.now(),
                    "status": "pending_review"
                }
                question_review_collection.insert_one(question)
                return jsonify({"success": True, "message": "Question added for review"})
                
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    
    return render_template('admin_question_upload.html')

@app.route('/admin/questions/review')
def admin_question_review():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    questions = list(question_review_collection.find({}))
    return render_template('admin_question_review.html', questions=questions, tags=QUESTION_TAGS)

@app.route('/api/questions/review/update', methods=['POST'])
def update_review_question():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    question_id = data.get('question_id')
    action = data.get('action')
    
    if not question_id or not action:
        return jsonify({"error": "Question ID and action are required"}), 400
    
    question = question_review_collection.find_one({"question_id": question_id})
    if not question:
        return jsonify({"error": "Question not found"}), 404
    
    if action == 'approve':
        question_bank_data = {
            "question_id": question['question_id'],
            "text": question['text'],
            "options": question['options'],
            "correct_answer": question['correct_answer'],
            "tags": data.get('tags', []),
            "difficulty": data.get('difficulty', 'intermediate'),
            "created_at": question['created_at'],
            "approved_at": datetime.now(),
            "approved_by": session['username']
        }
        question_bank_collection.insert_one(question_bank_data)
        question_review_collection.delete_one({"question_id": question_id})
        return jsonify({"success": True, "message": "Question approved and moved to question bank"})
    
    elif action == 'reject':
        question_review_collection.delete_one({"question_id": question_id})
        return jsonify({"success": True, "message": "Question rejected and deleted"})
    
    elif action == 'update':
        update_data = {
            "text": data.get('text', question['text']),
            "options": data.get('options', question['options']),
            "correct_answer": data.get('correct_answer', question['correct_answer'])
        }
        question_review_collection.update_one(
            {"question_id": question_id},
            {"$set": update_data}
        )
        return jsonify({"success": True, "message": "Question updated"})
    
    return jsonify({"error": "Invalid action"}), 400

@app.route('/admin/questions/bank')
def admin_question_bank():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    tag_filter = request.args.get('tag', '')
    difficulty_filter = request.args.get('difficulty', '')
    
    query = {}
    if tag_filter:
        query['tags'] = tag_filter
    if difficulty_filter:
        query['difficulty'] = difficulty_filter
    
    questions = list(question_bank_collection.find(query))
    return render_template('admin_question_bank.html', questions=questions, tags=QUESTION_TAGS)

@app.route('/api/questions/bank/update', methods=['POST'])
def update_question_bank():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    question_id = data.get('question_id')
    action = data.get('action')
    
    if not question_id or not action:
        return jsonify({"error": "Question ID and action are required"}), 400
    
    if action == 'update':
        update_data = {
            "text": data.get('text'),
            "options": data.get('options'),
            "correct_answer": data.get('correct_answer'),
            "tags": data.get('tags', []),
            "difficulty": data.get('difficulty', 'intermediate')
        }
        update_data = {k: v for k, v in update_data.items() if v is not None}
        
        question_bank_collection.update_one(
            {"question_id": question_id},
            {"$set": update_data}
        )
        return jsonify({"success": True, "message": "Question updated"})
    
    elif action == 'delete':
        question_bank_collection.delete_one({"question_id": question_id})
        return jsonify({"success": True, "message": "Question deleted"})
    
    return jsonify({"error": "Invalid action"}), 400

# ==================== NEW QUIZ MANAGEMENT ROUTES ====================

@app.route('/admin/quizzes')
def admin_quizzes():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    quizzes = list(quizzes_collection.find({}).sort('created_at', -1))
    return render_template('admin_quizzes.html', quizzes=quizzes)

# Add this route for listing quizzes
@app.route('/admin/quizzes/list')
def list_quizzes():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    quizzes = list(quizzes_collection.find({}))
    # Convert ObjectId to string for JSON serialization
    for quiz in quizzes:
        quiz['_id'] = str(quiz['_id'])
    
    return jsonify({"quizzes": quizzes})

@app.route('/admin/quizzes/create', methods=['POST'])
def admin_create_quiz():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['quiz_title', 'school', 'department', 'course', 'semester', 'duration', 'pass_percentage']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        quiz_id = str(uuid.uuid4())
        quiz = {
            "quiz_id": quiz_id,
            "title": data['quiz_title'],
            "school": data['school'],
            "department": data['department'],
            "course": data['course'],
            "semester": data['semester'],
            "duration": int(data['duration'])*60,
            "pass_percentage": int(data['pass_percentage']),
            "status": "draft",
            "created_at": datetime.now(),
            "questions": [],
            "participants": ["all"]  # Default to all students
        }
        
        quizzes_collection.insert_one(quiz)
        
        return jsonify({"success": True, "message": "Quiz created successfully", "quiz_id": quiz_id})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/quizzes/manage/<quiz_id>')
def manage_quiz(quiz_id):
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
    if not quiz:
        return redirect(url_for('admin_quizzes'))
    
    # Convert ObjectId to string for JSON serialization
    if '_id' in quiz:
        quiz['_id'] = str(quiz['_id'])
    
    # Get all questions from question bank for selection
    questions = list(question_bank_collection.find({}))
    
    # Clean up questions and convert ObjectId to string
    for question in questions:
        if '_id' in question:
            question['_id'] = str(question['_id'])
        if 'text' not in question or not question['text']:
            question['text'] = 'No question text available'
        if 'tags' not in question:
            question['tags'] = []
        if 'difficulty' not in question:
            question['difficulty'] = 'Not set'
    
    # Get students based on course/semester filter
    course_filter = quiz.get('course', 'all')
    semester_filter = quiz.get('semester', 'all')
    
    query = {}
    if course_filter != 'all':
        query['course'] = course_filter
    if semester_filter != 'all':
        query['semester'] = semester_filter
    
    students = list(users_collection.find(query, {'_id': 0, 'scholar_id': 1, 'name': 1, 'course': 1, 'semester': 1}))
    
    return render_template('admin_manage_quiz.html', 
                         quiz=quiz, 
                         questions=questions, 
                         students=students,
                         tags=QUESTION_TAGS)

@app.route('/api/quizzes/<quiz_id>', methods=['DELETE'])
def delete_quiz(quiz_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        # FIXED: Use the correct collection name (quizzes_collection instead of quiz_collection)
        result = quizzes_collection.delete_one({"quiz_id": quiz_id})
        if result.deleted_count > 0:
            # Also delete any participants for this quiz
            quiz_participants_collection.delete_many({"quiz_id": quiz_id})
            return jsonify({"success": True, "message": "Quiz deleted successfully"})
        else:
            return jsonify({"error": "Quiz not found"}), 404
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/quizzes/<quiz_id>/questions', methods=['POST'])
def add_questions_to_quiz(quiz_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.json
        question_ids = data.get('question_ids', [])
        
        # Update the quiz with the selected questions
        quizzes_collection.update_one(
            {"quiz_id": quiz_id},
            {"$addToSet": {"questions": {"$each": question_ids}}}
        )
        
        return jsonify({"success": True, "message": f"Added {len(question_ids)} questions to quiz"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/quizzes/<quiz_id>/participants', methods=['POST'])
def add_participants_to_quiz(quiz_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.json
        scholar_ids = data.get('scholar_ids', [])
        
        # Update the quiz with the selected participants
        quizzes_collection.update_one(
            {"quiz_id": quiz_id},
            {"$addToSet": {"participants": {"$each": scholar_ids}}}
        )
        
        # Also add to quiz_participants collection
        for scholar_id in scholar_ids:
            quiz_participants_collection.update_one(
                {"quiz_id": quiz_id, "scholar_id": scholar_id},
                {"$setOnInsert": {
                    "quiz_id": quiz_id,
                    "scholar_id": scholar_id,
                    "added_at": datetime.now()
                }},
                upsert=True
            )
        
        return jsonify({"success": True, "message": f"Added {len(scholar_ids)} participants to quiz"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/quizzes/<quiz_id>/status', methods=['POST'])
def update_quiz_status(quiz_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.json
        action = data.get('action')
        
        if action == 'start':
            # Get quiz details first
            quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
            if not quiz:
                return jsonify({"error": "Quiz not found"}), 404
            
            # Activate the quiz
            quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"status": "active", "started_at": datetime.now()}}
            )
            
            # Determine which course/semester to activate questions for
            target_course = quiz['course']
            target_semester = quiz['semester']
            
            # If quiz has "all", we need to activate questions for all relevant courses/semesters
            if target_course == "all" or target_semester == "all":
                # For quizzes with "all", we need a different approach
                # You might want to modify this based on your specific needs
                if target_course == "all" and target_semester == "all":
                    # Activate all questions
                    questions_collection.update_many(
                        {},
                        {"$set": {"active": True, "activated_at": datetime.now()}}
                    )
                elif target_course == "all":
                    # Activate all questions for this semester
                    questions_collection.update_many(
                        {"semester": target_semester},
                        {"$set": {"active": True, "activated_at": datetime.now()}}
                    )
                elif target_semester == "all":
                    # Activate all questions for this course
                    questions_collection.update_many(
                        {"course": target_course},
                        {"$set": {"active": True, "activated_at": datetime.now()}}
                    )
            else:
                # Specific course and semester - activate those questions
                questions_collection.update_many(
                    {
                        "course": target_course,
                        "semester": target_semester
                    },
                    {"$set": {"active": True, "activated_at": datetime.now()}}
                )
            
            # Notify students
            if quiz.get('participants') and 'all' in quiz.get('participants', []):
                # Notify all students in the relevant course/semester
                if target_course == "all" and target_semester == "all":
                    students = users_collection.find({})
                elif target_course == "all":
                    students = users_collection.find({"semester": target_semester})
                elif target_semester == "all":
                    students = users_collection.find({"course": target_course})
                else:
                    students = users_collection.find({
                        "course": target_course,
                        "semester": target_semester
                    })
            else:
                # Notify only specific participants
                students = users_collection.find({
                    "scholar_id": {"$in": quiz.get('participants', [])}
                })
            
            for student in students:
                create_notification(
                    student['scholar_id'],
                    "Quiz Started",
                    f"A new quiz for {quiz['title']} has started. You can now take the quiz.",
                    "info"
                )
            
            return jsonify({"success": True, "message": "Quiz started successfully"})
        
        elif action == 'stop':
            # Get quiz details first
            quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
            if not quiz:
                return jsonify({"error": "Quiz not found"}), 404
            
            # Deactivate the quiz
            quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"status": "inactive", "ended_at": datetime.now()}}
            )
            
            # Determine which course/semester to deactivate questions for
            target_course = quiz['course']
            target_semester = quiz['semester']
            
            # Deactivate questions based on quiz scope
            if target_course == "all" or target_semester == "all":
                if target_course == "all" and target_semester == "all":
                    # Deactivate all questions
                    questions_collection.update_many(
                        {},
                        {"$set": {"active": False}}
                    )
                elif target_course == "all":
                    # Deactivate all questions for this semester
                    questions_collection.update_many(
                        {"semester": target_semester},
                        {"$set": {"active": False}}
                    )
                elif target_semester == "all":
                    # Deactivate all questions for this course
                    questions_collection.update_many(
                        {"course": target_course},
                        {"$set": {"active": False}}
                    )
            else:
                # Specific course and semester - deactivate those questions
                questions_collection.update_many(
                    {
                        "course": target_course,
                        "semester": target_semester
                    },
                    {"$set": {"active": False}}
                )
            
            return jsonify({"success": True, "message": "Quiz stopped successfully"})
        
        else:
            return jsonify({"error": "Invalid action"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/admin/leaderboard')
def admin_leaderboard():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    course = request.args.get('course', '')
    semester = request.args.get('semester', '')
    quiz_id = request.args.get('quiz_id', '')
    limit = int(request.args.get('limit', 10))
    
    pipeline = [
        {"$match": {"published": True}},
        {"$sort": {"score": -1, "completion_time": 1, "timestamp": 1}},
        {"$group": {
            "_id": "$scholar_id",
            "max_score": {"$max": "$score"},
            "total_questions": {"$first": "$total"},
            "user_name": {"$first": "$user_name"},
            "course": {"$first": "$course"},
            "semester": {"$first": "$semester"},
            "timestamp": {"$max": "$timestamp"},
            "completion_time": {"$min": "$completion_time"}
        }},
        {"$sort": {"max_score": -1, "completion_time": 1}},
        {"$limit": limit},
        {"$project": {
            "scholar_id": "$_id",
            "user_name": 1,
            "score": "$max_score",
            "total": "$total_questions",
            "course": 1,
            "semester": 1,
            "percentage": {"$multiply": [{"$divide": ["$max_score", "$total_questions"]}, 100]},
            "timestamp": 1,
            "completion_time": 1
        }}
    ]
    
    match_stage = pipeline[0]["$match"]
    if course and course != 'all':
        match_stage["course"] = course
    if semester and semester != 'all':
        match_stage["semester"] = semester
    if quiz_id:
        match_stage["quiz_id"] = quiz_id
    
    leaderboard = list(results_collection.aggregate(pipeline))
    
    for item in leaderboard:
        if 'timestamp' in item and isinstance(item['timestamp'], datetime):
            item['formatted_date'] = item['timestamp'].strftime('%d/%m/%y')
    
    quizzes = list(quizzes_collection.find({}, {'quiz_id': 1, 'name': 1}))
    
    return render_template('admin_leaderboard.html',
                         leaderboard=leaderboard,
                         courses=['MCA-DS', 'BSC IT', 'BCA', 'all'],
                         semesters=['1', '2', '3', '4', '5', '6', 'all'],
                         quizzes=quizzes,
                         selected_course=course,
                         selected_semester=semester,
                         selected_quiz=quiz_id)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000, help='Port to run the app on')
    args = parser.parse_args()
    app.run(host='0.0.0.0', port=args.port, debug=True)