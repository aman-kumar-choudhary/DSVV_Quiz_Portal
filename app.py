from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort, send_file,flash
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
questions_collection = db.questions
users_collection = db.users
results_collection = db.results
user_sessions_collection = db.user_sessions
quiz_settings_collection = db.quiz_settings
feedback_collection = db.feedback
notifications_collection = db.notifications

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Admin credentials
ADMIN_CREDENTIALS = {"username": "admin.computer", "password": bcrypt.generate_password_hash("admin123").decode('utf-8')}


# Create indexes for better performance
def create_indexes():
    users_collection.create_index("scholar_id", unique=True)
    users_collection.create_index("email", unique=True)
    questions_collection.create_index([("course", 1), ("semester", 1)])
    questions_collection.create_index("question_id", unique=True)
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


def cleanup_duplicate_emails():
    # Find duplicate emails
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
        # Keep the first document, remove others
        keep_id = dup["ids"][0]
        remove_ids = dup["ids"][1:]
        
        # Remove duplicates
        users_collection.delete_many({"_id": {"$in": remove_ids}})
        print(f"Removed {len(remove_ids)} duplicates for email: {dup['_id']}")

cleanup_duplicate_emails()
create_indexes()

def add_blocked_field():
    users_collection.update_many(
        {"blocked": {"$exists": False}},
        {"$set": {"blocked": False}}
    )

add_blocked_field()  # Call this to initialize

# Add notification functions
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

def get_notifications(scholar_id, limit=10):
    notifications = list(notifications_collection.find(
        {"scholar_id": scholar_id}
    ).sort("timestamp", -1).limit(limit))
    
    # Convert ObjectId to string for JSON serialization
    for notification in notifications:
        notification['_id'] = str(notification['_id'])
        if 'timestamp' in notification and isinstance(notification['timestamp'], datetime):
            notification['timestamp'] = notification['timestamp'].isoformat()
    
    return notifications

def get_user_stats(scholar_id):
    """Get user statistics including quiz attempts, average score, and highest score"""
    # Get quiz attempts count
    quiz_attempts = results_collection.count_documents({"scholar_id": scholar_id, "published": True})
    
    # Get average score
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
    """Add created_at field to existing users"""
    users_collection.update_many(
        {"created_at": {"$exists": False}},
        {"$set": {"created_at": datetime.now()}}
    )
    print("Added created_at field to users")

# Call this function once
add_created_at_to_users()

@app.route('/')
def index():
    is_logged_in = bool(session.get('scholar_id') or session.get('username'))
    user = None
    if is_logged_in and session.get('role') == 'student':
        user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
        if user:
            # Add user statistics
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
        return render_template('login.html', error="Invalid student credentials")
    return render_template('login.html')


# Add API endpoint for notifications
@app.route('/api/notifications')
def api_notifications():
    if 'scholar_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    notifications = get_notifications(session['scholar_id'])
    return jsonify({"notifications": notifications})

# Add API endpoint for marking notifications as read
@app.route('/api/notifications/read', methods=['POST'])
def mark_notifications_read():
    if 'scholar_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    notifications_collection.update_many(
        {"scholar_id": session['scholar_id'], "read": False},
        {"$set": {"read": True}}
    )
    return jsonify({"success": True})

# Add API endpoint for daily leaderboard
@app.route('/api/daily_leaderboard')
def daily_leaderboard():
    try:
        # Get distinct dates from results
        distinct_dates = results_collection.distinct("timestamp", {"published": True})
        distinct_dates.sort(reverse=True)
        
        date_data = []
        for date in distinct_dates[:8]:  # Last 7 days + today
            date_start = datetime(date.year, date.month, date.day)
            date_end = date_start + timedelta(days=1)
            
            pipeline = [
                {"$match": {
                    "timestamp": {"$gte": date_start, "$lt": date_end},
                    "published": True
                }},
                {"$sort": {"score": -1, "completion_time": 1}},
                {"$limit": 10},
                {"$lookup": {
                    "from": "users",
                    "localField": "scholar_id",
                    "foreignField": "scholar_id",
                    "as": "user_info"
                }},
                {"$unwind": "$user_info"},
                {"$project": {
                    "user_name": "$user_info.name",
                    "score": 1,
                    "total": 1,
                    "percentage": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}
                }}
            ]
            
            leaders = list(results_collection.aggregate(pipeline))
            
            # Convert ObjectId to string for JSON serialization
            for leader in leaders:
                if '_id' in leader:
                    leader['_id'] = str(leader['_id'])
            
            date_data.append({
                "date": date_start.isoformat(),
                "leaders": leaders
            })
        
        return jsonify({"dates": date_data})
    except Exception as e:
        print(f"Error in daily_leaderboard: {str(e)}")
        return jsonify({"error": "Failed to load leaderboard data"}), 500


# Add API endpoint for course-specific leaderboard
@app.route('/api/course_leaderboard/<course>/<semester>')
def course_leaderboard(course, semester):
    try:
        # Get distinct dates from results for this course/semester
        distinct_dates = results_collection.distinct("timestamp", {
            "published": True,
            "course": course,
            "semester": semester
        })
        distinct_dates.sort(reverse=True)
        
        date_data = []
        for date in distinct_dates[:8]:  # Last 7 days + today
            date_start = datetime(date.year, date.month, date.day)
            date_end = date_start + timedelta(days=1)
            
            pipeline = [
                {"$match": {
                    "timestamp": {"$gte": date_start, "$lt": date_end},
                    "published": True,
                    "course": course,
                    "semester": semester
                }},
                {"$sort": {"score": -1, "completion_time": 1}},
                {"$limit": 5},
                {"$lookup": {
                    "from": "users",
                    "localField": "scholar_id",
                    "foreignField": "scholar_id",
                    "as": "user_info"
                }},
                {"$unwind": "$user_info"},
                {"$project": {
                    "user_name": "$user_info.name",
                    "score": 1,
                    "total": 1,
                    "percentage": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}
                }}
            ]
            
            leaders = list(results_collection.aggregate(pipeline))
            
            # Convert ObjectId to string for JSON serialization
            for leader in leaders:
                if '_id' in leader:
                    leader['_id'] = str(leader['_id'])
            
            date_data.append({
                "date": date_start.isoformat(),
                "leaders": leaders
            })
        
        return jsonify({"dates": date_data})
    except Exception as e:
        print(f"Error in course_leaderboard: {str(e)}")
        return jsonify({"error": "Failed to load leaderboard data"}), 500


@app.route('/admin-login',methods=['GET','POST'])
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

        return render_template('admin_login.html',error='Invalid admin credentials')

    return render_template('admin_login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            scholar_id = request.form.get('scholar_id', '').strip()
            name = request.form.get('name', '').strip()
            course = request.form.get('course', '')
            semester = request.form.get('semester', '')
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            retype_password = request.form.get('retype-password', '')
            
            # Basic validation - check if required fields are present
            required_fields = {
                'scholar_id': scholar_id,
                'name': name,
                'course': course,
                'semester': semester,
                'email': email,
                'password': password
            }
            
            missing_fields = [field for field, value in required_fields.items() if not value]
            
            if missing_fields:
                return render_template('signup.html', 
                                    error=f"Missing required fields: {', '.join(missing_fields)}")
            
            if password != retype_password:
                return render_template('signup.html', error="Passwords do not match")
            
            if users_collection.find_one({"scholar_id": scholar_id}):
                return render_template('signup.html', error="Scholar ID already exists")
            
            if users_collection.find_one({"email": email}):
                return render_template('signup.html', error="Email already registered")
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users_collection.insert_one({
                "scholar_id": scholar_id,
                "name": name,
                "course": course,
                "semester": semester,
                "email": email,
                "password": hashed_password
            })
            
            session['role'] = 'student'
            session['scholar_id'] = scholar_id
            session['workspace'] = str(uuid.uuid4())
            user_sessions_collection.insert_one({
                "scholar_id": scholar_id,
                "workspace_id": session['workspace'],
                "start_time": datetime.now()
            })
            
            return redirect(url_for('student_dashboard'))
        
        except Exception as e:
            print(f"Error in signup: {str(e)}")
            return render_template('signup.html', 
                                error="An error occurred during registration. Please try again.")
    
    return render_template('signup.html')



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

@app.route('/api/submit_answer', methods=['POST'])
def submit_answer():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    answer_data = request.json
    answer = answer_data.get('answer')
    question_index = answer_data.get('question_index')
    
    if answer is None or question_index is None:
        return jsonify({"error": "No answer or question index provided"}), 400
    
    # Initialize answers dictionary if it doesn't exist
    if 'answers' not in session:
        session['answers'] = {}
    
    # Store the answer with string key
    session['answers'][str(question_index)] = answer
    session.modified = True  # Force session save
    
    print(f"Stored answer for question {question_index}: {answer}")
    
    # Get the current question
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

@app.route('/api/next_question', methods=['POST'])
def next_question():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    session['current_question'] += 1
    current_index = session['current_question']
    questions = session['questions']
    
    if current_index >= len(questions):
        # Calculate score
        score = sum(1 for i, q in enumerate(questions) 
                  if session['answers'].get(str(i)) == q['correct_answer'])
        
        # Save results
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
        
        # Calculate score
        questions = session['questions']
        answers = session.get('answers', {})
        
        score = 0
        for i, question in enumerate(questions):
            answer_key = str(i)
            if answer_key in answers and answers[answer_key] == question['correct_answer']:
                score += 1
        
        # Get user info
        user = users_collection.find_one({'scholar_id': session['scholar_id']})
        user_name = user['name'] if user else 'Unknown'
        
        # Calculate completion time
        quiz_start = datetime.fromisoformat(session['quiz_start_time'])
        completion_time = (datetime.now() - quiz_start).total_seconds()
        
        # Prepare quiz result data
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
            "completion_time": completion_time
        }
        
        # Check if result already exists for this workspace
        existing_result = results_collection.find_one({"workspace_id": session.get('workspace')})
        
        if existing_result:
            # Update existing result
            results_collection.update_one(
                {"workspace_id": session.get('workspace')},
                {"$set": quiz_data}
            )
        else:
            # Save new results
            results_collection.insert_one(quiz_data)
        
        # Clear session quiz data
        session_keys = ['questions', 'answers', 'current_question', 'quiz_start_time', 'course', 'semester', 'quiz_duration']
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
        # Even if there's an error, try to redirect to feedback
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



# Add API endpoint for quiz stats
@app.route('/api/quiz_stats')
def quiz_stats():
    # Count active quizzes (questions with active=True)
    active_quizzes = questions_collection.distinct("course", {"active": True})
    
    # Count quizzes completed today
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    completed_today = results_collection.count_documents({
        "timestamp": {"$gte": today_start},
        "published": True
    })
    
    # Get active quizzes details
    active_quizzes_list = []
    for course in active_quizzes:
        # Find when the quiz was activated (approximation)
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
    
    if not course:
        return jsonify({"error": "Course is required"}), 400
    
    # Deactivate questions for this course
    result = questions_collection.update_many(
        {"course": course, "semester": semester},
        {"$set": {"active": False}}
    )
    
    return jsonify({
        "success": True,
        "message": f"Quiz ended for {course} - Semester {semester}",
        "modified_count": result.modified_count
    })

# Update the feedback route to flash a message
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    
    if request.method == 'POST':
        rating = request.form.get('rating')
        feedback_text = request.form.get('feedback_text', '').strip()
        
        if not rating:
            return render_template('feedback.html', 
                                user=user,
                                error="Please provide a rating")
        
        # Save feedback to database
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
        
        # Clear any remaining quiz session data
        session_keys = ['questions', 'answers', 'current_question', 'quiz_start_time', 'course', 'semester', 'quiz_duration']
        for key in session_keys:
            session.pop(key, None)
        
        # Flash success message and redirect to home
        flash('Thank you for your feedback! Your quiz experience has been recorded.', 'success')
        return redirect(url_for('index'))
    
    return render_template('feedback.html', user=user)

# Add API endpoint for user profile update
@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    if 'scholar_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    name = request.json.get('name')
    email = request.json.get('email')
    
    if not name:
        return jsonify({"error": "Name is required"}), 400
    
    # Check if email is already taken by another user
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
        
        # Check if email exists in database
        user = users_collection.find_one({"email": email})
        if not user:
            return render_template('forgot_password.html', 
                                error="No account found with that email address")
        
        # Generate a reset token
        reset_token = str(uuid.uuid4())
        
        # Store the token with expiration (24 hours)
        db.password_resets.insert_one({
            "email": email,
            "token": reset_token,
            "expires_at": datetime.now() + timedelta(hours=24),
            "used": False
        })
        
        # In a production app, you would send an email here with the reset link
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        
        return render_template('forgot_password.html', 
                            message=f"Password reset link has been sent to {email}. For demo purposes: {reset_link}")
    
    return render_template('/forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify the token
    reset_record = db.password_resets.find_one({
        "token": token,
        "expires_at": {"$gt": datetime.now()},
        "used": False
    })
    
    if not reset_record:
        return render_template('reset_password.html', error="Invalid or expired token")
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            return render_template('reset_password.html', 
                                error="Passwords do not match",
                                token=token)
        
        # Update user's password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        users_collection.update_one(
            {"email": reset_record['email']},
            {"$set": {"password": hashed_password}}
        )
        
        # Mark token as used
        db.password_resets.update_one(
            {"_id": reset_record['_id']},
            {"$set": {"used": True}}
        )
        
        return render_template('reset_password.html', 
                            success="Password updated successfully. You can now login with your new password.")
    
    return render_template('reset_password.html', token=token)

@app.route('/view_score')
def view_score():
    if 'scholar_id' not in session and 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') == 'student':
        user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
        
        # Get only published results for this student
        results = list(results_collection.find(
            {"scholar_id": session['scholar_id'], "published": True},
            {'_id': 0}
        ).sort('timestamp', -1))
        
        # Get the latest published result
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
    query = {}
    results = list(results_collection.find(query, {'_id': 0}).sort('timestamp', -1))
    
    # Get leaderboard data (top 10 students across all courses)
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
    
    # Convert ObjectId to string for JSON serialization
    for item in leaderboard:
        if '_id' in item:
            item['_id'] = str(item['_id'])
    
    stats = {
        'total_students': users_collection.count_documents({}),
        'total_questions': questions_collection.count_documents({}),
        'total_quizzes': results_collection.count_documents({}),
        'courses': ['MCA-DS', 'BSC IT', 'BCA'],
        'semesters': ['1', '2', '3', '4', '5', '6'],
        'leaderboard': leaderboard,
        'average_score': results_collection.aggregate([
            {"$match": query},
            {"$group": {"_id": None, "avg_score": {"$avg": "$score"}}}
        ]).next().get('avg_score', 0) if results_collection.count_documents(query) > 0 else 0
    }
    
    return render_template('admin.html', stats=stats, results=results)

@app.route('/admin/upload_questions', methods=['POST'])
def admin_upload_questions():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    if 'json_file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['json_file']
    course = request.form.get('course')
    semester = request.form.get('semester')
    
    if not course or not semester:
        return jsonify({"error": "Course and semester are required"}), 400
    
    if file.filename.endswith('.json'):
        try:
            data = json.load(file)
            for question in data:
                if 'question_id' not in question:
                    question['question_id'] = str(uuid.uuid4())
                question['course'] = course
                question['semester'] = semester
                question['active'] = False
                if 'created_at' not in question:
                    question['created_at'] = datetime.utcnow()
                questions_collection.update_one(
                    {"question_id": question['question_id']},
                    {"$set": question},
                    upsert=True
                )
            return jsonify({"success": True, "message": f"{len(data)} questions uploaded successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    return jsonify({"error": "Invalid file format"}), 400



@app.route('/admin/questions', methods=['GET', 'POST'])
def admin_questions():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Handle question deletion
        if 'delete_question_id' in request.form:
            question_id = request.form['delete_question_id']
            questions_collection.delete_one({"question_id": question_id})
            return jsonify({"success": True, "message": "Question deleted successfully"})
        
        # Check if this is an edit operation
        is_edit = request.form.get('is_edit') == 'true'
        question_id = request.form.get('question_id')
        
        # Handle question addition/editing
        question_text = request.form.get('question_text')
        options = [
            request.form.get('option1'),
            request.form.get('option2'),
            request.form.get('option3'),
            request.form.get('option4')
        ]
        correct_answer = request.form.get('correct_answer')
        course = request.form.get('course')
        semester = request.form.get('semester')
        
        # Validate inputs
        if not all([question_text, options[0], options[1], options[2], options[3], correct_answer, course, semester]):
            return jsonify({"error": "All fields are required"}), 400
        
        if correct_answer not in options:
            return jsonify({"error": "Correct answer must be one of the options"}), 400
        
        # Handle image upload
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + '_' + filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                image_path = unique_filename
        
        # Create question data
        question_data = {
            "text": question_text,
            "options": options,
            "correct_answer": correct_answer,
            "course": course,
            "semester": semester,
            "active": True,
            "updated_at": datetime.now()
        }
        
        # Add created_at for new questions
        if not is_edit:
            question_data["created_at"] = datetime.now()
        
        if image_path:
            question_data["image_path"] = image_path
        
        # Update or insert question
        if is_edit and question_id:
            questions_collection.update_one(
                {"question_id": question_id},
                {"$set": question_data}
            )
            return jsonify({"success": True, "message": "Question updated successfully"})
        else:
            question_data["question_id"] = str(uuid.uuid4())
            questions_collection.insert_one(question_data)
            return jsonify({"success": True, "message": "Question added successfully"})
    
    # Filter questions (GET request handling remains the same)
    course = request.args.get('course', '')
    semester = request.args.get('semester', '')
    query = {}
    if course and course != 'All':
        query['course'] = course
    if semester and semester != 'All':
        query['semester'] = semester
    
    questions = list(questions_collection.find(query, {'_id': 0}).sort('created_at', -1))
    return render_template('admin_questions.html', questions=questions, selected_course=course, selected_semester=semester)

@app.route('/admin/results')
def admin_results():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    # Get filter parameters
    course_filter = request.args.get('course', '')
    semester_filter = request.args.get('semester', '')
    
    # Build query based on filters
    query = {}
    if course_filter and course_filter != 'All':
        query['course'] = course_filter
    if semester_filter and semester_filter != 'All':
        query['semester'] = semester_filter
    
    # Get filtered results
    results = list(results_collection.find(query, {'_id': 0}).sort('timestamp', -1))
    
    # Fetch user names for results
    for result in results:
        user = users_collection.find_one({'scholar_id': result['scholar_id']}, {'_id': 0, 'name': 1})
        result['user_name'] = user['name'] if user else 'Unknown'
    
    # Get top 5 students by filter (only published results)
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
    
    # Add user statistics
    user_stats = get_user_stats(session['scholar_id'])
    user.update(user_stats)
    
    if user.get('blocked', False):
        return render_template('student_dashboard.html', 
                               error="You have been blocked from participating in quizzes. Contact admin.", 
                               user=user)
    
    if request.method == 'POST':
        try:
            course = request.form['course'].strip()
            semester = request.form['semester'].strip()
            
            # Validate course/semester match
            if user['course'].strip() != course or user['semester'].strip() != semester:
                return render_template('student_dashboard.html', 
                                    error="Please select your registered course and semester", 
                                    user=user)
            
            # Store course and semester in session
            session['course'] = course
            session['semester'] = semester
            
            # Get quiz duration from settings
            quiz_settings = quiz_settings_collection.find_one({
                "course": course,
                "semester": semester
            })
            
            duration = 600  # Default 10 minutes
            if quiz_settings and 'duration' in quiz_settings:
                duration = quiz_settings['duration']
            
            # Query active questions
            questions = list(questions_collection.find({
                "course": course,
                "semester": semester,
                "active": True
            }, {'_id': 0}))
            
            if not questions:
                return render_template('student_dashboard.html', 
                                    error="No active questions available. Please contact your instructor.", 
                                    user=user)
            
            # Store quiz info in session for the instructions page
            session['quiz_duration'] = duration
            session['total_questions'] = len(questions)
            
            # Redirect to instructions page
            return redirect(url_for('instructions'))
            
        except Exception as e:
            return render_template('student_dashboard.html', 
                                error="An error occurred. Please try again.", 
                                user=user)
    
    return render_template('student_dashboard.html', user=user)

@app.route('/instructions')
def instructions():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Add user statistics
    user_stats = get_user_stats(session['scholar_id'])
    user.update(user_stats)
    
    # Check if course and semester are set
    if 'course' not in session or 'semester' not in session:
        return redirect(url_for('student_dashboard'))
    
    return render_template('instructions.html', user=user)

@app.route('/start_quiz', methods=['POST'])
def start_quiz():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    # Check if course and semester are set
    if 'course' not in session or 'semester' not in session:
        return jsonify({"error": "Course and semester not selected"}), 400
    
    course = session['course']
    semester = session['semester']
    
    try:
        # Query active questions
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
        
        # Get quiz duration from settings
        quiz_settings = quiz_settings_collection.find_one({
            "course": course,
            "semester": semester
        })
        
        duration = 600  # Default 10 minutes
        if quiz_settings and 'duration' in quiz_settings:
            duration = quiz_settings['duration']
        
        session['quiz_duration'] = duration
        
        return jsonify({"success": True, "redirect": url_for('quiz')})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/set_quiz_time', methods=['POST'])
def set_quiz_time():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    course = request.json.get('course')
    semester = request.json.get('semester')
    duration = request.json.get('duration')
    
    if not all([course, semester, duration]):
        return jsonify({"error": "Course, semester, and duration are required"}), 400
    
    # Convert duration to seconds
    duration_seconds = int(duration) * 60
    
    # Update or insert quiz settings
    quiz_settings_collection.update_one(
        {"course": course, "semester": semester},
        {"$set": {"duration": duration_seconds}},
        upsert=True
    )
    
    return jsonify({"success": True, "message": f"Quiz duration set to {duration} minutes for {course} Semester {semester}"})

@app.route('/publish_results', methods=['POST'])
def publish_results():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    workspace_id = request.json.get('workspace_id')
    if not workspace_id:
        return jsonify({"error": "Workspace ID is required"}), 400
    
    # Update all results with this workspace_id
    result = results_collection.update_many(
        {"workspace_id": workspace_id},
        {"$set": {"published": True}}
    )
    
    if result.modified_count > 0:
        return jsonify({"success": True, "message": f"Results for workspace {workspace_id} published successfully"})
    
    return jsonify({"error": "Result not found"}), 404

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
    
    # Clear quiz-related session data
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
        # Remove user session from database
        user_sessions_collection.delete_one({"workspace_id": session.get('workspace')})
    
    # Clear all session data
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

# New route for User Management page
@app.route('/admin/users')
def admin_users():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    # Get filter parameters
    course_filter = request.args.get('course', '')
    semester_filter = request.args.get('semester', '')
    
    query = {}
    if course_filter and course_filter != 'All':
        query['course'] = course_filter
    if semester_filter and semester_filter != 'All':
        query['semester'] = semester_filter
    
    # Get filtered students (exclude _id and password for security)
    students = list(users_collection.find(query, {'_id': 0, 'password': 0}).sort('scholar_id', 1))
    
    stats = {
        'total_students': users_collection.count_documents(query),
    }
    
    return render_template('admin_users.html', 
                           students=students, 
                           stats=stats, 
                           selected_course=course_filter, 
                           selected_semester=semester_filter)

# API to edit user details
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
    
    # Remove None values
    updates = {k: v for k, v in updates.items() if v is not None}
    
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    result = users_collection.update_one({"scholar_id": scholar_id}, {"$set": updates})
    
    if result.modified_count > 0:
        return jsonify({"success": True, "message": "User updated successfully"})
    return jsonify({"error": "No changes made or user not found"}), 404

# API to delete user
@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    scholar_id = request.json.get('scholar_id')
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    # Cascade delete
    users_collection.delete_one({"scholar_id": scholar_id})
    results_collection.delete_many({"scholar_id": scholar_id})
    feedback_collection.delete_many({"scholar_id": scholar_id})
    notifications_collection.delete_many({"scholar_id": scholar_id})
    user_sessions_collection.delete_many({"scholar_id": scholar_id})
    
    return jsonify({"success": True, "message": "User and related data deleted successfully"})

# API to block/unblock user
@app.route('/api/block_user', methods=['POST'])
def block_user():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    scholar_id = data.get('scholar_id')
    block = data.get('block', True)  # True to block, False to unblock
    
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    users_collection.update_one({"scholar_id": scholar_id}, {"$set": {"blocked": block}})
    
    if block:
        create_notification(scholar_id, "Account Blocked", "You have been blocked from participating in quizzes. Contact the admin for more details.", "warning")
    
    return jsonify({"success": True, "message": f"User {'blocked' if block else 'unblocked'} successfully"})

# API to get user results (for viewing marks)
@app.route('/api/user_results/<scholar_id>')
def user_results(scholar_id):
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    results = list(results_collection.find({"scholar_id": scholar_id}, {'_id': 0}).sort('timestamp', -1))
    return jsonify({"results": results})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)