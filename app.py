from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from flask_bcrypt import Bcrypt
import uuid
import json
from datetime import datetime, timedelta
import pandas as pd
from io import BytesIO
from flask import send_file
import random

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Ensure this is set; use a fixed key in production
bcrypt = Bcrypt(app)

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

# Admin credentials
ADMIN_CREDENTIALS = {"username": "admin.computer", "password": bcrypt.generate_password_hash("admin123").decode('utf-8')}

@app.route('/')
def index():
    is_logged_in = bool(session.get('scholar_id') or session.get('username'))
    user = None
    if is_logged_in and session.get('role') == 'student':
        user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    return render_template('index.html', is_logged_in=is_logged_in, user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        identifier = request.form['identifier']
        password = request.form['password']
        
        if role == 'admin':
            if identifier == ADMIN_CREDENTIALS["username"] and bcrypt.check_password_hash(ADMIN_CREDENTIALS["password"], password):
                session['role'] = 'admin'
                session['username'] = identifier
                return redirect(url_for('admin'))
            return render_template('login.html', error="Invalid admin credentials")
        else:
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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        scholar_id = request.form['scholar_id']
        name = request.form['name']
        course = request.form['course']
        semester = request.form['semester']
        email = request.form['email']
        password = request.form['password']
        if users_collection.find_one({"scholar_id": scholar_id}):
            return render_template('signup.html', error="Scholar ID exists")
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
    return render_template('signup.html')

@app.route('/student_dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    if not user:
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            course = request.form['course'].strip()
            semester = request.form['semester'].strip()
            
            # Validate course/semester match (use original values)
            if user['course'].strip() != course or user['semester'].strip() != semester:
                return render_template('student_dashboard.html', 
                                    error="Please select your registered course and semester", 
                                    user=user)
            
            # Query active questions (use original semester value)
            questions = list(questions_collection.find({
                "course": course,
                "semester": semester,
                "active": True
            }, {'_id': 0}))
            
            if not questions:
                app.logger.warning(f"No active questions found for {course} - Semester {semester}")
                return render_template('student_dashboard.html', 
                                    error="No active questions available. Please contact your instructor.", 
                                    user=user)
            
            random.shuffle(questions)
            session['questions'] = questions
            session['current_question'] = 0
            session['answers'] = {}
            session['quiz_start_time'] = datetime.now().isoformat()
            return redirect(url_for('quiz'))
            
        except Exception as e:
            app.logger.error(f"Error in student_dashboard: {str(e)}")
            return render_template('student_dashboard.html', 
                                error="An error occurred. Please try again.", 
                                user=user)
    
    return render_template('student_dashboard.html', user=user)




@app.route('/set_timer', methods=['POST'])
def set_timer():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    duration = request.json.get('duration') if request.is_json else request.form.get('duration', 600, type=int)
    session['quiz_duration'] = duration
    return jsonify({"success": True, "message": f"Quiz duration set to {duration} seconds"})

@app.route('/publish_results', methods=['POST'])
def publish_results():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    workspace_id = request.json.get('workspace_id') if request.is_json else request.form.get('workspace_id')
    if not workspace_id:
        return jsonify({"error": "Workspace ID is required"}), 400
    result = results_collection.find_one({"workspace_id": workspace_id})
    if result:
        results_collection.update_one(
            {"workspace_id": workspace_id},
            {"$set": {"published": True}}
        )
        return jsonify({"success": True, "message": f"Results for workspace {workspace_id} published successfully"})
    return jsonify({"error": "Result not found"}), 404




# For students to take the quiz (GET)
@app.route('/quiz')
def quiz():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    if 'questions' not in session:
        return redirect(url_for('student_dashboard'))
    
    return render_template('quiz.html')


@app.route('/admin/start_quiz', methods=['POST'])
def start_quiz():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    course = request.json.get('course')
    semester = request.json.get('semester')
    
    if not course or not semester:
        return jsonify({"error": "Course and semester are required"}), 400
    
    # Activate questions for this course/semester
    result = questions_collection.update_many(
        {"course": course, "semester": semester},
        {"$set": {"active": True}}
    )
    
    return jsonify({
        "success": True,
        "message": f"Quiz started for {course} - Semester {semester}",
        "modified_count": result.modified_count
    })


# API endpoints for quiz interaction
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
    
    answer = request.json.get('answer')
    if not answer:
        return jsonify({"error": "No answer provided"}), 400
    
    current_index = session['current_question']
    session['answers'][str(current_index)] = answer
    session['current_question'] += 1
    
    return jsonify({"success": True})

@app.route('/api/next_question', methods=['POST'])
def next_question():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    current_index = session['current_question']
    questions = session['questions']
    
    if current_index >= len(questions):
        # Calculate score
        score = sum(1 for i, q in enumerate(questions) 
                  if session['answers'].get(str(i)) == q['correct_answer'])
        
        # Save results
        results_collection.insert_one({
            "scholar_id": session['scholar_id'],
            "course": questions[0]['course'],
            "semester": questions[0]['semester'],
            "score": score,
            "total": len(questions),
            "timestamp": datetime.now(),
            "workspace_id": session.get('workspace'),
            "published": False
        })
        
        return jsonify({"finished": True})
    
    return jsonify(questions[current_index])

@app.route('/admin/upload_questions', methods=['POST'])
def upload_questions():
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


@app.route('/admin/questions')
def admin_questions():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    # Same question filtering logic from original admin route
    course = request.args.get('course', '')
    semester = request.args.get('semester', '')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    query = {}
    if course and course != 'All Courses':
        query['course'] = course
    if semester and semester != 'All Semesters':
        query['semester'] = semester
    if from_date:
        query['created_at'] = {'$gte': datetime.strptime(from_date, '%Y-%m-%d')}
    if to_date:
        if 'created_at' not in query:
            query['created_at'] = {}
        query['created_at']['$lte'] = datetime.strptime(to_date, '%Y-%m-%d') + timedelta(days=1) - timedelta(seconds=1)
    
    questions = list(questions_collection.find(query, {'_id': 0}).sort('created_at', -1))
    return render_template('admin_questions.html', questions=questions, selected_course=course, selected_semester=semester)

@app.route('/admin/results')
def admin_results():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    results = list(results_collection.find({}, {'_id': 0}))
    # Fetch user names for results
    for result in results:
        user = users_collection.find_one({'scholar_id': result['scholar_id']}, {'_id': 0, 'name': 1})
        result['user_name'] = user['name'] if user else 'Unknown'
    
    stats = {
        'total_quizzes': results_collection.count_documents({}),
        'total_students': users_collection.count_documents({}),
        'average_score': results_collection.aggregate([
            {"$group": {"_id": None, "avg_score": {"$avg": "$score"}}}
        ]).next().get('avg_score', 0) if results_collection.count_documents({}) > 0 else 0
    }
    
    return render_template('admin_results.html', results=results, stats=stats)

@app.route('/admin')
def admin():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    stats = {
        'total_students': users_collection.count_documents({}),
        'total_questions': questions_collection.count_documents({}),
        'total_quizzes': results_collection.count_documents({}),
        'courses': ['MCA-DS', 'BSC IT', 'BCA'],
        'semesters': ['1', '2', '3', '4', '5', '6']
    }
    
    return render_template('admin.html', stats=stats)

@app.route('/check_time', methods=['GET'])
def check_time():
    if 'scholar_id' not in session or session['role'] != 'student':
        return jsonify({"error": "Unauthorized"}), 401
    
    quiz_start = datetime.fromisoformat(session['quiz_start_time'])
    duration = session.get('quiz_duration', 600)  # Default 10 minutes
    time_elapsed = (datetime.now() - quiz_start).total_seconds()
    
    return jsonify({
        "time_up": time_elapsed >= duration,
        "time_left": max(0, duration - time_elapsed)
    })

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'scholar_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    
    if request.method == 'POST':
        feedback_text = request.form.get('feedback', '').strip()
        
        if not feedback_text:
            return render_template('feedback.html', 
                                user=user,
                                error="Feedback cannot be empty")
        
        # Save feedback to database
        feedback_data = {
            "text": feedback_text,
            "timestamp": datetime.now(),
            "course": session.get('course', ''),
            "semester": session.get('semester', '')
        }
        
        # Update the user's session with feedback
        user_sessions_collection.update_one(
            {"workspace_id": session['workspace']},
            {"$set": {"feedback": feedback_data}}
        )
        
        # Also store feedback in a separate collection for easy access
        db.feedback.insert_one({
            "scholar_id": session['scholar_id'],
            "name": user.get('name', ''),
            "feedback": feedback_data,
            "workspace_id": session['workspace']
        })
        
        return redirect(url_for('index'))
    
    return render_template('feedback.html', user=user)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if email exists in database
        user = users_collection.find_one({"email": email})
        if not user:
            return render_template('forgot_password.html', 
                                error="No account found with that email address")
        
        # Generate a reset token (in a real app, you'd send this via email)
        reset_token = str(uuid.uuid4())
        
        # Store the token with expiration (24 hours)
        db.password_resets.insert_one({
            "email": email,
            "token": reset_token,
            "expires_at": datetime.now() + timedelta(hours=24),
            "used": False
        })
        
        # In a production app, you would send an email here with the reset link
        # For this example, we'll just show a success message
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        
        return render_template('forgot_password.html', 
                            message=f"Password reset link has been sent to {email}. For demo purposes: {reset_link}")
    
    return render_template('forgot_password.html')

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
        # Get all results for this student, sorted by timestamp (newest first)
        results = list(results_collection.find(
            {"scholar_id": session['scholar_id']},
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

@app.route('/export_results', methods=['GET'])
def export_results():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    results = list(results_collection.find({}, {'_id': 0}))
    df = pd.DataFrame(results)
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='quiz_results.csv')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)