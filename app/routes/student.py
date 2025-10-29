from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify
from app.utils.decorators import login_required
from app.utils.helpers import get_user_stats, is_quiz_active, find_active_quiz, check_student_enrollment, create_notification, create_admin_notification, log_activity
from app.models.user_models import users_collection, user_sessions_collection
from app.models.quiz_models import results_collection, quizzes_collection
from app.models.question_models import question_bank_collection, questions_collection
from app.models.feedback_models import feedback_collection
from datetime import datetime
import random
import uuid

student_bp = Blueprint('student', __name__)





@student_bp.route('/student_dashboard', methods=['GET', 'POST'])
@login_required(role='student')
def student_dashboard():
    """Student dashboard"""
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    
    # Check if user is blocked
    if user.get('blocked', False):
        flash("Your account has been blocked. Please contact the administrator.", "error")
        return render_template('student_dashboard.html', user=user)
    
    user_stats = get_user_stats(session['scholar_id'])
    user.update(user_stats)
    
    quiz_active = is_quiz_active(user['course'], user['semester'])
    user['quiz_active'] = quiz_active
    
    if request.method == 'POST':
        try:
            submitted_course = request.form['course'].strip()
            submitted_semester = request.form['semester'].strip()
            
            if user['course'].strip() != submitted_course or str(user['semester']).strip() != submitted_semester:
                flash("Invalid course or semester selection. Please select your registered course and semester.", "error")
                return render_template('student_dashboard.html', user=user)
            
            active_quiz = find_active_quiz(submitted_course, submitted_semester)
            
            if not active_quiz:
                flash("No active quiz for your course and semester at the moment.", "error")
                return render_template('student_dashboard.html', user=user)
            
            # Check if already attempted this quiz
            existing_result = results_collection.find_one({
                "scholar_id": session['scholar_id'],
                "quiz_id": active_quiz['quiz_id']
            })
            
            if existing_result:
                flash("You have already attempted this quiz. You cannot re-attempt.", "error")
                return render_template('student_dashboard.html', user=user)
            
            is_enrolled = check_student_enrollment(
                session['scholar_id'], 
                active_quiz['quiz_id'],
                user['course'],
                user['semester']
            )
            
            if not is_enrolled:
                flash("You are not enrolled in this quiz. Please contact your instructor.", "error")
                return render_template('student_dashboard.html', user=user)
            
            session['quiz_id'] = active_quiz['quiz_id']
            session['course'] = submitted_course
            session['semester'] = submitted_semester
            
            return redirect(url_for('student.instructions'))
            
        except Exception as e:
            print(f"Error in student_dashboard: {str(e)}")
            flash("An error occurred. Please try again.", "error")
            return render_template('student_dashboard.html', user=user)
    
    return render_template('student_dashboard.html', user=user)

@student_bp.route('/instructions')
@login_required(role='student')
def instructions():
    """Quiz instructions page"""
    user = users_collection.find_one({'scholar_id': session['scholar_id']}, {'_id': 0})
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    
    # Check if user is blocked
    if user.get('blocked', False):
        flash("Your account has been blocked. Please contact the administrator.", "error")
        return redirect(url_for('student.student_dashboard'))
    
    # Check if quiz_id is in session (meaning they came from dashboard)
    if 'quiz_id' not in session:
        flash("Please start the quiz from your dashboard.", "error")
        return redirect(url_for('student.student_dashboard'))
    
    # Check if already attempted this quiz
    existing_result = results_collection.find_one({
        "scholar_id": session['scholar_id'],
        "quiz_id": session['quiz_id']
    })
    
    if existing_result:
        flash("You have already attempted this quiz. You cannot re-attempt.", "error")
        return redirect(url_for('student.student_dashboard'))
    
    user_stats = get_user_stats(session['scholar_id'])
    user.update(user_stats)
    
    # Get quiz details from database
    quiz = quizzes_collection.find_one({'quiz_id': session['quiz_id']})
    if not quiz:
        flash("Quiz not found. Please try again.", "error")
        return redirect(url_for('student.student_dashboard'))
    
    # Store quiz info in session for the template
    session['quiz_duration'] = quiz.get('duration', 60)  # Default to 60 minutes if not set
    session['total_questions'] = len(quiz.get('questions', []))
    
    # Also add quiz info to user object for template
    user['quiz'] = quiz
    user['quiz_duration'] = session['quiz_duration']
    user['total_questions'] = session['total_questions']
    
    return render_template('instructions.html', user=user)

@student_bp.route('/quiz')
@login_required(role='student')
def quiz():
    """Quiz page for students"""
    if 'questions' not in session:
        return redirect(url_for('student.student_dashboard'))
    return render_template('quiz.html')

@student_bp.route('/api/get_questions', methods=['GET'])
@login_required(role='student')
def get_questions():
    """Get questions for student quiz"""
    if 'questions' not in session:
        return jsonify({"error": "No questions available"}), 400
    return jsonify(session['questions'])

@student_bp.route('/start_quiz', methods=['POST'])
@login_required(role='student')
def start_quiz():
    """Start quiz for student"""
    if 'course' not in session or 'semester' not in session:
        return jsonify({"error": "Course and semester not selected"}), 400
    
    # Check if user is blocked
    user = users_collection.find_one({'scholar_id': session['scholar_id']})
    if user and user.get('blocked', False):
        return jsonify({"error": "Your account has been blocked. Please contact the administrator."}), 403
    
    course = session['course']
    semester = session['semester']
    
    try:
        # Get the active quiz first
        active_quiz = find_active_quiz(course, semester)
        
        if not active_quiz:
            return jsonify({"error": "No active quiz found"}), 400
        
        # Check if already attempted this quiz
        existing_result = results_collection.find_one({
            "scholar_id": session['scholar_id'],
            "quiz_id": active_quiz['quiz_id']
        })
        
        if existing_result:
            return jsonify({"error": "You have already attempted this quiz. You cannot re-attempt."}), 400
        
        # Get questions from the active quiz's question list
        if active_quiz and 'questions' in active_quiz and active_quiz['questions']:
            # Get questions from the question bank using the IDs stored in the quiz
            question_ids = active_quiz['questions']
            questions = list(question_bank_collection.find({
                "question_id": {"$in": question_ids}
            }, {'_id': 0}))
            
            # Shuffle questions to prevent cheating, but keep options in original order
            random.shuffle(questions)
            
        else:
            # Fallback to old system
            questions = list(questions_collection.find({
                "course": course,
                "semester": semester,
                "active": True
            }, {'_id': 0}))
            random.shuffle(questions)  # Only shuffle questions, not options
        
        if not questions:
            return jsonify({"error": "No active questions available"}), 400
        
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
        
        return jsonify({"success": True, "redirect": url_for('student.quiz')})
        
    except Exception as e:
        print(f"Error in start_quiz: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@student_bp.route('/api/submit_answer', methods=['POST'])
@login_required(role='student')
def submit_answer():
    """Submit answer for current question"""
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

@student_bp.route('/api/next_question', methods=['POST'])
@login_required(role='student')
def next_question():
    """Move to next question"""
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

@student_bp.route('/api/finish_quiz', methods=['POST'])
@login_required(role='student')
def finish_quiz():
    """Finish quiz and calculate results"""
    try:
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
        
        # Check if result already exists (prevent duplicate submissions)
        existing_result = results_collection.find_one({
            "scholar_id": session['scholar_id'],
            "quiz_id": session.get('quiz_id')
        })
        
        if existing_result:
            return jsonify({
                "success": True,
                "score": score,
                "total": len(questions),
                "redirect": url_for('student.feedback'),
                "message": "Quiz already submitted"
            })
        
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
            "redirect": url_for('student.feedback')
        })
        
    except Exception as e:
        print(f"Error in finish_quiz: {str(e)}")
        return jsonify({
            "redirect": url_for('student.feedback'),
            "error": str(e)
        }), 500

@student_bp.route('/check_time', methods=['GET'])
@login_required(role='student')
def check_time():
    """Check remaining quiz time"""
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

@student_bp.route('/feedback', methods=['GET', 'POST'])
@login_required(role='student')
def feedback():
    """Feedback page after quiz"""
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
        return redirect(url_for('auth.index'))
    
    return render_template('feedback.html', user=user)

@student_bp.route('/view_score')
@login_required(role='student')
def view_score():
    """View quiz scores"""
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

@student_bp.route('/api/update_profile', methods=['POST'])
@login_required(role='student')
def update_profile():
    """Update student profile"""
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

@student_bp.route('/api/check_quiz_attempt')
@login_required(role='student')
def check_quiz_attempt():
    """Check if student has already attempted the current quiz"""
    try:
        if 'quiz_id' not in session:
            return jsonify({"attempted": False})
        
        quiz_id = session['quiz_id']
        scholar_id = session['scholar_id']
        
        # Check if result already exists for this quiz
        existing_result = results_collection.find_one({
            "scholar_id": scholar_id,
            "quiz_id": quiz_id
        })
        
        if existing_result:
            return jsonify({"attempted": True})
        
        return jsonify({"attempted": False})
    
    except Exception as e:
        print(f"Error checking quiz attempt: {str(e)}")
        return jsonify({"attempted": False})

@student_bp.route('/api/check_blocked')
@login_required(role='student')
def check_blocked():
    """Check if student is blocked"""
    user = users_collection.find_one({'scholar_id': session['scholar_id']})
    if user and user.get('blocked', False):
        return jsonify({"blocked": True})
    return jsonify({"blocked": False})

@student_bp.route('/api/debug_answers', methods=['GET'])
@login_required(role='student')
def debug_answers():
    """Debug answers for testing"""
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

@student_bp.route('/api/clear_quiz_data', methods=['POST'])
@login_required(role='student')
def clear_quiz_data():
    """Clear quiz data from session"""
    session.pop('questions', None)
    session.pop('answers', None)
    session.pop('current_question', None)
    session.pop('quiz_start_time', None)
    session.pop('course', None)
    session.pop('semester', None)
    session.pop('quiz_duration', None)
    
    return jsonify({"success": True})