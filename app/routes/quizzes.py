from flask import Blueprint, render_template, request, session, jsonify, redirect, url_for
from app.utils.decorators import login_required, permission_required, role_required
from app.utils.helpers import build_student_query, schoolDepartments, departmentCourses, create_notification, create_admin_notification, log_activity
from app.models.quiz_models import quizzes_collection, quiz_participants_collection, results_collection
from app.models.question_models import question_bank_collection, questions_collection
from app.models.user_models import users_collection
from bson import ObjectId
import uuid
from datetime import datetime

quizzes_bp = Blueprint('quizzes', __name__)

@quizzes_bp.route('/')
@login_required(role='admin')
@permission_required('read')
def admin_quizzes():
    """Quiz management page"""
    quizzes = list(quizzes_collection.find({}).sort('created_at', -1))
    return render_template('admin_quizzes.html', quizzes=quizzes)

@quizzes_bp.route('/list')
@login_required(role='admin')
@permission_required('read')
def list_quizzes():
    """List quizzes API"""
    try:
        quizzes = list(quizzes_collection.find({}))
        for quiz in quizzes:
            quiz['_id'] = str(quiz['_id'])
            # Ensure all required fields exist with proper defaults
            quiz.setdefault('questions', [])
            quiz.setdefault('participants', [])
            quiz.setdefault('status', 'draft')
            quiz.setdefault('description', '')
            quiz.setdefault('duration', 0)
            quiz.setdefault('pass_percentage', 40)
            
            # Ensure participants is always a list
            if not isinstance(quiz.get('participants'), list):
                quiz['participants'] = []
                
        return jsonify({"success": True, "quizzes": quizzes})
    except Exception as e:
        print(f"Error in list_quizzes: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@quizzes_bp.route('/create', methods=['POST'])
@login_required(role='admin')
@permission_required('create')
def admin_create_quiz():
    """Create quiz"""
    try:
        data = request.get_json()
        
        required_fields = ['quiz_title', 'school', 'department', 'course', 'semester', 'duration', 'pass_percentage']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"success": False, "error": f"Missing required field: {field}"}), 400
        
        # Check if quiz with same title already exists
        existing_quiz = quizzes_collection.find_one({"title": data['quiz_title']})
        if existing_quiz:
            return jsonify({"success": False, "error": "A quiz with this title already exists. Please choose a different title."}), 400
        
        quiz_id = str(uuid.uuid4())
        quiz = {
            "quiz_id": quiz_id,
            "title": data['quiz_title'],
            "description": data.get('description', ''),  # Add description field
            "school": data['school'],
            "department": data['department'],
            "course": data['course'],
            "semester": data['semester'],
            "duration": int(data['duration']),
            "pass_percentage": int(data['pass_percentage']),
            "status": "draft",
            "created_at": datetime.now(),
            "questions": [],
            "participants": []
        }
        
        quizzes_collection.insert_one(quiz)
        
        log_activity(
            "quiz_created",
            f"Created quiz: {data['quiz_title']}",
            scholar_id=None
        )
        
        return jsonify({"success": True, "message": "Quiz created successfully", "quiz_id": quiz_id})
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@quizzes_bp.route('/manage/<quiz_id>')
@login_required(role='admin')
@permission_required('update')
def manage_quiz(quiz_id):
    """Manage specific quiz"""
    try:
        quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
        if not quiz:
            return redirect(url_for('quizzes.admin_quizzes'))
        
        if '_id' in quiz:
            quiz['_id'] = str(quiz['_id'])
        
        # Get questions from question_bank_collection
        questions = list(question_bank_collection.find({}))
        
        for question in questions:
            if '_id' in question:
                question['_id'] = str(question['_id'])
            if 'text' not in question or not question['text']:
                question['text'] = 'No question text available'
            if 'tags' not in question:
                question['tags'] = []
            if 'difficulty' not in question:
                question['difficulty'] = 'Not set'
            # Ensure question_id exists
            if 'question_id' not in question:
                question['question_id'] = str(question['_id'])
        
        # Get students based on quiz filters
        query = build_student_query(quiz)
        students = list(users_collection.find(query, {'_id': 0, 'scholar_id': 1, 'name': 1, 'course': 1, 'semester': 1}))
        
        # Get all unique tags from questions
        all_tags = set()
        for question in questions:
            if question.get('tags'):
                all_tags.update(question['tags'])
        
        return render_template('admin_manage_quiz.html', 
                             quiz=quiz, 
                             questions=questions, 
                             students=students,
                             tags=list(all_tags))
    
    except Exception as e:
        print(f"Error in manage_quiz: {str(e)}")
        return redirect(url_for('quizzes.admin_quizzes'))

@quizzes_bp.route('/preview/<quiz_id>')
@login_required(role='admin')
@permission_required('read')
def preview_quiz(quiz_id):
    """Preview quiz page"""
    try:
        quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
        if not quiz:
            return redirect(url_for('quizzes.admin_quizzes'))
        
        # Get questions for this quiz
        questions = []
        if quiz.get('questions'):
            questions = list(question_bank_collection.find({
                "question_id": {"$in": quiz['questions']}
            }))
        
        return render_template('admin_preview_quiz.html', 
                             quiz=quiz, 
                             questions=questions)
    
    except Exception as e:
        print(f"Error in preview_quiz: {str(e)}")
        return redirect(url_for('quizzes.admin_quizzes'))

@quizzes_bp.route('/api/<quiz_id>/questions', methods=['POST', 'PUT', 'DELETE'])
@login_required(role='admin')
def manage_quiz_questions(quiz_id):
    """Add, update, or remove questions from quiz"""
    try:
        data = request.json
        question_ids = data.get('question_ids', [])
        action = data.get('action', 'add')  # 'add' or 'remove'
        
        if not question_ids:
            return jsonify({"success": False, "error": "No questions selected"}), 400
        
        # Get the current quiz
        quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
        if not quiz:
            return jsonify({"success": False, "error": "Quiz not found"}), 404
        
        current_questions = quiz.get('questions', [])
        
        if action == 'add':
            # Add questions to quiz
            new_questions = list(set(current_questions + question_ids))
            result = quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"questions": new_questions}}
            )
            message = f"Added {len(question_ids)} questions to quiz"
        elif action == 'remove':
            # Remove questions from quiz
            new_questions = [q for q in current_questions if q not in question_ids]
            result = quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"questions": new_questions}}
            )
            message = f"Removed {len(question_ids)} questions from quiz"
        else:
            return jsonify({"success": False, "error": "Invalid action"}), 400
        
        if result.modified_count > 0:
            return jsonify({
                "success": True, 
                "message": message,
                "total_questions": len(new_questions)
            })
        else:
            return jsonify({"success": False, "error": "No changes made"}), 400
            
    except Exception as e:
        print(f"Error in manage_quiz_questions: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


@quizzes_bp.route('/api/<quiz_id>/participants', methods=['POST', 'PUT', 'DELETE'])
@login_required(role='admin')
def manage_quiz_participants(quiz_id):
    """Add or remove participants from quiz"""
    try:
        data = request.json
        scholar_ids = data.get('scholar_ids', [])
        action = data.get('action', 'add')  # 'add' or 'remove'
        
        if not scholar_ids:
            return jsonify({"success": False, "error": "No students selected"}), 400
        
        print(f"{action.capitalize()}ing {len(scholar_ids)} participants from quiz {quiz_id}: {scholar_ids}")
        
        # Get the current quiz
        quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
        if not quiz:
            return jsonify({"success": False, "error": "Quiz not found"}), 404
        
        current_participants = quiz.get('participants', [])
        if not isinstance(current_participants, list):
            current_participants = []
        
        # Remove "all" if it exists when managing specific participants
        if 'all' in current_participants:
            current_participants.remove('all')
        
        if action == 'add':
            # Add participants (avoid duplicates)
            new_participants = list(set(current_participants + scholar_ids))
            
            # Update quiz participants
            result = quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"participants": new_participants}}
            )
            
            # Add to quiz_participants collection
            for scholar_id in scholar_ids:
                quiz_participants_collection.update_one(
                    {"quiz_id": quiz_id, "scholar_id": scholar_id},
                    {"$setOnInsert": {
                        "quiz_id": quiz_id,
                        "scholar_id": scholar_id,
                        "added_at": datetime.now(),
                        "status": "enrolled"
                    }},
                    upsert=True
                )
            
            message = f"Added {len(scholar_ids)} participants to quiz"
            
        elif action == 'remove':
            # Remove participants
            new_participants = [p for p in current_participants if p not in scholar_ids]
            
            # Update quiz participants
            result = quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"participants": new_participants}}
            )
            
            # Remove from quiz_participants collection
            quiz_participants_collection.delete_many({
                "quiz_id": quiz_id,
                "scholar_id": {"$in": scholar_ids}
            })
            
            message = f"Removed {len(scholar_ids)} participants from quiz"
        else:
            return jsonify({"success": False, "error": "Invalid action"}), 400
        
        print(f"Update result - matched: {result.matched_count}, modified: {result.modified_count}")
        
        if result.matched_count > 0:
            log_activity(
                f"participants_{action}ed",
                f"{action.capitalize()}ed {len(scholar_ids)} participants from quiz: {quiz['title']}",
                scholar_id=None
            )
            
            return jsonify({
                "success": True, 
                "message": message,
                "total_participants": len(new_participants)
            })
        else:
            return jsonify({"success": False, "error": "Failed to update quiz participants"}), 400
            
    except Exception as e:
        print(f"Error in manage_quiz_participants: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@quizzes_bp.route('/api/<quiz_id>/participants/all', methods=['POST', 'DELETE'])
@login_required(role='admin')
def handle_all_participants(quiz_id):
    """Handle all participants enrollment"""
    try:
        quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
        if not quiz:
            return jsonify({"success": False, "error": "Quiz not found"}), 404
        
        if request.method == 'POST':
            # Add 'all' to participants and clear individual participants
            result = quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"participants": ["all"]}}
            )
            if result.modified_count > 0:
                log_activity(
                    "all_participants_added",
                    f"Enrolled all students in quiz: {quiz['title']}",
                    scholar_id=None
                )
                return jsonify({"success": True, "message": "All students enrolled"})
            else:
                return jsonify({"success": False, "error": "Failed to enroll all students"}), 400
        
        elif request.method == 'DELETE':
            # Remove all participants
            result = quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"participants": []}}
            )
            if result.modified_count > 0:
                # Also clean up quiz_participants collection
                quiz_participants_collection.delete_many({"quiz_id": quiz_id})
                
                log_activity(
                    "all_participants_removed", 
                    f"Removed all participants from quiz: {quiz['title']}",
                    scholar_id=None
                )
                return jsonify({"success": True, "message": "All enrollment removed"})
            else:
                return jsonify({"success": False, "error": "Failed to remove all enrollment"}), 400
    
    except Exception as e:
        print(f"Error in handle_all_participants: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@quizzes_bp.route('/api/<quiz_id>/status', methods=['POST'])
@login_required(role='admin')
def update_quiz_status(quiz_id):
    """Update quiz status (start/stop)"""
    try:
        data = request.json
        action = data.get('action')
        
        if action not in ['start', 'stop']:
            return jsonify({"success": False, "error": "Invalid action"}), 400
        
        quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
        if not quiz:
            return jsonify({"success": False, "error": "Quiz not found"}), 404
        
        if action == 'start':
            # Activate the quiz
            result = quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"status": "active", "started_at": datetime.now()}}
            )
            
            if result.modified_count > 0:
                # Determine which course/semester to activate questions for
                target_course = quiz['course']
                target_semester = quiz['semester']
                
                # Handle "All" options
                if target_course == "all" or target_semester == "all":
                    if target_course == "all" and target_semester == "all":
                        questions_collection.update_many(
                            {},
                            {"$set": {"active": True, "activated_at": datetime.now()}}
                        )
                    elif target_course == "all":
                        questions_collection.update_many(
                            {"semester": target_semester},
                            {"$set": {"active": True, "activated_at": datetime.now()}}
                        )
                    elif target_semester == "all":
                        questions_collection.update_many(
                            {"course": target_course},
                            {"$set": {"active": True, "activated_at": datetime.now()}}
                        )
                else:
                    questions_collection.update_many(
                        {
                            "course": target_course,
                            "semester": target_semester
                        },
                        {"$set": {"active": True, "activated_at": datetime.now()}}
                    )
                
                # Notify students
                notify_quiz_start(quiz)
                
                log_activity(
                    "quiz_started",
                    f"Started quiz: {quiz['title']}",
                    scholar_id=None
                )
                
                return jsonify({"success": True, "message": "Quiz started successfully"})
            else:
                return jsonify({"success": False, "error": "Failed to start quiz"}), 400
        
        elif action == 'stop':
            # Deactivate the quiz
            result = quizzes_collection.update_one(
                {"quiz_id": quiz_id},
                {"$set": {"status": "inactive", "ended_at": datetime.now()}}
            )
            
            if result.modified_count > 0:
                # Deactivate questions
                target_course = quiz['course']
                target_semester = quiz['semester']
                
                # Handle "All" options
                if target_course == "all" or target_semester == "all":
                    if target_course == "all" and target_semester == "all":
                        questions_collection.update_many(
                            {},
                            {"$set": {"active": False}}
                        )
                    elif target_course == "all":
                        questions_collection.update_many(
                            {"semester": target_semester},
                            {"$set": {"active": False}}
                        )
                    elif target_semester == "all":
                        questions_collection.update_many(
                            {"course": target_course},
                            {"$set": {"active": False}}
                        )
                else:
                    questions_collection.update_many(
                        {
                            "course": target_course,
                            "semester": target_semester
                        },
                        {"$set": {"active": False}}
                    )
                
                log_activity(
                    "quiz_stopped",
                    f"Stopped quiz: {quiz['title']}",
                    scholar_id=None
                )
                
                return jsonify({"success": True, "message": "Quiz stopped successfully"})
            else:
                return jsonify({"success": False, "error": "Failed to stop quiz"}), 400
            
    except Exception as e:
        print(f"Error in update_quiz_status: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

def notify_quiz_start(quiz):
    """Notify students when quiz starts"""
    try:
        target_course = quiz['course']
        target_semester = quiz['semester']
        
        # Build query based on quiz scope
        if quiz.get('participants') and 'all' in quiz.get('participants', []):
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
            students = users_collection.find({
                "scholar_id": {"$in": quiz.get('participants', [])}
            })
        
        for student in students:
            create_notification(
                student['scholar_id'],
                "Quiz Started",
                f"A new quiz '{quiz['title']}' has started. You can now take the quiz.",
                "info"
            )
    
    except Exception as e:
        print(f"Error notifying students: {str(e)}")

@quizzes_bp.route('/api/<quiz_id>', methods=['DELETE'])
@login_required(role='admin')
@permission_required('delete')
def delete_quiz(quiz_id):
    """Delete quiz"""
    try:
        result = quizzes_collection.delete_one({"quiz_id": quiz_id})
        if result.deleted_count > 0:
            # Clean up related data
            quiz_participants_collection.delete_many({"quiz_id": quiz_id})
            results_collection.delete_many({"quiz_id": quiz_id})
            
            log_activity(
                "quiz_deleted",
                f"Deleted quiz with ID: {quiz_id}",
                scholar_id=None
            )
            
            return jsonify({"success": True, "message": "Quiz deleted successfully"})
        else:
            return jsonify({"success": False, "error": "Quiz not found"}), 404
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500