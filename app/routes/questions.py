from flask import Blueprint, render_template, request, session, jsonify
from app.utils.decorators import login_required, permission_required, role_required
from app.utils.helpers import QUESTION_TAGS
from app.models.question_models import question_review_collection, question_bank_collection
from app.models.user_models import users_collection
import json
import pandas as pd
import uuid
from datetime import datetime
from bson import ObjectId

questions_bp = Blueprint('questions', __name__)

@questions_bp.route('/management')
@login_required(role='admin')
@role_required(2)  # Faculty level (2) and above can access
def admin_questions_management():
    """Question management main page"""
    # Get counts for display
    pending_count = question_review_collection.count_documents({})
    bank_count = question_bank_collection.count_documents({})
    
    return render_template('admin_questions_main.html', 
                         pending_count=pending_count,
                         bank_count=bank_count)

@questions_bp.route('/upload', methods=['GET', 'POST'])
@login_required(role='admin')
@permission_required('create')  # Requires create permission
def admin_question_upload():
    """Upload questions - Requires create permission"""
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
    
    # For GET request, get counts for display and provide default pagination values
    pending_count = question_review_collection.count_documents({})
    bank_count = question_bank_collection.count_documents({})
    
    # Get questions for review tab with pagination
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 10, type=int)
    
    # Build query for review questions
    review_query = {}
    total_review_count = question_review_collection.count_documents(review_query)
    total_review_pages = (total_review_count + page_size - 1) // page_size if total_review_count > 0 else 1
    
    # Get paginated review questions
    skip = (page - 1) * page_size
    review_questions = list(question_review_collection.find(review_query).skip(skip).limit(page_size))
    
    # Get questions for bank tab with pagination
    bank_query = {}
    total_bank_count = question_bank_collection.count_documents(bank_query)
    total_bank_pages = (total_bank_count + page_size - 1) // page_size if total_bank_count > 0 else 1
    
    # Get paginated bank questions
    bank_questions = list(question_bank_collection.find(bank_query).skip(skip).limit(page_size))
    
    return render_template('admin_question_upload.html',
                         pending_count=pending_count,
                         bank_count=bank_count,
                         current_page=page,
                         total_pages=total_review_pages,
                         total_count=total_review_count,
                         page_size=page_size,
                         questions=review_questions,  # Questions for review tab
                         bank_questions=bank_questions,  # Questions for bank tab
                         total_bank_pages=total_bank_pages,
                         total_bank_count=total_bank_count)

@questions_bp.route('/review')
@login_required(role='admin')
@role_required(2)  # Faculty level and above
def admin_question_review():
    """Question review page"""
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 10, type=int)
    search = request.args.get('search', '')
    difficulty = request.args.get('difficulty', '')
    
    # Build query
    query = {}
    if search:
        query['text'] = {'$regex': search, '$options': 'i'}
    if difficulty:
        query['difficulty'] = difficulty
    
    # Get total count
    total_count = question_review_collection.count_documents(query)
    total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1
    
    # Get paginated questions
    skip = (page - 1) * page_size
    questions = list(question_review_collection.find(query).skip(skip).limit(page_size))
    
    # Get counts for display
    pending_count = question_review_collection.count_documents({})
    bank_count = question_bank_collection.count_documents({})
    
    return render_template('admin_question_review.html', 
                         questions=questions, 
                         tags=QUESTION_TAGS,
                         current_page=page,
                         total_pages=total_pages,
                         total_count=total_count,
                         page_size=page_size,
                         pending_count=pending_count,
                         bank_count=bank_count)

# API endpoint for review questions data with pagination
@questions_bp.route('/api/review/questions')
@login_required(role='admin')
@role_required(2)
def api_review_questions():
    """API endpoint to get review questions as JSON with pagination"""
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 10, type=int)
    search = request.args.get('search', '')
    difficulty = request.args.get('difficulty', '')
    
    # Build query
    query = {}
    if search:
        query['text'] = {'$regex': search, '$options': 'i'}
    if difficulty:
        query['difficulty'] = difficulty
    
    # Get total count
    total_count = question_review_collection.count_documents(query)
    total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1
    
    # Get paginated questions
    skip = (page - 1) * page_size
    questions = list(question_review_collection.find(query).skip(skip).limit(page_size))
    
    # Convert ObjectId to string for JSON serialization
    for question in questions:
        question['_id'] = str(question['_id'])
        if 'created_at' in question and isinstance(question['created_at'], datetime):
            question['created_at'] = question['created_at'].isoformat()
    
    return jsonify({
        "questions": questions,
        "total_pages": total_pages,
        "total_count": total_count,
        "current_page": page,
        "page_size": page_size
    })

@questions_bp.route('/api/review/update', methods=['POST'])
@login_required(role='admin')
@permission_required('update')  # Requires update permission
def update_review_question():
    """Update question in review"""
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
        return jsonify({"success": True, "message": "Question updated successfully"})
    
    return jsonify({"error": "Invalid action"}), 400

@questions_bp.route('/bank')
@login_required(role='admin')
@permission_required('read')  # Requires read permission
def admin_question_bank():
    """Question bank page"""
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 10, type=int)
    search = request.args.get('search', '')
    difficulty = request.args.get('difficulty', '')
    tag = request.args.get('tag', '')
    
    # Build query
    query = {}
    if search:
        query['text'] = {'$regex': search, '$options': 'i'}
    if difficulty:
        query['difficulty'] = difficulty
    if tag:
        query['tags'] = {'$in': [tag]}
    
    # Get total count
    total_count = question_bank_collection.count_documents(query)
    total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1
    
    # Get paginated questions
    skip = (page - 1) * page_size
    questions = list(question_bank_collection.find(query).skip(skip).limit(page_size))
    
    # Get counts for display
    pending_count = question_review_collection.count_documents({})
    bank_count = question_bank_collection.count_documents({})
    
    return render_template('admin_question_bank.html', 
                         questions=questions, 
                         tags=QUESTION_TAGS,
                         current_page=page,
                         total_pages=total_pages,
                         total_count=total_count,
                         page_size=page_size,
                         pending_count=pending_count,
                         bank_count=bank_count)

# API endpoint for bank questions data with pagination
@questions_bp.route('/api/bank/questions')
@login_required(role='admin')
@permission_required('read')
def api_bank_questions():
    """API endpoint to get bank questions as JSON with pagination"""
    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 10, type=int)
    search = request.args.get('search', '')
    difficulty = request.args.get('difficulty', '')
    tag = request.args.get('tag', '')
    
    # Build query
    query = {}
    if search:
        query['text'] = {'$regex': search, '$options': 'i'}
    if difficulty:
        query['difficulty'] = difficulty
    if tag:
        query['tags'] = {'$in': [tag]}
    
    # Get total count
    total_count = question_bank_collection.count_documents(query)
    total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1
    
    # Get paginated questions
    skip = (page - 1) * page_size
    questions = list(question_bank_collection.find(query).skip(skip).limit(page_size))
    
    # Convert ObjectId to string for JSON serialization
    for question in questions:
        question['_id'] = str(question['_id'])
        if 'created_at' in question and isinstance(question['created_at'], datetime):
            question['created_at'] = question['created_at'].isoformat()
        if 'approved_at' in question and isinstance(question['approved_at'], datetime):
            question['approved_at'] = question['approved_at'].isoformat()
    
    return jsonify({
        "questions": questions,
        "total_pages": total_pages,
        "total_count": total_count,
        "current_page": page,
        "page_size": page_size
    })

@questions_bp.route('/api/bank/update', methods=['POST'])
@login_required(role='admin')
@permission_required('update')  # Requires update permission
def update_question_bank():
    """Update question in bank"""
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
        return jsonify({"success": True, "message": "Question updated successfully"})
    
    elif action == 'delete':
        question_bank_collection.delete_one({"question_id": question_id})
        return jsonify({"success": True, "message": "Question deleted"})
    
    return jsonify({"error": "Invalid action"}), 400

@questions_bp.route('/api/questions/approve/<question_id>', methods=['POST'])
@login_required(role='admin')
@permission_required('update')
def approve_question(question_id):
    """Approve a specific question"""
    try:
        question = question_review_collection.find_one({"question_id": question_id})
        if not question:
            return jsonify({"error": "Question not found"}), 404
        
        # Handle both cases: with and without JSON data
        data = request.get_json(silent=True) or {}
        
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@questions_bp.route('/api/questions/reject/<question_id>', methods=['POST'])
@login_required(role='admin')
@permission_required('update')
def reject_question(question_id):
    """Reject a specific question"""
    try:
        result = question_review_collection.delete_one({"question_id": question_id})
        if result.deleted_count == 0:
            return jsonify({"error": "Question not found"}), 404
        return jsonify({"success": True, "message": "Question rejected and deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@questions_bp.route('/api/questions/delete/<question_id>', methods=['POST'])
@login_required(role='admin')
@permission_required('delete')
def delete_question(question_id):
    """Delete a specific question from bank"""
    try:
        result = question_bank_collection.delete_one({"question_id": question_id})
        if result.deleted_count == 0:
            return jsonify({"error": "Question not found"}), 404
        return jsonify({"success": True, "message": "Question deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Bulk operations for review questions
@questions_bp.route('/api/review/bulk-approve', methods=['POST'])
@login_required(role='admin')
@permission_required('update')
def bulk_approve_questions():
    """Bulk approve questions"""
    try:
        data = request.json
        question_ids = data.get('question_ids', [])
        
        if not question_ids:
            return jsonify({"error": "No question IDs provided"}), 400
        
        approved_count = 0
        for question_id in question_ids:
            question = question_review_collection.find_one({"question_id": question_id})
            if question:
                question_bank_data = {
                    "question_id": question['question_id'],
                    "text": question['text'],
                    "options": question['options'],
                    "correct_answer": question['correct_answer'],
                    "tags": [],
                    "difficulty": 'intermediate',
                    "created_at": question['created_at'],
                    "approved_at": datetime.now(),
                    "approved_by": session['username']
                }
                question_bank_collection.insert_one(question_bank_data)
                question_review_collection.delete_one({"question_id": question_id})
                approved_count += 1
        
        return jsonify({
            "success": True, 
            "message": f"Successfully approved {approved_count} out of {len(question_ids)} questions"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@questions_bp.route('/api/review/bulk-reject', methods=['POST'])
@login_required(role='admin')
@permission_required('update')
def bulk_reject_questions():
    """Bulk reject questions"""
    try:
        data = request.json
        question_ids = data.get('question_ids', [])
        
        if not question_ids:
            return jsonify({"error": "No question IDs provided"}), 400
        
        rejected_count = 0
        for question_id in question_ids:
            result = question_review_collection.delete_one({"question_id": question_id})
            if result.deleted_count > 0:
                rejected_count += 1
        
        return jsonify({
            "success": True, 
            "message": f"Successfully rejected {rejected_count} out of {len(question_ids)} questions"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Bulk operations for bank questions
@questions_bp.route('/api/bank/bulk-delete', methods=['POST'])
@login_required(role='admin')
@permission_required('delete')
def bulk_delete_questions():
    """Bulk delete questions from bank"""
    try:
        data = request.json
        question_ids = data.get('question_ids', [])
        
        if not question_ids:
            return jsonify({"error": "No question IDs provided"}), 400
        
        deleted_count = 0
        for question_id in question_ids:
            result = question_bank_collection.delete_one({"question_id": question_id})
            if result.deleted_count > 0:
                deleted_count += 1
        
        return jsonify({
            "success": True, 
            "message": f"Successfully deleted {deleted_count} out of {len(question_ids)} questions"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500