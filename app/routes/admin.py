from flask import Blueprint, render_template, request, session, jsonify
from app.utils.decorators import login_required, permission_required, role_required
from app.utils.helpers import get_all_schools, get_all_departments, get_all_courses, get_all_semesters, ROLES
from app.models.user_models import users_collection, admin_users_collection
from app.models.quiz_models import results_collection, quizzes_collection
from app.models.question_models import question_bank_collection
from app.models.feedback_models import feedback_collection, activities_collection
from bson import ObjectId
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/')
@login_required(role='admin')
def admin_dashboard():
    """Admin dashboard - Accessible to all admin roles"""
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
    
    # Get active quizzes
    active_quizzes = []
    quizzes = quizzes_collection.find({"status": "active"})
    for quiz in quizzes:
        active_quizzes.append({
            "title": quiz.get('title', 'Untitled Quiz'),
            "course": quiz.get('course', 'N/A'),
            "semester": quiz.get('semester', 'N/A'),
            "duration": quiz.get('duration', 0),
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
    
    # Format dates in leaderboard
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

@admin_bp.route('/users')
@login_required(role='admin')
@role_required(3)
def admin_users():
    """User management page - Only for super admin"""
    # Get filter parameters
    school = request.args.get('school', '')
    department = request.args.get('department', '')
    course = request.args.get('course', '')
    semester = request.args.get('semester', '')
    
    # Pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Build query
    query = {}
    if school and school != 'All' and school != '':
        query['school'] = school
    if department and department != 'All' and department != '':
        query['department'] = department
    if course and course != 'All' and course != '':
        query['course'] = course
    if semester and semester != 'All' and semester != '':
        query['semester'] = semester
    
    # Calculate pagination
    total_students = users_collection.count_documents(query)
    total_pages = (total_students + per_page - 1) // per_page
    skip = (page - 1) * per_page
    
    # Get students with pagination
    students = list(users_collection.find(
        query, 
        {'_id': 0, 'password': 0}
    ).sort('scholar_id', 1).skip(skip).limit(per_page))
    
    stats = {
        'total_students': total_students,
        'current_page': page,
        'per_page': per_page,
        'total_pages': total_pages
    }
    
    return render_template('admin_users.html', 
                           students=students, 
                           stats=stats, 
                           schools=get_all_schools(),
                           departments=get_all_departments(),
                           courses=get_all_courses(),
                           semesters=get_all_semesters(),
                           selected_school=school,
                           selected_department=department,
                           selected_course=course, 
                           selected_semester=semester,
                           current_page=page,
                           per_page=per_page)

@admin_bp.route('/edit_user', methods=['POST'])
@login_required(role='admin')
@role_required(3)
def edit_user():
    """Edit user details"""
    from app.utils.helpers import log_activity
    
    data = request.json
    scholar_id = data.get('scholar_id')
    
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    updates = {}
    if 'name' in data:
        updates['name'] = data.get('name')
    if 'email' in data:
        updates['email'] = data.get('email')
    if 'school' in data:
        updates['school'] = data.get('school')
    if 'department' in data:
        updates['department'] = data.get('department')
    if 'course' in data:
        updates['course'] = data.get('course')
    if 'semester' in data:
        updates['semester'] = data.get('semester')
    if 'blocked' in data:
        updates['blocked'] = data.get('blocked')
    
    result = users_collection.update_one({"scholar_id": scholar_id}, {"$set": updates})
    
    if result.modified_count > 0:
        log_activity(
            "user_updated",
            f"Updated user details for {scholar_id}",
            scholar_id=scholar_id
        )
        return jsonify({"success": True, "message": "User updated successfully"})
    
    return jsonify({"error": "No changes made or user not found"}), 404

@admin_bp.route('/delete_user', methods=['POST'])
@login_required(role='admin')
@role_required(3)
def delete_user():
    """Delete user"""
    from app.utils.helpers import log_activity
    
    scholar_id = request.json.get('scholar_id')
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    # Delete user and all related data
    users_collection.delete_one({"scholar_id": scholar_id})
    results_collection.delete_many({"scholar_id": scholar_id})
    feedback_collection.delete_many({"scholar_id": scholar_id})
    
    from app.models.user_models import notifications_collection, user_sessions_collection
    notifications_collection.delete_many({"scholar_id": scholar_id})
    user_sessions_collection.delete_many({"scholar_id": scholar_id})
    
    log_activity(
        "user_deleted",
        f"Deleted user {scholar_id} and all related data",
        scholar_id=scholar_id
    )
    
    return jsonify({"success": True, "message": "User and related data deleted successfully"})

@admin_bp.route('/block_user', methods=['POST'])
@login_required(role='admin')
@role_required(3)
def block_user():
    """Block or unblock user"""
    from app.utils.helpers import create_notification, log_activity
    
    data = request.json
    scholar_id = data.get('scholar_id')
    block = data.get('block', True)
    
    if not scholar_id:
        return jsonify({"error": "Scholar ID is required"}), 400
    
    users_collection.update_one({"scholar_id": scholar_id}, {"$set": {"blocked": block}})
    
    # Force logout the user if they're currently logged in
    from app.models.user_models import user_sessions_collection
    user_sessions_collection.delete_many({"scholar_id": scholar_id})
    
    if block:
        create_notification(scholar_id, "Account Blocked", "Your account has been temporarily blocked from participating in quizzes. Please contact the administrator for more information.", "warning")
        log_activity("user_blocked", f"Blocked user {scholar_id}", scholar_id=scholar_id)
    else:
        create_notification(scholar_id, "Account Unblocked", "Your account has been unblocked. You can now participate in quizzes.", "success")
        log_activity("user_unblocked", f"Unblocked user {scholar_id}", scholar_id=scholar_id)
    
    return jsonify({"success": True, "message": f"User {'blocked' if block else 'unblocked'} successfully"})

@admin_bp.route('/user_results/<scholar_id>')
@login_required(role='admin')
@role_required(3)
def user_results(scholar_id):
    """Get user results"""
    try:
        results = list(results_collection.find(
            {"scholar_id": scholar_id}, 
            {'_id': 0}
        ).sort('timestamp', -1))
        
        # Format the results for display
        for result in results:
            if 'timestamp' in result and isinstance(result['timestamp'], datetime):
                result['timestamp'] = result['timestamp'].isoformat()
        
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route('/users/manage-admins')
@login_required(role='admin')
@role_required(3)
def manage_admin_users():
    """Manage admin users page"""
    admin_users = list(admin_users_collection.find({}))
    return render_template('admin_manage_users.html', 
                         admin_users=admin_users, 
                         roles=ROLES.keys())

@admin_bp.route('/users/manage-admins-data')
@login_required(role='admin')
@role_required(3)
def manage_admin_users_data():
    """Serve admin users data for the management page"""
    try:
        admin_users = list(admin_users_collection.find({}, {'password': 0}))
        
        # Convert ObjectId to string for JSON serialization
        for user in admin_users:
            user['_id'] = str(user['_id'])
            if 'created_at' in user and user['created_at']:
                user['created_at'] = user['created_at'].isoformat()
            if 'last_login' in user and user['last_login']:
                user['last_login'] = user['last_login'].isoformat()
        
        return jsonify({
            "success": True,
            "admin_users": admin_users
        })
    
    except Exception as e:
        print(f"Error in manage_admin_users_data: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/admin-users/create', methods=['POST'])
@login_required(role='admin')
@role_required(3)
def create_admin_user():
    """Create a new admin user"""
    from app import get_bcrypt
    
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        name = data.get('name')
        email = data.get('email')
        
        if not all([username, password, role, name]):
            return jsonify({"error": "All fields are required"}), 400
        
        if role not in ROLES:
            return jsonify({"error": "Invalid role"}), 400
        
        # Check if username already exists
        if admin_users_collection.find_one({"username": username}):
            return jsonify({"error": "Username already exists"}), 400
        
        hashed_password = get_bcrypt().generate_password_hash(password).decode('utf-8')
        
        admin_user = {
            "username": username,
            "password": hashed_password,
            "role": role,
            "name": name,
            "email": email,
            "active": True,
            "created_by": session.get('username', 'system'),
            "created_at": datetime.now(),
            "last_login": None
        }
        
        admin_users_collection.insert_one(admin_user)
        
        from app.utils.helpers import log_activity
        log_activity(
            "admin_user_created",
            f"Created {role} user: {name} ({username})",
            scholar_id=None
        )
        
        return jsonify({"success": True, "message": "Admin user created successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/admin-users/update', methods=['POST'])
@login_required(role='admin')
@role_required(3)
def update_admin_user():
    """Update admin user"""
    from app import get_bcrypt
    
    try:
        data = request.json
        user_id = data.get('user_id')
        updates = {}
        
        if 'password' in data and data['password']:
            updates['password'] = get_bcrypt().generate_password_hash(data['password']).decode('utf-8')
        
        if 'role' in data:
            updates['role'] = data['role']
        
        if 'name' in data:
            updates['name'] = data['name']
        
        if 'email' in data:
            updates['email'] = data['email']
        
        if 'active' in data:
            updates['active'] = data['active']
        
        admin_users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": updates}
        )
        
        return jsonify({"success": True, "message": "User updated successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/admin-users/delete', methods=['POST'])
@login_required(role='admin')
@role_required(3)
def delete_admin_user():
    """Delete admin user"""
    try:
        user_id = request.json.get('user_id')
        admin_users_collection.delete_one({"_id": ObjectId(user_id)})
        
        from app.utils.helpers import log_activity
        log_activity(
            "admin_user_deleted",
            f"Deleted admin user with ID: {user_id}",
            scholar_id=None
        )
        
        return jsonify({"success": True, "message": "User deleted successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/students/filter', methods=['POST'])
@login_required(role='admin')
@permission_required('read')
def filter_students():
    """Filter students - Requires read permission"""
    try:
        filters = request.json
        query = {}
        
        for key, value in filters.items():
            if value and value != "all" and value != "":
                query[key] = value
        
        students = list(users_collection.find(query, {'_id': 0, 'scholar_id': 1, 'name': 1, 'course': 1, 'semester': 1}))
        return jsonify(students)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/recent_activities')
@login_required(role='admin')
def recent_activities():
    """Get recent activities"""
    activities = list(activities_collection.find({}, {'_id': 0}).sort('timestamp', -1).limit(20))
    return jsonify({"activities": activities})

@admin_bp.route('/quiz_stats')
@login_required(role='admin')
def quiz_stats():
    """Get quiz statistics"""
    from app.models.question_models import questions_collection
    
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

@admin_bp.route('/leaderboard')
@login_required(role='admin')
def admin_leaderboard():
    """Admin leaderboard page"""
    school = request.args.get('school', '')
    department = request.args.get('department', '')
    course = request.args.get('course', '')
    semester = request.args.get('semester', '')
    quiz_id = request.args.get('quiz_id', '')
    limit = int(request.args.get('limit', 10))
    
    # Build query based on filters
    query = {"published": True}
    
    # Add filters only if they are provided and not empty
    if school and school != 'all' and school != '':
        query["user_info.school"] = school
    if department and department != 'all' and department != '':
        query["user_info.department"] = department
    if course and course != 'all' and course != '':
        query["user_info.course"] = course
    if semester and semester != 'all' and semester != '':
        query["user_info.semester"] = semester
    if quiz_id and quiz_id != '':
        query["quiz_id"] = quiz_id
    
    # Updated pipeline with proper filtering
    pipeline = [
        {"$match": {"published": True}},  # Initial match for published results
        {"$lookup": {
            "from": "users",
            "localField": "scholar_id",
            "foreignField": "scholar_id",
            "as": "user_info"
        }},
        {"$unwind": "$user_info"},
        # Apply filters after lookup
        {"$match": query},
        {"$sort": {"score": -1, "completion_time": 1, "timestamp": 1}},
        {"$group": {
            "_id": "$scholar_id",
            "max_score": {"$max": "$score"},
            "total_questions": {"$first": "$total"},
            "user_name": {"$first": "$user_info.name"},
            "school": {"$first": "$user_info.school"},
            "department": {"$first": "$user_info.department"},
            "course": {"$first": "$user_info.course"},
            "semester": {"$first": "$user_info.semester"},
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
            "school": 1,
            "department": 1,
            "course": 1,
            "semester": 1,
            "percentage": {"$multiply": [{"$divide": ["$max_score", "$total_questions"]}, 100]},
            "timestamp": 1,
            "completion_time": 1
        }}
    ]
    
    leaderboard = list(results_collection.aggregate(pipeline))
    
    # Format dates
    for item in leaderboard:
        if 'timestamp' in item and isinstance(item['timestamp'], datetime):
            item['formatted_date'] = item['timestamp'].strftime('%d/%m/%y')
    
    # Get available quizzes
    quizzes = list(quizzes_collection.find({}, {'quiz_id': 1, 'title': 1}))
    
    return render_template('admin_leaderboard.html',
                         leaderboard=leaderboard,
                         schools=get_all_schools(),
                         departments=get_all_departments(),
                         courses=get_all_courses(),
                         semesters=get_all_semesters(),
                         quizzes=quizzes,
                         selected_school=school,
                         selected_department=department,
                         selected_course=course,
                         selected_semester=semester,
                         selected_quiz=quiz_id,
                         limit=limit)


@admin_bp.route('/leaderboard_data')
@login_required(role='admin')
def leaderboard_data():
    """API endpoint for leaderboard data"""
    try:
        school = request.args.get('school', '')
        department = request.args.get('department', '')
        course = request.args.get('course', '')
        semester = request.args.get('semester', '')
        quiz_id = request.args.get('quiz_id', '')
        limit = int(request.args.get('limit', 10))
        
        # Build query based on filters
        query = {"published": True}
        if school and school != 'all' and school != '':
            query["user_info.school"] = school
        if department and department != 'all' and department != '':
            query["user_info.department"] = department
        if course and course != 'all' and course != '':
            query["user_info.course"] = course
        if semester and semester != 'all' and semester != '':
            query["user_info.semester"] = semester
        if quiz_id and quiz_id != '':
            query["quiz_id"] = quiz_id
        
        # Updated pipeline with proper filtering
        pipeline = [
            {"$match": {"published": True}},
            {"$lookup": {
                "from": "users",
                "localField": "scholar_id",
                "foreignField": "scholar_id",
                "as": "user_info"
            }},
            {"$unwind": "$user_info"},
            # Apply filters after lookup
            {"$match": query},
            {"$sort": {"score": -1, "completion_time": 1, "timestamp": 1}},
            {"$group": {
                "_id": "$scholar_id",
                "max_score": {"$max": "$score"},
                "total_questions": {"$first": "$total"},
                "user_name": {"$first": "$user_info.name"},
                "school": {"$first": "$user_info.school"},
                "department": {"$first": "$user_info.department"},
                "course": {"$first": "$user_info.course"},
                "semester": {"$first": "$user_info.semester"},
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
                "school": 1,
                "department": 1,
                "course": 1,
                "semester": 1,
                "percentage": {"$multiply": [{"$divide": ["$max_score", "$total_questions"]}, 100]},
                "timestamp": 1,
                "completion_time": 1
            }}
        ]
        
        leaderboard = list(results_collection.aggregate(pipeline))
        
        for item in leaderboard:
            if 'timestamp' in item and isinstance(item['timestamp'], datetime):
                item['formatted_date'] = item['timestamp'].strftime('%d/%m/%y')
                item['timestamp'] = item['timestamp'].isoformat()
        
        return jsonify({
            "success": True,
            "leaderboard": leaderboard,
            "total_results": len(leaderboard)
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@admin_bp.route('/dashboard_stats')
@login_required(role='admin')
def dashboard_stats():
    """API endpoint for dashboard statistics"""
    try:
        # Total students
        total_students = users_collection.count_documents({})
        
        # Total questions
        total_questions = question_bank_collection.count_documents({})
        
        # Total published quizzes
        total_quizzes = results_collection.count_documents({"published": True})
        
        # Average score
        pipeline = [
            {"$match": {"published": True}},
            {"$group": {
                "_id": None,
                "avg_score": {"$avg": {"$multiply": [{"$divide": ["$score", "$total"]}, 100]}}
            }}
        ]
        
        avg_score_result = list(results_collection.aggregate(pipeline))
        average_score = round(avg_score_result[0]['avg_score'], 2) if avg_score_result else 0
        
        # Recent activities
        recent_activities = list(activities_collection.find({}, {'_id': 0}).sort('timestamp', -1).limit(5))
        
        # Format activities
        for activity in recent_activities:
            if 'timestamp' in activity and isinstance(activity['timestamp'], datetime):
                activity['timestamp'] = activity['timestamp'].isoformat()
        
        return jsonify({
            "success": True,
            "stats": {
                "total_students": total_students,
                "total_questions": total_questions,
                "total_quizzes": total_quizzes,
                "average_score": average_score,
                "recent_activities": recent_activities
            }
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@admin_bp.route('/clear_filters')
@login_required(role='admin')
def clear_filters():
    """Clear all filters and return to default view"""
    # This is handled client-side, but we can add server-side logic if needed
    return jsonify({"success": True, "message": "Filters cleared"})

# Error handlers for admin routes
@admin_bp.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Resource not found"}), 404

@admin_bp.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

@admin_bp.errorhandler(403)
def forbidden_error(error):
    return jsonify({"error": "Access forbidden"}), 403