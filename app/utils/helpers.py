from datetime import datetime, timedelta
from flask import session
from app import get_db
import uuid
import re
from bson import ObjectId
from bson.json_util import dumps, loads
import pandas as pd
from io import BytesIO
import random
import json
import os

# Collections
def get_collection(collection_name):
    db = get_db()
    return db[collection_name]

# Role configuration
ROLES = {
    'admin': {
        'level': 3, 
        'permissions': ['create', 'read', 'update', 'delete', 'manage_users'],
        'dashboard_access': ['/admin', '/admin/questions/*', '/admin/quizzes/*', '/admin/results', '/admin/leaderboard', '/admin/users/*', '/admin/users/manage-admins']
    },
    'faculty': {
        'level': 2, 
        'permissions': ['create', 'read', 'update'],
        'dashboard_access': ['/admin', '/admin/questions/*', '/admin/quizzes/*', '/admin/results', '/admin/leaderboard']
    },
    'coordinator': {
        'level': 1, 
        'permissions': ['create', 'read'],
        'dashboard_access': ['/admin', '/admin/questions/management', '/admin/questions/upload', '/admin/questions/review', '/admin/results']
    }
}

# School to Department mapping
schoolDepartments = {
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

# Department to Course mapping
departmentCourses = {
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

# Question difficulty tags
QUESTION_TAGS = ['beginner', 'easy', 'intermediate', 'advanced', 'expert']

def initialize_roles():
    """Initialize roles in the database"""
    roles_collection = get_collection('roles')
    for role_name, role_data in ROLES.items():
        if not roles_collection.find_one({'name': role_name}):
            roles_collection.insert_one({
                'name': role_name,
                'level': role_data['level'],
                'permissions': role_data['permissions'],
                'created_at': datetime.now()
            })

def create_indexes():
    """Create database indexes"""
    users_collection = get_collection('users')
    questions_collection = get_collection('questions')
    question_review_collection = get_collection('question_review')
    question_bank_collection = get_collection('question_bank')
    quizzes_collection = get_collection('quizzes')
    results_collection = get_collection('results')
    user_sessions_collection = get_collection('user_sessions')
    quiz_settings_collection = get_collection('quiz_settings')
    feedback_collection = get_collection('feedback')
    notifications_collection = get_collection('notifications')
    admin_notifications_collection = get_collection('admin_notifications')
    activities_collection = get_collection('activities')
    quiz_participants_collection = get_collection('quiz_participants')
    admin_users_collection = get_collection('admin_users')

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
    admin_users_collection.create_index("username", unique=True)
    admin_users_collection.create_index("role")
    admin_users_collection.create_index("active")

def initialize_notification_system():
    """Initialize notification collections"""
    try:
        from app.models.notification_models import get_notifications_collection, get_admin_notifications_collection
        
        notifications_collection = get_notifications_collection()
        admin_notifications_collection = get_admin_notifications_collection()
        
        # Create indexes for better performance
        notifications_collection.create_index([("scholar_id", 1), ("timestamp", -1)])
        notifications_collection.create_index([("read", 1)])
        
        admin_notifications_collection.create_index([("timestamp", -1)])
        admin_notifications_collection.create_index([("read", 1)])
        
        print("✅ Notification system initialized")
        return True
    except Exception as e:
        print(f"❌ Error initializing notification system: {str(e)}")
        return False

def cleanup_duplicate_emails():
    """Clean up duplicate emails in users collection"""
    users_collection = get_collection('users')
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

def add_blocked_field():
    """Add blocked field to existing users"""
    users_collection = get_collection('users')
    users_collection.update_many(
        {"blocked": {"$exists": False}},
        {"$set": {"blocked": False}}
    )

def add_created_at_to_users():
    """Add created_at field to existing users"""
    users_collection = get_collection('users')
    users_collection.update_many(
        {"created_at": {"$exists": False}},
        {"$set": {"created_at": datetime.now()}}
    )

def initialize_database():
    """Initialize the complete database"""
    cleanup_duplicate_emails()
    create_indexes()
    add_blocked_field()
    add_created_at_to_users()
    initialize_roles()
    initialize_notification_system()  # Add this line



def get_all_courses():
    """Get all unique courses from the database"""
    users_collection = get_collection('users')
    courses = users_collection.distinct("course")
    return sorted([course for course in courses if course])

def get_all_semesters():
    """Get all unique semesters from the database"""
    users_collection = get_collection('users')
    semesters = users_collection.distinct("semester")
    return sorted([semester for semester in semesters if semester])

def get_all_departments():
    """Get all unique departments from the database"""
    users_collection = get_collection('users')
    departments = users_collection.distinct("department")
    return sorted([dept for dept in departments if dept])

def get_all_schools():
    """Get all unique schools from the database"""
    users_collection = get_collection('users')
    schools = users_collection.distinct("school")
    return sorted([school for school in schools if school])


def create_notification(scholar_id, title, message, notification_type="info", course=None, semester=None):
    """Create a notification for student"""
    try:
        from app.models.notification_models import create_student_notification
        notification_id = create_student_notification(scholar_id, title, message, notification_type, course, semester)
        return notification_id is not None
    except Exception as e:
        print(f"Error creating notification: {str(e)}")
        return False

def create_admin_notification(title, message, notification_type="info", scholar_id=None, course=None, semester=None):
    """Create a notification for admin users"""
    try:
        from app.models.notification_models import create_admin_notification as create_admin_notif
        notification_id = create_admin_notif(title, message, notification_type, scholar_id, course, semester)
        return notification_id is not None
    except Exception as e:
        print(f"Error creating admin notification: {str(e)}")
        return False

def get_notifications(scholar_id, limit=10):
    """Get student notifications"""
    try:
        from app.models.notification_models import get_student_notifications
        return get_student_notifications(scholar_id, limit)
    except Exception as e:
        print(f"Error getting notifications: {str(e)}")
        return []

def get_admin_notifications(limit=20):
    """Get admin notifications"""
    try:
        from app.models.notification_models import get_all_admin_notifications
        return get_all_admin_notifications(limit)
    except Exception as e:
        print(f"Error getting admin notifications: {str(e)}")
        return []

def mark_admin_notifications_read():
    """Mark all admin notifications as read"""
    try:
        from app.models.notification_models import mark_all_admin_notifications_read
        return mark_all_admin_notifications_read() > 0
    except Exception as e:
        print(f"Error marking admin notifications as read: {str(e)}")
        return False

def get_user_stats(scholar_id):
    """Get user statistics"""
    results_collection = get_collection('results')
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

def is_quiz_active(course, semester):
    """Check if there's an active quiz for the given course/semester"""
    quizzes_collection = get_collection('quizzes')
    specific_quiz = quizzes_collection.find_one({
        "course": course,
        "semester": semester,
        "status": "active"
    })
    
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
    
    return (specific_quiz is not None or 
            all_course_quiz is not None or 
            all_semester_quiz is not None or 
            all_course_semester_quiz is not None)

def has_dashboard_access(path):
    """Check if user has access to the requested path"""
    if session.get('user_type') == 'super_admin':
        return True
    
    user_role = session.get('role')
    allowed_paths = session.get('dashboard_access', [])
    
    # Check if path matches any allowed pattern
    for allowed_path in allowed_paths:
        if allowed_path.endswith('*'):
            # Wildcard match
            if path.startswith(allowed_path[:-1]):
                return True
        else:
            # Exact match
            if path == allowed_path:
                return True
    
    return False

def find_active_quiz(course, semester):
    """Find an active quiz for the given course/semester"""
    quizzes_collection = get_collection('quizzes')
    quiz = quizzes_collection.find_one({
        "course": course,
        "semester": semester,
        "status": "active"
    })
    if quiz:
        return quiz
    
    quiz = quizzes_collection.find_one({
        "course": "all",
        "semester": semester,
        "status": "active"
    })
    if quiz:
        return quiz
    
    quiz = quizzes_collection.find_one({
        "course": course,
        "semester": "all",
        "status": "active"
    })
    if quiz:
        return quiz
    
    quiz = quizzes_collection.find_one({
        "course": "all",
        "semester": "all",
        "status": "active"
    })
    return quiz

def log_activity(activity_type, description, scholar_id=None, course=None, semester=None):
    """Log system activity"""
    activities_collection = get_collection('activities')
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

def check_student_enrollment(scholar_id, quiz_id, course, semester):
    """Check if a student is enrolled in a quiz"""
    quizzes_collection = get_collection('quizzes')
    quiz = quizzes_collection.find_one({"quiz_id": quiz_id})
    if not quiz:
        return False
    
    participants = quiz.get('participants', [])
    
    if scholar_id in participants:
        return True
    
    if 'all' in participants:
        return check_student_matches_filters(course, semester, quiz)
    
    return False

def check_student_matches_filters(student_course, student_semester, quiz):
    """Check if a student matches the quiz's hierarchical filters"""
    if quiz['school'] != 'all':
        departments_in_school = schoolDepartments.get(quiz['school'], [])
        course_matches_school = False
        for dept in departments_in_school:
            if student_course in departmentCourses.get(dept, []):
                course_matches_school = True
                break
        if not course_matches_school:
            return False
    
    if quiz['department'] != 'all':
        if student_course not in departmentCourses.get(quiz['department'], []):
            return False
    
    if quiz['course'] != 'all' and student_course != quiz['course']:
        return False
    
    if quiz['semester'] != 'all' and str(student_semester) != quiz['semester']:
        return False
    
    return True

def validate_input(input_data, expected_fields):
    """Validate input data against expected fields"""
    for field in expected_fields:
        if field not in input_data:
            return False, f"Missing field: {field}"
    return True, "Valid"

def sanitize_input(input_data):
    """Sanitize input data to prevent XSS attacks"""
    if isinstance(input_data, dict):
        return {k: sanitize_input(v) for k, v in input_data.items()}
    elif isinstance(input_data, list):
        return [sanitize_input(item) for item in input_data]
    elif isinstance(input_data, str):
        return input_data.replace('<', '&lt;').replace('>', '&gt;')
    else:
        return input_data

def build_student_query(quiz):
    """Build student query based on quiz filters"""
    query = {}
    
    if quiz.get('school') != 'all':
        school_name = quiz.get('school')
        departments_in_school = schoolDepartments.get(school_name, [])
        
        if quiz.get('department') != 'all' and quiz.get('department') in departments_in_school:
            departments_to_filter = [quiz.get('department')]
        else:
            departments_to_filter = departments_in_school
        
        courses_to_filter = []
        for dept in departments_to_filter:
            courses_to_filter.extend(departmentCourses.get(dept, []))
        
        if quiz.get('course') != 'all' and quiz.get('course') in courses_to_filter:
            query['course'] = quiz.get('course')
        else:
            query['course'] = {'$in': courses_to_filter}
        
        if quiz.get('semester') != 'all':
            query['semester'] = quiz.get('semester')
    
    else:
        if quiz.get('department') != 'all':
            dept_name = quiz.get('department')
            courses_to_filter = departmentCourses.get(dept_name, [])
            
            if quiz.get('course') != 'all' and quiz.get('course') in courses_to_filter:
                query['course'] = quiz.get('course')
            else:
                query['course'] = {'$in': courses_to_filter}
            
            if quiz.get('semester') != 'all':
                query['semester'] = quiz.get('semester')
        
        else:
            if quiz.get('course') != 'all':
                query['course'] = quiz.get('course')
                
                if quiz.get('semester') != 'all':
                    query['semester'] = quiz.get('semester')
            else:
                if quiz.get('semester') != 'all':
                    query['semester'] = quiz.get('semester')
    
    return query