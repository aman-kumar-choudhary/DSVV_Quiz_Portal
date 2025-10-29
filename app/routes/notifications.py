from flask import Blueprint, jsonify, request, session
from app.utils.decorators import login_required
from app.models.notification_models import (
    get_student_notifications,
    get_all_admin_notifications,
    create_student_notification,
    create_admin_notification,
    mark_student_notification_read,
    mark_admin_notification_read,
    mark_all_student_notifications_read,
    mark_all_admin_notifications_read,
    delete_student_notification,
    delete_admin_notification,
    clear_all_student_notifications,
    clear_all_admin_notifications,
    get_unread_student_notification_count,
    get_unread_admin_notification_count
)
from bson import ObjectId

notifications_bp = Blueprint('notifications', __name__)

# Student Notification Routes
@notifications_bp.route('/api/notifications')
@login_required(role='student')
def get_student_notifications_route():
    """Get student notifications"""
    try:
        scholar_id = session['scholar_id']
        limit = request.args.get('limit', 20, type=int)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        notifications = get_student_notifications(scholar_id, limit, unread_only)
        
        return jsonify({
            "success": True,
            "notifications": notifications,
            "unread_count": get_unread_student_notification_count(scholar_id)
        })
    
    except Exception as e:
        print(f"Error fetching student notifications: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@notifications_bp.route('/api/notifications/read', methods=['POST'])
@login_required(role='student')
def mark_all_student_notifications_read_route():
    """Mark all student notifications as read"""
    try:
        scholar_id = session['scholar_id']
        count = mark_all_student_notifications_read(scholar_id)
        
        return jsonify({
            "success": True,
            "message": f"Marked {count} notifications as read"
        })
    
    except Exception as e:
        print(f"Error marking student notifications as read: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@notifications_bp.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required(role='student')
def mark_single_student_notification_read_route(notification_id):
    """Mark a single student notification as read"""
    try:
        scholar_id = session['scholar_id']
        success = mark_student_notification_read(notification_id, scholar_id)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Notification marked as read"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Notification not found"
            }), 404
    
    except Exception as e:
        print(f"Error marking student notification as read: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@notifications_bp.route('/api/notifications/clear', methods=['POST'])
@login_required(role='student')
def clear_all_student_notifications_route():
    """Clear all student notifications"""
    try:
        scholar_id = session['scholar_id']
        count = clear_all_student_notifications(scholar_id)
        
        return jsonify({
            "success": True,
            "message": f"Cleared {count} notifications"
        })
    
    except Exception as e:
        print(f"Error clearing student notifications: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@notifications_bp.route('/api/notifications/<notification_id>', methods=['DELETE'])
@login_required(role='student')
def delete_single_student_notification_route(notification_id):
    """Delete a single student notification"""
    try:
        scholar_id = session['scholar_id']
        success = delete_student_notification(notification_id, scholar_id)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Notification deleted"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Notification not found"
            }), 404
    
    except Exception as e:
        print(f"Error deleting student notification: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

# Admin Notification Routes
@notifications_bp.route('/api/admin_notifications')
@login_required(role='admin')
def get_admin_notifications_route():
    """Get admin notifications"""
    try:
        limit = request.args.get('limit', 20, type=int)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        notifications = get_all_admin_notifications(limit, unread_only)
        
        return jsonify({
            "success": True,
            "notifications": notifications,
            "unread_count": get_unread_admin_notification_count()
        })
    
    except Exception as e:
        print(f"Error fetching admin notifications: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@notifications_bp.route('/api/admin_notifications/read', methods=['POST'])
@login_required(role='admin')
def mark_all_admin_notifications_read_route():
    """Mark all admin notifications as read"""
    try:
        count = mark_all_admin_notifications_read()
        
        return jsonify({
            "success": True,
            "message": f"Marked {count} notifications as read"
        })
    
    except Exception as e:
        print(f"Error marking admin notifications as read: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@notifications_bp.route('/api/admin_notifications/<notification_id>/read', methods=['POST'])
@login_required(role='admin')
def mark_single_admin_notification_read_route(notification_id):
    """Mark a single admin notification as read"""
    try:
        success = mark_admin_notification_read(notification_id)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Notification marked as read"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Notification not found"
            }), 404
    
    except Exception as e:
        print(f"Error marking admin notification as read: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@notifications_bp.route('/api/admin_notifications/clear', methods=['POST'])
@login_required(role='admin')
def clear_all_admin_notifications_route():
    """Clear all admin notifications"""
    try:
        count = clear_all_admin_notifications()
        
        return jsonify({
            "success": True,
            "message": f"Cleared {count} notifications"
        })
    
    except Exception as e:
        print(f"Error clearing admin notifications: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

@notifications_bp.route('/api/admin_notifications/<notification_id>', methods=['DELETE'])
@login_required(role='admin')
def delete_single_admin_notification_route(notification_id):
    """Delete a single admin notification"""
    try:
        success = delete_admin_notification(notification_id)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Notification deleted"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Notification not found"
            }), 404
    
    except Exception as e:
        print(f"Error deleting admin notification: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

# Utility routes for both student and admin
@notifications_bp.route('/api/notifications/unread_count')
@login_required()
def get_unread_count():
    """Get unread notification count for current user"""
    try:
        if session.get('user_type') == 'student':
            scholar_id = session['scholar_id']
            count = get_unread_student_notification_count(scholar_id)
        else:
            count = get_unread_admin_notification_count()
        
        return jsonify({
            "success": True,
            "unread_count": count
        })
    
    except Exception as e:
        print(f"Error getting unread count: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500