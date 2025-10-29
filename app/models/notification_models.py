from datetime import datetime
from bson import ObjectId

def get_db():
    """Get database connection"""
    from app import get_db as get_app_db
    return get_app_db()

def get_notifications_collection():
    """Get student notifications collection"""
    db = get_db()
    return db.notifications

def get_admin_notifications_collection():
    """Get admin notifications collection"""
    db = get_db()
    return db.admin_notifications

def create_student_notification(scholar_id, title, message, notification_type="info", course=None, semester=None):
    """Create a new notification for student"""
    try:
        notifications_collection = get_notifications_collection()
        notification = {
            "title": title,
            "message": message,
            "type": notification_type,
            "scholar_id": scholar_id,
            "course": course,
            "semester": semester,
            "timestamp": datetime.utcnow(),
            "read": False,
            "read_at": None
        }
        result = notifications_collection.insert_one(notification)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error creating student notification: {str(e)}")
        return None

def create_admin_notification(title, message, notification_type="info", scholar_id=None, course=None, semester=None):
    """Create a new notification for admin"""
    try:
        admin_notifications_collection = get_admin_notifications_collection()
        notification = {
            "title": title,
            "message": message,
            "type": notification_type,
            "scholar_id": scholar_id,
            "course": course,
            "semester": semester,
            "timestamp": datetime.utcnow(),
            "read": False,
            "read_at": None
        }
        result = admin_notifications_collection.insert_one(notification)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error creating admin notification: {str(e)}")
        return None

def get_student_notifications(scholar_id, limit=20, unread_only=False):
    """Get notifications for a specific student"""
    try:
        notifications_collection = get_notifications_collection()
        query = {"scholar_id": scholar_id}
        if unread_only:
            query["read"] = False
            
        notifications = list(notifications_collection.find(
            query,
            {'_id': 1, 'title': 1, 'message': 1, 'type': 1, 'timestamp': 1, 'read': 1, 'course': 1, 'semester': 1}
        ).sort('timestamp', -1).limit(limit))
        
        # Convert ObjectId to string and format timestamp
        for notification in notifications:
            notification['_id'] = str(notification['_id'])
            if 'timestamp' in notification and isinstance(notification['timestamp'], datetime):
                notification['timestamp'] = notification['timestamp'].isoformat()
        
        return notifications
    except Exception as e:
        print(f"Error getting student notifications: {str(e)}")
        return []

def get_all_admin_notifications(limit=20, unread_only=False):
    """Get all admin notifications"""
    try:
        admin_notifications_collection = get_admin_notifications_collection()
        query = {}
        if unread_only:
            query["read"] = False
            
        notifications = list(admin_notifications_collection.find(
            query,
            {'_id': 1, 'title': 1, 'message': 1, 'type': 1, 'timestamp': 1, 'read': 1, 'scholar_id': 1, 'course': 1, 'semester': 1}
        ).sort('timestamp', -1).limit(limit))
        
        # Convert ObjectId to string and format timestamp
        for notification in notifications:
            notification['_id'] = str(notification['_id'])
            if 'timestamp' in notification and isinstance(notification['timestamp'], datetime):
                notification['timestamp'] = notification['timestamp'].isoformat()
        
        return notifications
    except Exception as e:
        print(f"Error getting admin notifications: {str(e)}")
        return []

def mark_student_notification_read(notification_id, scholar_id):
    """Mark a specific student notification as read"""
    try:
        notifications_collection = get_notifications_collection()
        result = notifications_collection.update_one(
            {"_id": ObjectId(notification_id), "scholar_id": scholar_id},
            {"$set": {"read": True, "read_at": datetime.utcnow()}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error marking student notification as read: {str(e)}")
        return False

def mark_admin_notification_read(notification_id):
    """Mark a specific admin notification as read"""
    try:
        admin_notifications_collection = get_admin_notifications_collection()
        result = admin_notifications_collection.update_one(
            {"_id": ObjectId(notification_id)},
            {"$set": {"read": True, "read_at": datetime.utcnow()}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error marking admin notification as read: {str(e)}")
        return False

def mark_all_student_notifications_read(scholar_id):
    """Mark all student notifications as read"""
    try:
        notifications_collection = get_notifications_collection()
        result = notifications_collection.update_many(
            {"scholar_id": scholar_id, "read": False},
            {"$set": {"read": True, "read_at": datetime.utcnow()}}
        )
        return result.modified_count
    except Exception as e:
        print(f"Error marking all student notifications as read: {str(e)}")
        return 0

def mark_all_admin_notifications_read():
    """Mark all admin notifications as read"""
    try:
        admin_notifications_collection = get_admin_notifications_collection()
        result = admin_notifications_collection.update_many(
            {"read": False},
            {"$set": {"read": True, "read_at": datetime.utcnow()}}
        )
        return result.modified_count
    except Exception as e:
        print(f"Error marking all admin notifications as read: {str(e)}")
        return 0

def delete_student_notification(notification_id, scholar_id):
    """Delete a specific student notification"""
    try:
        notifications_collection = get_notifications_collection()
        result = notifications_collection.delete_one(
            {"_id": ObjectId(notification_id), "scholar_id": scholar_id}
        )
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting student notification: {str(e)}")
        return False

def delete_admin_notification(notification_id):
    """Delete a specific admin notification"""
    try:
        admin_notifications_collection = get_admin_notifications_collection()
        result = admin_notifications_collection.delete_one(
            {"_id": ObjectId(notification_id)}
        )
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting admin notification: {str(e)}")
        return False

def clear_all_student_notifications(scholar_id):
    """Clear all notifications for a student"""
    try:
        notifications_collection = get_notifications_collection()
        result = notifications_collection.delete_many({"scholar_id": scholar_id})
        return result.deleted_count
    except Exception as e:
        print(f"Error clearing student notifications: {str(e)}")
        return 0

def clear_all_admin_notifications():
    """Clear all admin notifications"""
    try:
        admin_notifications_collection = get_admin_notifications_collection()
        result = admin_notifications_collection.delete_many({})
        return result.deleted_count
    except Exception as e:
        print(f"Error clearing admin notifications: {str(e)}")
        return 0

def get_unread_student_notification_count(scholar_id):
    """Get count of unread notifications for a student"""
    try:
        notifications_collection = get_notifications_collection()
        count = notifications_collection.count_documents({
            "scholar_id": scholar_id,
            "read": False
        })
        return count
    except Exception as e:
        print(f"Error getting unread student notification count: {str(e)}")
        return 0

def get_unread_admin_notification_count():
    """Get count of unread admin notifications"""
    try:
        admin_notifications_collection = get_admin_notifications_collection()
        count = admin_notifications_collection.count_documents({
            "read": False
        })
        return count
    except Exception as e:
        print(f"Error getting unread admin notification count: {str(e)}")
        return 0