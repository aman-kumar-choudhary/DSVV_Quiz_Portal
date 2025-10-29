from app import get_db

# Collection getters
def get_users_collection():
    return get_db().users

def get_admin_users_collection():
    return get_db().admin_users

def get_user_sessions_collection():
    return get_db().user_sessions

def get_roles_collection():
    return get_db().roles

def get_feedback_collection():
    return get_db().feedback

def get_notifications_collection():
    return get_db().notifications

def get_admin_notifications_collection():
    return get_db().admin_notifications

def get_activities_collection():
    return get_db().activities

# Shortcut variables for easy access
users_collection = get_users_collection()
admin_users_collection = get_admin_users_collection()
user_sessions_collection = get_user_sessions_collection()
roles_collection = get_roles_collection()
feedback_collection = get_feedback_collection()
notifications_collection = get_notifications_collection()
admin_notifications_collection = get_admin_notifications_collection()
activities_collection = get_activities_collection()