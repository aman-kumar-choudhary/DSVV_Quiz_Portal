from app import get_db

# Collection getters for feedback and activities
def get_feedback_collection():
    return get_db().feedback

def get_activities_collection():
    return get_db().activities

# Shortcut variables
feedback_collection = get_feedback_collection()
activities_collection = get_activities_collection()