from app import get_db

# Collection getters
def get_quizzes_collection():
    return get_db().quizzes

def get_quiz_participants_collection():
    return get_db().quiz_participants

def get_results_collection():
    return get_db().results

def get_quiz_settings_collection():
    return get_db().quiz_settings

# Shortcut variables for easy access
quizzes_collection = get_quizzes_collection()
quiz_participants_collection = get_quiz_participants_collection()
results_collection = get_results_collection()
quiz_settings_collection = get_quiz_settings_collection()