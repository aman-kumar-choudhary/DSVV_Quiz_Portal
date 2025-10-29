from app import get_db

# Collection getters
def get_questions_collection():
    return get_db().questions

def get_question_review_collection():
    return get_db().question_review

def get_question_bank_collection():
    return get_db().question_bank

# Shortcut variables for easy access
questions_collection = get_questions_collection()
question_review_collection = get_question_review_collection()
question_bank_collection = get_question_bank_collection()