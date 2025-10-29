from flask import Blueprint, jsonify
from app.models.quiz_models import results_collection, quizzes_collection
from app.utils.decorators import login_required, permission_required
from app.models.user_models import users_collection
from datetime import datetime, timedelta

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/daily_leaderboard')
def daily_leaderboard_api():
    """Get daily leaderboard data for home page (Public route)"""
    try:
        # Get dates with quiz results
        pipeline = [
            {"$match": {"published": True}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": -1}},
            {"$limit": 7}
        ]
        
        dates_with_results = list(results_collection.aggregate(pipeline))
        
        dates_data = []
        for date_info in dates_with_results:
            date_str = date_info['_id']
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            
            # Format date as DD/MM/YY
            formatted_date = f"{date_obj.day:02d}/{date_obj.month:02d}/{date_obj.year % 100:02d}"
            
            # Get top performers for this date
            pipeline = [
                {"$match": {
                    "published": True,
                    "timestamp": {
                        "$gte": datetime(date_obj.year, date_obj.month, date_obj.day),
                        "$lt": datetime(date_obj.year, date_obj.month, date_obj.day) + timedelta(days=1)
                    }
                }},
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
            
            leaders = list(results_collection.aggregate(pipeline))
            
            # Convert ObjectId to string for JSON serialization
            for leader in leaders:
                if '_id' in leader:
                    leader['_id'] = str(leader['_id'])
                if 'timestamp' in leader and isinstance(leader['timestamp'], datetime):
                    leader['timestamp'] = leader['timestamp'].isoformat()
            
            dates_data.append({
                "date": date_str,
                "formatted_date": formatted_date,
                "leaders": leaders
            })
        
        return jsonify({"dates": dates_data})
    
    except Exception as e:
        print(f"Error in daily_leaderboard_api: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@api_bp.route('/api/course_leaderboard/<course>/<semester>')
def course_leaderboard(course, semester):
    """Get course-specific leaderboard for student dashboard"""
    try:
        # Get dates with quiz results for this specific course/semester
        pipeline = [
            {"$match": {
                "published": True,
                "course": course,
                "semester": semester
            }},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": -1}},
            {"$limit": 7}
        ]
        
        dates_with_results = list(results_collection.aggregate(pipeline))
        
        dates_data = []
        for date_info in dates_with_results:
            date_str = date_info['_id']
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            
            # Format date as DD/MM/YY
            formatted_date = f"{date_obj.day:02d}/{date_obj.month:02d}/{date_obj.year % 100:02d}"
            
            # Get top performers for this date and course/semester
            pipeline = [
                {"$match": {
                    "published": True,
                    "course": course,
                    "semester": semester,
                    "timestamp": {
                        "$gte": datetime(date_obj.year, date_obj.month, date_obj.day),
                        "$lt": datetime(date_obj.year, date_obj.month, date_obj.day) + timedelta(days=1)
                    }
                }},
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
            
            leaders = list(results_collection.aggregate(pipeline))
            
            # Convert ObjectId to string for JSON serialization
            for leader in leaders:
                if '_id' in leader:
                    leader['_id'] = str(leader['_id'])
                if 'timestamp' in leader and isinstance(leader['timestamp'], datetime):
                    leader['timestamp'] = leader['timestamp'].isoformat()
            
            dates_data.append({
                "date": date_str,
                "formatted_date": formatted_date,
                "leaders": leaders
            })
        
        return jsonify({"dates": dates_data})
    
    except Exception as e:
        print(f"Error in course_leaderboard: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


