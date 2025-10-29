from flask import Blueprint, render_template, request, session, jsonify, send_file
from app.utils.decorators import login_required, permission_required
from app.utils.helpers import get_all_schools, get_all_departments, get_all_courses, get_all_semesters, create_notification, create_admin_notification, log_activity
from app.models.quiz_models import results_collection, quizzes_collection
from app.models.user_models import users_collection
import pandas as pd
from io import BytesIO
from datetime import datetime, timedelta

results_bp = Blueprint('results', __name__)

# Course to School/Department mapping
COURSE_MAPPING = {
    "Bachelor of Computer Application (Honors)": {
        "school": "School of Technology, Communication and Management",
        "department": "Department of Computer Sciences"
    },
    "Master of Computer Application (Data Science)": {
        "school": "School of Technology, Communication and Management", 
        "department": "Department of Computer Sciences"
    },
    "B.Sc. Information Technology (Honors)": {
        "school": "School of Technology, Communication and Management",
        "department": "Department of Computer Sciences"
    },
    "B.B.A Tourism & Travel Management (Honors)": {
        "school": "School of Technology, Communication and Management",
        "department": "Department of Tourism Management"
    },
    "M.B.A. Tourism & Travel Management": {
        "school": "School of Technology, Communication and Management",
        "department": "Department of Tourism Management"
    },
    "B.A. Journalism and Mass Communication (Honors)": {
        "school": "School of Technology, Communication and Management",
        "department": "Department of Journalism & Mass Communication"
    },
    "M. A. Journalism and Mass Communication": {
        "school": "School of Technology, Communication and Management",
        "department": "Department of Journalism & Mass Communication"
    },
    "M. A. Spiritual Journalism": {
        "school": "School of Technology, Communication and Management",
        "department": "Department of Journalism & Mass Communication"
    },
    "B.Voc. (Bachelor of Vocation) in 3D Animation and VFX (Honors)": {
        "school": "School of Technology, Communication and Management",
        "department": "Department of Animation and Visual Effects"
    },
    "Bachelor of Rural Studies (Honors)": {
        "school": "School of Biological Sciences and Sustainability",
        "department": "Department of Rural Studies and Sustainability"
    },
    "B.A. English (Honors)": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of English"
    },
    "B.Ed. (Bachelor of Education)": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Education"
    },
    "B.A. Psychology (Honors)": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Psychology"
    },
    "M.A. Counselling Psychology": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Psychology"
    },
    "M.Sc. Counselling Psychology": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Psychology"
    },
    "Life Management - Compulsory Program for PG and UG": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Life Management"
    },
    "M.Sc. Herbal Medicine and Natural Product Chemistry": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Scientific Spirituality"
    },
    "M.Sc. Molecular Physiology and Traditional Health Sciences": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Scientific Spirituality"
    },
    "M.Sc. Indigenous Approaches for Child Development & Generational Dynamics": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Scientific Spirituality"
    },
    "M.Sc. Indian Knowledge Systems": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Scientific Spirituality"
    },
    "M.A. Indian Knowledge Systems": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Scientific Spirituality"
    },
    "M.A. Hindu Studies": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Oriental Studies, Religious Studies & Philosophy"
    },
    "M.A. Philosophy": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Oriental Studies, Religious Studies & Philosophy"
    },
    "B.Sc. Yogic Science (Honors)": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Yogic Sciences and Human Consciousness"
    },
    "M.Sc. Yoga Therapy": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Yogic Sciences and Human Consciousness"
    },
    "M.A. Human Consciousness & Yogic Science": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Yogic Sciences and Human Consciousness"
    },
    "M.Sc. Human Consciousness & Yogic Science": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Yogic Sciences and Human Consciousness"
    },
    "P. G. Diploma Human Consciousness, Yoga & Alternative Therapy": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Yogic Sciences and Human Consciousness"
    },
    "Certificate In Yoga And Alternative Therapy": {
        "school": "School of Humanities, Social Sciences and Foundation Courses",
        "department": "Department of Yogic Sciences and Human Consciousness"
    },
    "B.A. Sanskrit (Honors)": {
        "school": "School of Indology",
        "department": "Department of Sanskrit and Vedic Studies"
    },
    "M.A. Sanskrit": {
        "school": "School of Indology",
        "department": "Department of Sanskrit and Vedic Studies"
    },
    "B.A. Hindi (Honors)": {
        "school": "School of Indology",
        "department": "Department of Hindi"
    },
    "M.A. Hindi": {
        "school": "School of Indology",
        "department": "Department of Hindi"
    },
    "B.A. Music (Vocal) (Honors)": {
        "school": "School of Indology",
        "department": "Department of Indian Classical Music"
    },
    "M.A. Music (Vocal)": {
        "school": "School of Indology",
        "department": "Department of Indian Classical Music"
    },
    "B.A. Music Instrumental Mridang/Tabla (Honors)": {
        "school": "School of Indology",
        "department": "Department of Indian Classical Music"
    },
    "M.A. Music (Tabla, Pakhaawaj)": {
        "school": "School of Indology",
        "department": "Department of Indian Classical Music"
    },
    "B.A. History (Honors)": {
        "school": "School of Indology",
        "department": "Department of History and Indian Culture"
    },
    "M. A. History and Indian Culture": {
        "school": "School of Indology",
        "department": "Department of History and Indian Culture"
    }
}

@results_bp.route('/')
@login_required(role='admin')
@permission_required('read')
def admin_results():
    """Results management page - Showing only published results"""
    school = request.args.get('school', '')
    department = request.args.get('department', '')
    course = request.args.get('course', '')
    semester = request.args.get('semester', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Start with published results only
    query = {}
    
    # Add filters only if they are provided and not empty
    if school and school != 'All' and school != '':
        # Find courses that belong to this school
        school_courses = [course_name for course_name, mapping in COURSE_MAPPING.items() 
                         if mapping['school'] == school]
        query['course'] = {'$in': school_courses}
    
    if department and department != 'All' and department != '':
        # Find courses that belong to this department
        dept_courses = [course_name for course_name, mapping in COURSE_MAPPING.items() 
                       if mapping['department'] == department]
        if 'course' in query:
            # Combine with existing course filter
            existing_courses = query['course']['$in']
            filtered_courses = [c for c in existing_courses if c in dept_courses]
            if filtered_courses:
                query['course']['$in'] = filtered_courses
            else:
                # No overlap, return empty results
                query['course']['$in'] = []
        else:
            query['course'] = {'$in': dept_courses}
    
    if course and course != 'All' and course != '':
        if 'course' in query and isinstance(query['course'], dict):
            # Filter existing course list
            existing_courses = query['course']['$in']
            if course in existing_courses:
                query['course'] = course
            else:
                # Course not in filtered list, return empty
                query['course'] = {'$in': []}
        else:
            query['course'] = course
    
    if semester and semester != 'All' and semester != '':
        query['semester'] = semester
    
    print(f"Final query: {query}")  # Debug print
    
    # Calculate pagination
    total_results = results_collection.count_documents(query)
    total_pages = (total_results + per_page - 1) // per_page
    skip = (page - 1) * per_page
    
    # Get results with pagination
    results = list(results_collection.find(query, {'_id': 0}).sort('timestamp', -1).skip(skip).limit(per_page))
    
    # Add user names to results
    for result in results:
        user = users_collection.find_one({'scholar_id': result['scholar_id']}, {'_id': 0, 'name': 1})
        result['user_name'] = user['name'] if user else 'Unknown'
        
        # Add school and department info for display
        if result['course'] in COURSE_MAPPING:
            mapping = COURSE_MAPPING[result['course']]
            result['school'] = mapping['school']
            result['department'] = mapping['department']
    
    # Get unique students count for published results with same filters
    pipeline = [
        {"$match": query},
        {"$group": {"_id": "$scholar_id"}},
        {"$count": "total_students"}
    ]
    
    student_count_result = list(results_collection.aggregate(pipeline))
    total_students = student_count_result[0]['total_students'] if student_count_result else 0
    
    # Calculate average score for filtered published results
    avg_score_pipeline = [
        {"$match": query},
        {"$group": {"_id": None, "avg_score": {"$avg": "$score"}}}
    ]
    
    avg_score_result = list(results_collection.aggregate(avg_score_pipeline))
    average_score = avg_score_result[0]['avg_score'] if avg_score_result else 0
    
    stats = {
        'total_quizzes': total_results,
        'total_students': total_students,
        'average_score': average_score,
        'current_page': page,
        'per_page': per_page,
        'total_pages': total_pages
    }
    
    return render_template('admin_results.html', 
                         results=results, 
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

@results_bp.route('/export_results', methods=['GET'])
@login_required(role='admin')
def export_results():
    """Export published results to CSV"""
    school = request.args.get('school', '')
    department = request.args.get('department', '')
    course = request.args.get('course', '')
    semester = request.args.get('semester', '')
    
    # Start with published results only
    query = {"published": True}
    
    # Apply same filtering logic as main route
    if school and school != 'All' and school != '':
        school_courses = [course_name for course_name, mapping in COURSE_MAPPING.items() 
                         if mapping['school'] == school]
        query['course'] = {'$in': school_courses}
    
    if department and department != 'All' and department != '':
        dept_courses = [course_name for course_name, mapping in COURSE_MAPPING.items() 
                       if mapping['department'] == department]
        if 'course' in query:
            existing_courses = query['course']['$in']
            filtered_courses = [c for c in existing_courses if c in dept_courses]
            query['course']['$in'] = filtered_courses if filtered_courses else []
        else:
            query['course'] = {'$in': dept_courses}
    
    if course and course != 'All' and course != '':
        if 'course' in query and isinstance(query['course'], dict):
            existing_courses = query['course']['$in']
            if course in existing_courses:
                query['course'] = course
            else:
                query['course'] = {'$in': []}
        else:
            query['course'] = course
    
    if semester and semester != 'All' and semester != '':
        query['semester'] = semester
    
    results = list(results_collection.find(query, {'_id': 0}))
    
    # Add user names and school/department info for export
    for result in results:
        user = users_collection.find_one({'scholar_id': result['scholar_id']}, {'_id': 0, 'name': 1})
        result['user_name'] = user['name'] if user else 'Unknown'
        
        if result['course'] in COURSE_MAPPING:
            mapping = COURSE_MAPPING[result['course']]
            result['school'] = mapping['school']
            result['department'] = mapping['department']
    
    df = pd.DataFrame(results)
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    return send_file(output, mimetype='text/csv', as_attachment=True, download_name='published_quiz_results.csv')

@results_bp.route('/publish_results', methods=['POST'])
@login_required(role='admin')
def publish_results():
    """Publish results for a workspace"""
    workspace_id = request.json.get('workspace_id')
    if not workspace_id:
        return jsonify({"error": "Workspace ID is required"}), 400
    
    result = results_collection.update_many(
        {"workspace_id": workspace_id},
        {"$set": {"published": True}}
    )
    
    if result.modified_count > 0:
        published_result = results_collection.find_one({"workspace_id": workspace_id})
        if published_result:
            create_notification(
                published_result['scholar_id'],
                "Results Published",
                f"Your quiz results for {published_result['course']} Semester {published_result['semester']} have been published. Score: {published_result['score']}/{published_result['total']}",
                "success"
            )
            
            create_admin_notification(
                "Results Published",
                f"Published results for {published_result['user_name']} ({published_result['scholar_id']}) - {published_result['course']} Semester {published_result['semester']}",
                "success",
                published_result['scholar_id'],
                published_result['course'],
                published_result['semester']
            )
            
            log_activity(
                "results_published",
                f"Published results for {published_result['user_name']} - {published_result['course']} Semester {published_result['semester']}",
                published_result['scholar_id'],
                published_result['course'],
                published_result['semester']
            )
        
        return jsonify({"success": True, "message": f"Results for workspace {workspace_id} published successfully"})
    
    return jsonify({"error": "Result not found"}), 404

@results_bp.route('/api/bulk_publish_results', methods=['POST'])
@login_required(role='admin')
def bulk_publish_results():
    """Bulk publish results"""
    try:
        data = request.json
        workspace_ids = data.get('workspace_ids', [])
        
        if not workspace_ids:
            return jsonify({"error": "No workspace IDs provided"}), 400
        
        # Convert to list if it's not already
        if not isinstance(workspace_ids, list):
            workspace_ids = [workspace_ids]
        
        print(f"Attempting to publish {len(workspace_ids)} results: {workspace_ids}")
        
        # Use a different variable name for the update result
        update_result = results_collection.update_many(
            {"workspace_id": {"$in": workspace_ids}},
            {"$set": {"published": True}}
        )
        
        print(f"Modified count: {update_result.modified_count}")
        
        if update_result.modified_count > 0:
            # Create notifications for all published results
            published_results = list(results_collection.find(
                {"workspace_id": {"$in": workspace_ids}}
            ))
            
            for result_doc in published_results:
                create_notification(
                    result_doc['scholar_id'],
                    "Results Published",
                    f"Your quiz results for {result_doc['course']} Semester {result_doc['semester']} have been published. Score: {result_doc['score']}/{result_doc['total']}",
                    "success"
                )
                
                create_admin_notification(
                    "Results Published",
                    f"Published results for {result_doc['user_name']} ({result_doc['scholar_id']}) - {result_doc['course']} Semester {result_doc['semester']}",
                    "success",
                    result_doc['scholar_id'],
                    result_doc['course'],
                    result_doc['semester']
                )
                
                log_activity(
                    "results_published",
                    f"Published results for {result_doc['user_name']} - {result_doc['course']} Semester {result_doc['semester']}",
                    result_doc['scholar_id'],
                    result_doc['course'],
                    result_doc['semester']
                )
            
            return jsonify({
                "success": True, 
                "message": f"Published {update_result.modified_count} results successfully"
            })
        
        return jsonify({"error": "No results found to publish"}), 404
        
    except Exception as e:
        print(f"Error in bulk_publish_results: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500