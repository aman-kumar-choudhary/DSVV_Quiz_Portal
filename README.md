Quiz Management System
A Flask-based web application for managing quizzes, designed for students and administrators. Students can take quizzes, view scores, and provide feedback, while administrators can upload questions, manage quizzes, and view results. The application uses MongoDB for data storage and includes user authentication, session management, and result export functionality.
Features

Student Features:
User signup and login with scholar ID and password.
Take quizzes for specific courses and semesters.
View scores and quiz history.
Submit feedback after completing quizzes.


Admin Features:
Login with admin credentials.
Upload questions via JSON files.
Start quizzes for specific courses and semesters.
View and export quiz results as CSV.
Monitor quiz statistics (e.g., total students, quizzes, average scores).


Security:
Password hashing with Bcrypt.
Session-based authentication.


Database:
MongoDB for storing users, questions, results, and sessions.


Other:
Timer-based quiz functionality.
Randomized question order for fairness.



Prerequisites

Python 3.8+
MongoDB (local or cloud instance, e.g., MongoDB Atlas)
pip for installing Python dependencies

Installation

Clone the Repository:
git clone <repository-url>
cd quiz-management-system


Set Up a Virtual Environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install Dependencies:
pip install -r requirements.txt


Configure Environment Variables:Create a .env file in the project root with the following:
MONGO_URI=mongodb://localhost:27017/quiz_db
SECRET_KEY=your-secret-key


Replace mongodb://localhost:27017/quiz_db with your MongoDB connection string.
Generate a secure SECRET_KEY for Flask session management.


Set Up MongoDB:

Ensure MongoDB is running locally or accessible via the provided MONGO_URI.
The application uses the quiz_db database with collections: users, questions, results, user_sessions, and feedback.


Run the Application:
python app.py

The app will be available at http://127.0.0.1:5000.


Usage
For Students

Sign Up: Visit /signup to create an account with scholar ID, name, course, semester, email, and password.
Log In: Go to /login, enter scholar ID and password, and select "Student" role.
Take Quiz: From the student dashboard (/student_dashboard), select your course and semester to start a quiz.
Submit Feedback: After completing a quiz, provide feedback at /feedback.
View Scores: Check your quiz results at /view_score.

For Admins

Log In: Go to /login, enter username admin.computer and password admin123, and select "Admin" role.
Manage Questions: Upload questions via JSON files at /admin/upload_questions.
Start Quiz: Activate a quiz for a course and semester at /admin/start_quiz.
View Results: Access quiz results at /admin/results and export them as CSV via /export_results.
View Questions: Filter and view questions at /admin/questions.

Sample JSON Question File
[
  {
    "question": "What is the capital of France?",
    "options": ["Paris", "London", "Berlin", "Madrid"],
    "correct_answer": "Paris",
    "course": "MCA-DS",
    "semester": "1"
  }
]

Project Structure
quiz-management-system/
├── app.py               # Main Flask application
├── requirements.txt     # Python dependencies
├── .env                # Environment variables (not tracked in git)
├── templates/          # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── student_dashboard.html
│   ├── quiz.html
│   ├── feedback.html
│   ├── result.html
│   ├── admin.html
│   ├── admin_questions.html
│   ├── admin_results.html
├── static/             # CSS, JavaScript, and other static files

Dependencies
See requirements.txt for the full list of dependencies. Key packages include:

Flask: Web framework
pymongo: MongoDB driver
python-dotenv: Environment variable management
flask-bcrypt: Password hashing
pandas: CSV export functionality

Notes

Admin Credentials: Default admin username is admin.computer with password admin123. Change these in production.
Security: Use HTTPS in production and consider adding CSRF protection and rate limiting.
MongoDB: Ensure indexes are created for frequently queried fields (e.g., scholar_id, course, semester) for better performance.
Templates: Ensure templates/ folder contains all required HTML files, and add static/ for CSS/JavaScript as needed.

Contributing
Contributions are welcome! Please submit a pull request or open an issue to suggest improvements or report bugs.
License
This project is licensed under the MIT License.