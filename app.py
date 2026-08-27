from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
import flask_mysqldb
from functools import wraps
import os
import hashlib
from werkzeug.utils import secure_filename
import dotenv
import csv
from io import StringIO, BytesIO
# Prefer native MySQLdb; fall back to PyMySQL (pure Python) if unavailable
try:
    import MySQLdb  # provided by mysqlclient
except ImportError:  # e.g., missing native mysqlclient on macOS
    import pymysql as MySQLdb
try:
    import dbutils.pooled_db
except ImportError:
    dbutils.pooled_db.PooledDB = None  # Fallback handled below
import logging
import traceback
import secrets
import sys
from config import Config
# ReportLab imports are loaded lazily where needed to avoid hard dependency at startup
from datetime import datetime
import time

# Load environment variables
dotenv.load_dotenv()

app = Flask(__name__)

# Configure app
app.config['SECRET_KEY'] = Config.SECRET_KEY

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MySQL configurations
DB_CONFIG = {
    'host': Config.MYSQL_HOST,
    'user': Config.MYSQL_USER,
    'password': Config.MYSQL_PASSWORD,
    'db': Config.MYSQL_DB,
    'charset': 'utf8mb4',
    'cursorclass': MySQLdb.cursors.DictCursor
}

class _MinimalPool:
    def __init__(self, creator, db_kwargs):
        self._creator = creator
        self._db_kwargs = db_kwargs

    def connection(self):
        return self._creator.connect(**self._db_kwargs)

# Create a connection pool (or a minimal fallback if dbutils is missing)
if dbutils.pooled_db.PooledDB is not None:
    pool = dbutils.pooled_db.PooledDB(
        creator=MySQLdb,
        maxconnections=10,
        mincached=2,
        maxcached=5,
        maxshared=3,
        blocking=True,
        maxusage=None,
        setsession=[],
        ping=1,
        **DB_CONFIG
    )
else:
    logger.warning("dbutils not installed; using minimal non-pooled connections as fallback")
    pool = _MinimalPool(creator=MySQLdb, db_kwargs=DB_CONFIG)

# Upload folder configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def allowed_file(filename, allowed_extensions=None):
    if allowed_extensions is None:
        allowed_extensions = ALLOWED_EXTENSIONS
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Generate CSRF token
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Validate CSRF token
def validate_csrf_token():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return False
    return True

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    try:
        # Get connection from pool
        connection = pool.connection()
        logger.info("Successfully got connection from pool")
        return connection
    except MySQLdb.Error as e:
        logger.error(f"MySQL Error: {str(e)}")
        logger.error(traceback.format_exc())
        return None
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def check_database_connection():
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            cursor.execute('SELECT 1')
            cursor.close()
            connection.close()
            logger.info("Database connection test successful")
            return True
        return False
    except Exception as e:
        logger.error(f"Database connection test failed: {str(e)}")
        return False

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
logger.info(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")

# Check database connection before starting (but don't exit if it fails)
try:
    if not check_database_connection():
        logger.warning("Failed to connect to database on startup - will retry on first request")
    else:
        logger.info("Database connection test successful")
except Exception as e:
    logger.warning(f"Database connection test failed: {str(e)} - will retry on first request")

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'message': 'Student Record Management System is running'}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validate_csrf_token():
            flash('Invalid CSRF token. Please try again.', 'error')
            return render_template('auth/login.html')
            
        try:
            username = request.form['username']
            password = hashlib.sha256(request.form['password'].encode()).hexdigest()
            
            connection = get_db_connection()
            if not connection:
                flash('Database connection error. Please try again.', 'error')
                return render_template('auth/login.html')
            
            cur = connection.cursor()
            cur.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
            user = cur.fetchone()
            cur.close()
            connection.close()

            if user:
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['department'] = user['department'] or 'ALL'
                flash('Welcome back, ' + user['username'], 'success')
                return redirect(url_for('dashboard'))
            
            flash('Invalid username or password', 'error')
        except Exception as e:
            app.logger.error(f'Login error: {str(e)}')
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('auth/login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('login'))
    
    cur = connection.cursor()
    
    try:
        if session['role'] == 'admin':
            # Get statistics for admin dashboard
            cur.execute('SELECT COUNT(*) as count FROM students')
            total_students = cur.fetchone()['count']
            
            cur.execute('SELECT COUNT(*) as count FROM users WHERE role = "teacher"')
            total_teachers = cur.fetchone()['count']
            
            cur.execute('SELECT COUNT(*) as count FROM placements')
            total_placements = cur.fetchone()['count']
            
            cur.execute('SELECT COUNT(*) as count FROM internships WHERE status = "ongoing"')
            total_internships = cur.fetchone()['count']
            
            cur.close()
            connection.close()
            
            return render_template('admin/dashboard.html',
                                total_students=total_students,
                                total_teachers=total_teachers,
                                total_placements=total_placements,
                                total_internships=total_internships)
        else:
            # Get statistics for teacher dashboard
            cur.execute('SELECT COUNT(*) as count FROM students WHERE department = %s', (session['department'],))
            dept_students = cur.fetchone()['count']
            
            cur.execute('''
                SELECT COUNT(*) as count FROM students s
                JOIN placements p ON s.id = p.student_id
                WHERE s.department = %s
            ''', (session['department'],))
            dept_placed_students = cur.fetchone()['count']
            
            cur.execute('''
                SELECT COUNT(*) as count FROM students s
                JOIN internships i ON s.id = i.student_id
                WHERE s.department = %s AND i.status = "ongoing"
            ''', (session['department'],))
            dept_active_internships = cur.fetchone()['count']
            
            cur.execute('''
                SELECT AVG(package) as avg FROM students s
                JOIN placements p ON s.id = p.student_id
                WHERE s.department = %s
            ''', (session['department'],))
            result = cur.fetchone()
            avg_package = result['avg'] if result['avg'] is not None else 0
            
            cur.close()
            connection.close()
            
            return render_template('teacher/dashboard.html',
                                dept_students=dept_students,
                                dept_placed_students=dept_placed_students,
                                dept_active_internships=dept_active_internships,
                                avg_package=round(avg_package, 2))
    except Exception as e:
        cur.close()
        connection.close()
        app.logger.error(f'Dashboard error: {str(e)}')
        flash('An error occurred while loading the dashboard. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/students')
@login_required
def list_students():
    connection = None
    cursor = None
    try:
        logger.info("Starting list_students route")
        connection = get_db_connection()
        if not connection:
            logger.error("Failed to get database connection")
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('index'))
        
        logger.info("Successfully got database connection")
        cursor = connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Get current date for semester calculation
        current_date = datetime.now()
        current_year = current_date.year
        current_month = current_date.month
        
        # Calculate academic year (starts from July)
        academic_year = current_year if current_month >= 7 else current_year - 1
        
        logger.info(f"Fetching students for academic year {academic_year}")
        
        # Get all students with their contact info
        query = """
            SELECT s.*, c.mobile_number, c.email, c.father_name, c.father_mobile, c.mother_name, c.mother_mobile,
                   c.student_photo, c.aadhar_card, c.pan_card, c.other_documents
            FROM students s
            LEFT JOIN contact_info c ON s.id = c.student_id
            ORDER BY s.roll_no
        """
        logger.debug(f"Executing query: {query}")
        cursor.execute(query)
        students = cursor.fetchall()
        logger.info(f"Found {len(students)} students")
        
        # Process students to add calculated fields
        processed_students = []
        for student in students:
            try:
                # Calculate academic details
                if student['is_lateral']:  # For lateral entry students (3-year curriculum)
                    session_end_year = student['joining_year'] + 3  # 3-year program
                    years_passed = academic_year - student['joining_year']
                    
                    # If joining year is in the future, set to initial values
                    if years_passed < 0:
                        current_semester = 3  # Start from 3rd semester for lateral entry
                        year_of_study = "2nd Year"
                    else:
                        if years_passed == 0:  # First year (2022-2023)
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 3  # Odd semester
                            else:
                                current_semester = 4  # Even semester
                            year_of_study = "2nd Year"
                        elif years_passed == 1:  # Second year (2023-2024)
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 5  # Odd semester
                            else:
                                current_semester = 6  # Even semester
                            year_of_study = "3rd Year"
                        elif years_passed == 2:  # Third year (2024-2025)
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 7  # Odd semester
                            else:
                                current_semester = 8  # Even semester
                            year_of_study = "4th Year"
                        else:  # Beyond third year
                            current_semester = 8  # Final semester
                            year_of_study = "4th Year"
                else:  # For regular students (4-year curriculum)
                    session_end_year = student['joining_year'] + 4  # 4-year program
                    years_passed = academic_year - student['joining_year']
                    
                    # If joining year is in the future, set to initial values
                    if years_passed < 0:
                        current_semester = 1  # Start from 1st semester for regular entry
                        year_of_study = "1st Year"
                    else:
                        if years_passed == 0:  # First year
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 1  # Odd semester
                            else:
                                current_semester = 2  # Even semester
                            year_of_study = "1st Year"
                        elif years_passed == 1:  # Second year
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 3  # Odd semester
                            else:
                                current_semester = 4  # Even semester
                            year_of_study = "2nd Year"
                        elif years_passed == 2:  # Third year
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 5  # Odd semester
                            else:
                                current_semester = 6  # Even semester
                            year_of_study = "3rd Year"
                        else:  # Fourth year or more
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 7  # Odd semester
                            else:
                                current_semester = 8  # Even semester
                            year_of_study = "4th Year"
                
                # Update passout status based on student type and current year
                if student['is_lateral']:
                    if current_year >= session_end_year:  # Check if current year is past or equal to session end year
                        passout_status = "Passed Out"
                    elif current_semester == 7:
                        passout_status = "Final Year (Semester 7/8)"
                    elif current_semester == 6:
                        passout_status = "Final Year (Semester 6/8)"
                    elif current_semester == 5:
                        passout_status = "3rd Year (Semester 5/8)"
                    elif current_semester == 4:
                        passout_status = "2nd Year (Semester 4/8)"
                    else:
                        passout_status = "2nd Year (Semester 3/8)"
                else:
                    if current_year >= session_end_year:  # Check if current year is past or equal to session end year
                        passout_status = "Passed Out"
                    elif current_semester == 7:
                        passout_status = "Final Year (Semester 7/8)"
                    elif current_semester == 6:
                        passout_status = "Final Year (Semester 6/8)"
                    elif current_semester == 5:
                        passout_status = "3rd Year (Semester 5/8)"
                    elif current_semester == 4:
                        passout_status = "2nd Year (Semester 4/8)"
                    else:
                        passout_status = "2nd Year (Semester 3/8)"
                
                # Update student's current semester if it's different
                if current_semester != student['current_semester']:
                    try:
                        update_query = "UPDATE students SET current_semester = %s WHERE id = %s"
                        cursor.execute(update_query, (current_semester, student['id']))
                        connection.commit()
                        student['current_semester'] = current_semester
                        logger.info(f"Updated semester for student {student['id']} to {current_semester}")
                    except Exception as e:
                        logger.error(f"Error updating current semester for student {student['id']}: {str(e)}")
                
                # Add calculated fields to student dictionary
                student['year_of_study'] = year_of_study
                student['session'] = f"{student['joining_year']}-{session_end_year}"
                student['passout_status'] = passout_status
                
                processed_students.append(student)
                
            except Exception as e:
                logger.error(f"Error processing student {student.get('id', 'unknown')}: {str(e)}")
                logger.error(traceback.format_exc())
                continue
        
        logger.info(f"Successfully processed {len(processed_students)} students")
        return render_template('students/list.html', students=processed_students, now=datetime.now())
        
    except Exception as e:
        logger.error(f"Error in list_students route: {str(e)}")
        logger.error(traceback.format_exc())
        flash('An error occurred while fetching the student list. Please try again.', 'error')
        return redirect(url_for('index'))
    finally:
        try:
            if cursor:
                cursor.close()
                logger.info("Cursor closed")
            if connection:
                connection.close()
                logger.info("Connection closed")
        except Exception as e:
            logger.error(f"Error closing database resources: {str(e)}")

@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if request.method == 'POST':
        try:
            # Get form data
            full_name = request.form['full_name']
            roll_number = request.form['roll_number']
            registration_number = request.form['registration_number']
            joining_year = int(request.form['joining_year'])
            admission_type = 'Lateral' if 'admission_type' in request.form else 'Regular'
            department = request.form['department']
            
            # Check if teacher has permission to add student to this department
            if session['role'] == 'teacher' and session['department'] != 'ALL':
                if department != session['department']:
                    flash('You can only add students to your department', 'error')
                    return redirect(url_for('add_student'))
            
            # Calculate current semester based on joining year and admission type
            current_year = datetime.now().year
            years_passed = current_year - joining_year
            
            if admission_type == 'Lateral':
                # Lateral entry students start from 3rd semester (2nd year)
                # For example, if they joined in 2023, they start from semester 3
                # Each year adds 2 semesters, but we need to start from 3
                if years_passed == 0:  # Just joined
                    current_semester = 3  # Start from 3rd semester
                else:
                    current_semester = min(6, 3 + (years_passed * 2))  # Max 6 semesters for lateral
            else:
                # Regular students start from 1st semester
                current_semester = min(8, 1 + (years_passed * 2))  # Max 8 semesters for regular
            
            # Handle file uploads
            student_photo = request.files.get('student_photo')
            aadhar_card = request.files.get('aadhar_card')
            pan_card = request.files.get('pan_card')
            other_documents = request.files.getlist('other_documents')
            
            # Create uploads directory if it doesn't exist
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Process file uploads
            student_photo_path = handle_file_upload(student_photo, None, f"{roll_number}_photo")
            aadhar_card_path = handle_file_upload(aadhar_card, None, f"{roll_number}_aadhar")
            pan_card_path = handle_file_upload(pan_card, None, f"{roll_number}_pan")
            other_documents_paths = handle_multiple_file_uploads(other_documents, None, f"{roll_number}_other")
            
            # Get database connection
            connection = get_db_connection()
            if not connection:
                flash('Database connection error. Please try again.', 'error')
                return redirect(url_for('add_student'))
            
            try:
                cur = connection.cursor()
                
                # Insert student record
                cur.execute("""
                    INSERT INTO students (
                        name, roll_no, registration_no, joining_year, 
                        current_semester, is_lateral, department
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    full_name, roll_number, registration_number, joining_year,
                    current_semester, admission_type == 'Lateral', department
                ))
                
                # Get the student ID
                student_id = cur.lastrowid
                
                # Insert contact information
                cur.execute("""
                    INSERT INTO contact_info (
                        student_id, mobile_number, email, address,
                        date_of_birth, blood_group, father_name,
                        father_mobile, mother_name, mother_mobile,
                        student_photo, aadhar_card, pan_card, other_documents
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    student_id,
                    request.form.get('mobile_number'),
                    request.form.get('email'),
                    request.form.get('address'),
                    request.form.get('date_of_birth') or None,  # Convert empty string to None
                    request.form.get('blood_group'),
                    request.form.get('father_name'),
                    request.form.get('father_mobile'),
                    request.form.get('mother_name'),
                    request.form.get('mother_mobile'),
                    student_photo_path,
                    aadhar_card_path,
                    pan_card_path,
                    ','.join(other_documents_paths) if other_documents_paths else None
                ))
                
                connection.commit()
                flash('Student added successfully!', 'success')
                return redirect(url_for('list_students'))
                
            except Exception as e:
                connection.rollback()
                logger.error(f"Error adding student: {str(e)}")
                logger.error(traceback.format_exc())
                flash('An error occurred while adding the student. Please try again.', 'error')
                return redirect(url_for('add_student'))
                
            finally:
                cur.close()
                connection.close()
                
        except Exception as e:
            logger.error(f"Error processing student data: {str(e)}")
            logger.error(traceback.format_exc())
            flash('An error occurred while processing the student data. Please try again.', 'error')
            return redirect(url_for('add_student'))
    
    return render_template('students/add.html', now=datetime.now())

@app.route('/students/<int:id>')
@login_required
def view_student(id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('list_students'))
    
    try:
        cur = connection.cursor()
        
        # Get student details with contact information
        cur.execute("""
            SELECT s.*, c.*
            FROM students s
            LEFT JOIN contact_info c ON s.id = c.student_id
            WHERE s.id = %s
        """, (id,))
        result = cur.fetchone()
        
        if not result:
            cur.close()
            connection.close()
            flash('Student not found', 'error')
            return redirect(url_for('list_students'))
        
        # Process the result to separate student and contact information
        student = dict(result)
        contact = None
        
        # Debug logging
        logger.debug(f"Raw student data: {student}")
        
        # Check if contact information exists
        if student.get('mobile_number') is not None:  # Changed condition to check for actual contact data
            contact = {
                'mobile_number': student.get('mobile_number'),
                'email': student.get('email'),
                'address': student.get('address'),
                'date_of_birth': student.get('date_of_birth'),
                'blood_group': student.get('blood_group'),
                'father_name': student.get('father_name'),
                'father_mobile': student.get('father_mobile'),
                'mother_name': student.get('mother_name'),
                'mother_mobile': student.get('mother_mobile'),
                'student_photo': student.get('student_photo'),
                'aadhar_card': student.get('aadhar_card'),
                'pan_card': student.get('pan_card'),
                'other_documents': student.get('other_documents')
            }
            logger.debug(f"Processed contact data: {contact}")
        
        # Get academic performance records
        cur.execute('SELECT * FROM academic_performance WHERE student_id = %s ORDER BY semester', (id,))
        academics = cur.fetchall()
        
        # Get placement details
        cur.execute('SELECT * FROM placements WHERE student_id = %s', (id,))
        placement_result = cur.fetchone()
        if placement_result:
            student['placement'] = dict(placement_result)
        else:
            student['placement'] = None
        
        # Get internship details
        cur.execute('SELECT * FROM internships WHERE student_id = %s ORDER BY id DESC', (id,))
        internships = cur.fetchall()
        
        # Calculate current semester and year of study
        current_year = datetime.now().year
        current_month = datetime.now().month
        academic_year = current_year if current_month >= 7 else current_year - 1
        
        # Calculate session end year based on student type
        if student['is_lateral']:
            session_end_year = student['joining_year'] + 3  # 3-year program for lateral entry
        else:
            session_end_year = student['joining_year'] + 4  # 4-year program for regular students
        
        # Calculate year of study based on joining year
        years_passed = academic_year - student['joining_year']
        if years_passed < 0:
            years_passed = 0
        
        # Calculate current semester and year of study
        if student['is_lateral']:
            if years_passed == 0:  # First year (2022-2023)
                if current_month >= 7 and current_month <= 12:
                    current_semester = 3  # Odd semester
                else:
                    current_semester = 4  # Even semester
                year_of_study = "2nd Year"
            elif years_passed == 1:  # Second year (2023-2024)
                if current_month >= 7 and current_month <= 12:
                    current_semester = 5  # Odd semester
                else:
                    current_semester = 6  # Even semester
                year_of_study = "3rd Year"
            elif years_passed == 2:  # Third year (2024-2025)
                if current_month >= 7 and current_month <= 12:
                    current_semester = 7  # Odd semester
                else:
                    current_semester = 8  # Even semester
                year_of_study = "4th Year"
            else:  # Beyond third year
                current_semester = 8  # Final semester
                year_of_study = "4th Year"
        else:
            if years_passed == 0:  # First year
                if current_month >= 7 and current_month <= 12:
                    current_semester = 1  # Odd semester
                else:
                    current_semester = 2  # Even semester
                year_of_study = "1st Year"
            elif years_passed == 1:  # Second year
                if current_month >= 7 and current_month <= 12:
                    current_semester = 3  # Odd semester
                else:
                    current_semester = 4  # Even semester
                year_of_study = "2nd Year"
            elif years_passed == 2:  # Third year
                if current_month >= 7 and current_month <= 12:
                    current_semester = 5  # Odd semester
                else:
                    current_semester = 6  # Even semester
                year_of_study = "3rd Year"
            else:  # Fourth year or more
                if current_month >= 7 and current_month <= 12:
                    current_semester = 7  # Odd semester
                else:
                    current_semester = 8  # Even semester
                year_of_study = "4th Year"
        
        # Update passout status based on student type and current year
        if student['is_lateral']:
            if current_year >= session_end_year:
                passout_status = "Passed Out"
            elif current_semester == 7:
                passout_status = "Final Year (Semester 7/8)"
            elif current_semester == 6:
                passout_status = "Final Year (Semester 6/8)"
            elif current_semester == 5:
                passout_status = "3rd Year (Semester 5/8)"
            elif current_semester == 4:
                passout_status = "2nd Year (Semester 4/8)"
            else:
                passout_status = "2nd Year (Semester 3/8)"
        else:
            if current_year >= session_end_year:
                passout_status = "Passed Out"
            elif current_semester == 7:
                passout_status = "Final Year (Semester 7/8)"
            elif current_semester == 6:
                passout_status = "Final Year (Semester 6/8)"
            elif current_semester == 5:
                passout_status = "3rd Year (Semester 5/8)"
            elif current_semester == 4:
                passout_status = "2nd Year (Semester 4/8)"
            else:
                passout_status = "2nd Year (Semester 3/8)"
        
        # Update student's current semester if it's different
        if current_semester != student['current_semester']:
            try:
                cur.execute("UPDATE students SET current_semester = %s WHERE id = %s", 
                          (current_semester, student['id']))
                connection.commit()
                student['current_semester'] = current_semester
            except Exception as e:
                logger.error(f"Error updating current semester: {str(e)}")
        
        # Add calculated fields to student dictionary
        student['year_of_study'] = year_of_study
        student['session'] = f"{student['joining_year']}-{session_end_year}"
        student['passout_status'] = passout_status
        
        cur.close()
        connection.close()
        
        return render_template('students/view.html', 
                             student=student, 
                             contact=contact,
                             academics=academics,
                             internships=internships)
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error viewing student: {str(e)}')
        logger.error(traceback.format_exc())
        flash('An error occurred while viewing student details. Please try again.', 'error')
        return redirect(url_for('list_students'))

def handle_file_upload(file, existing_path, prefix):
    """Handle single file upload and return the new path if successful."""
    if file and file.filename:
        if allowed_file(file.filename):
            filename = secure_filename(f"{prefix}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            return os.path.join('uploads', filename)
    return existing_path

def handle_multiple_file_uploads(files, existing_paths, prefix):
    """Handle multiple file uploads and return list of new paths."""
    if not files or not any(file.filename for file in files):
        return existing_paths.split(',') if existing_paths else []
    
    new_paths = []
    for file in files:
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"{prefix}_{int(time.time())}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            new_paths.append(os.path.join('uploads', filename))
    
    return new_paths

@app.route('/students/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_student(id):
    try:
        logger.info(f"Starting edit_student for student ID: {id}")
        conn = get_db_connection()
        if not conn:
            logger.error("Database connection failed")
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('list_students'))
            
        cur = conn.cursor(MySQLdb.cursors.DictCursor)
        
        # Get student details first to check department
        cur.execute("SELECT * FROM students WHERE id = %s", (id,))
        student = cur.fetchone()
        
        if not student:
            logger.error(f"Student not found with ID: {id}")
            flash('Student not found!', 'error')
            return redirect(url_for('list_students'))
            
        # Check if teacher has permission to edit this student
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if student['department'] != session['department']:
                logger.warning(f"Teacher from {session['department']} attempted to edit student from {student['department']}")
                flash('You can only edit students from your department', 'error')
                return redirect(url_for('list_students'))
        
        if request.method == 'POST':
            try:
                # Get form data
                name = request.form['name']
                roll_no = request.form['roll_no']
                registration_no = request.form['registration_no']
                joining_year = int(request.form['joining_year'])
                is_lateral = request.form.get('admission_type') == 'on'  # Check if checkbox is checked
                department = request.form['department']
                
                # Check if teacher has permission to change department
                if session['role'] == 'teacher' and session['department'] != 'ALL':
                    if department != session['department']:
                        flash('You can only assign students to your department', 'error')
                        return redirect(url_for('edit_student', id=id))
                
                # Calculate current semester based on joining year and admission type
                current_year = datetime.now().year
                current_month = datetime.now().month
                years_passed = current_year - joining_year
                
                # Calculate new current semester based on the new admission type
                if is_lateral:
                    # For lateral entry students (3-year program)
                    if years_passed < 0:
                        current_semester = 3  # Start from 3rd semester
                    else:
                        if years_passed == 0:  # First year
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 3  # Odd semester
                            else:
                                current_semester = 4  # Even semester
                        elif years_passed == 1:  # Second year
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 5  # Odd semester
                            else:
                                current_semester = 6  # Even semester
                        else:  # Third year or more
                            current_semester = 6  # Final semester
                else:
                    # For regular students (4-year program)
                    if years_passed < 0:
                        current_semester = 1  # Start from 1st semester
                    else:
                        if years_passed == 0:  # First year
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 1  # Odd semester
                            else:
                                current_semester = 2  # Even semester
                        elif years_passed == 1:  # Second year
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 3  # Odd semester
                            else:
                                current_semester = 4  # Even semester
                        elif years_passed == 2:  # Third year
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 5  # Odd semester
                            else:
                                current_semester = 6  # Even semester
                        else:  # Fourth year or more
                            if current_month >= 7 and current_month <= 12:
                                current_semester = 7  # Odd semester
                            else:
                                current_semester = 8  # Even semester
                
                # Handle file uploads
                student_photo = request.files.get('student_photo')
                aadhar_card = request.files.get('aadhar_card')
                pan_card = request.files.get('pan_card')
                other_documents = request.files.getlist('other_documents')
                
                # Process file uploads
                student_photo_path = handle_file_upload(student_photo, None, f"{roll_no}_photo")
                aadhar_card_path = handle_file_upload(aadhar_card, None, f"{roll_no}_aadhar")
                pan_card_path = handle_file_upload(pan_card, None, f"{roll_no}_pan")
                other_documents_paths = handle_multiple_file_uploads(other_documents, None, f"{roll_no}_other")
                
                # Update student record
                try:
                    cur.execute("""
                        UPDATE students 
                        SET name = %s, roll_no = %s, registration_no = %s, joining_year = %s, 
                            current_semester = %s, is_lateral = %s, department = %s
                        WHERE id = %s
                    """, (
                        name, roll_no, registration_no, joining_year, current_semester,
                        is_lateral, department, id
                    ))
                    logger.info("Student record updated successfully")
                except Exception as e:
                    logger.error(f"Error updating student record: {str(e)}")
                    raise
                
                # Update contact information
                try:
                    cur.execute("""
                        UPDATE contact_info 
                        SET mobile_number = %s, email = %s, address = %s,
                            date_of_birth = %s, blood_group = %s, father_name = %s,
                            father_mobile = %s, mother_name = %s, mother_mobile = %s,
                            student_photo = COALESCE(%s, student_photo),
                            aadhar_card = COALESCE(%s, aadhar_card),
                            pan_card = COALESCE(%s, pan_card),
                            other_documents = COALESCE(%s, other_documents)
                        WHERE student_id = %s
                    """, (
                        request.form.get('mobile_number'),
                        request.form.get('email'),
                        request.form.get('address'),
                        request.form.get('date_of_birth') or None,  # Convert empty string to None
                        request.form.get('blood_group'),
                        request.form.get('father_name'),
                        request.form.get('father_mobile'),
                        request.form.get('mother_name'),
                        request.form.get('mother_mobile'),
                        student_photo_path,
                        aadhar_card_path,
                        pan_card_path,
                        ','.join(other_documents_paths) if other_documents_paths else None,
                        id
                    ))
                    logger.info("Contact information updated successfully")
                except Exception as e:
                    logger.error(f"Error updating contact information: {str(e)}")
                    raise
                
                conn.commit()
                flash('Student updated successfully', 'success')
                return redirect(url_for('view_student', id=id))
                
            except Exception as e:
                conn.rollback()
                logger.error(f"Error updating student: {str(e)}")
                flash('Error updating student. Please try again.', 'error')
                return redirect(url_for('edit_student', id=id))
        
        # Get student details with contact information for the form
        cur.execute("""
            SELECT s.*, c.*
            FROM students s
            LEFT JOIN contact_info c ON s.id = c.student_id
            WHERE s.id = %s
        """, (id,))
        result = cur.fetchone()
        
        if not result:
            logger.error(f"Student not found with ID: {id}")
            flash('Student not found!', 'error')
            return redirect(url_for('list_students'))
        
        logger.info("Successfully fetched student data for edit form")
        return render_template('students/edit.html', student=result, now=datetime.now())
        
    except Exception as e:
        logger.error(f"Error fetching student data for edit form: {str(e)}")
        return redirect(url_for('list_students'))
    
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()
            logger.info("Database connection closed")

@app.route('/students/<int:id>/delete', methods=['POST'])
@login_required
def delete_student(id):
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('list_students'))
            
        cur = conn.cursor(MySQLdb.cursors.DictCursor)
        
        # Get student details first to check department
        cur.execute("SELECT * FROM students WHERE id = %s", (id,))
        student = cur.fetchone()
        
        if not student:
            flash('Student not found!', 'error')
            return redirect(url_for('list_students'))
            
        # Check if teacher has permission to delete this student
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if student['department'] != session['department']:
                flash('You can only delete students from your department', 'error')
                return redirect(url_for('list_students'))
        
        # Delete the student
        cur.execute("DELETE FROM students WHERE id = %s", (id,))
        conn.commit()
        
        flash('Student deleted successfully!', 'success')
        return redirect(url_for('list_students'))
        
    except Exception as e:
        logger.error(f"Error deleting student: {str(e)}")
        flash('An error occurred while deleting the student. Please try again.', 'error')
        return redirect(url_for('list_students'))
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.route('/teachers')
@login_required
def list_teachers():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        cur = connection.cursor()
        cur.execute("SELECT id, username, department FROM users WHERE role = 'teacher'")
        teachers = cur.fetchall()
        cur.close()
        connection.close()
        return render_template('admin/teachers.html', teachers=teachers)
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error listing teachers: {str(e)}')
        flash('An error occurred while loading teachers. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/teachers/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_teacher():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        department = request.form['department']
        
        connection = get_db_connection()
        if not connection:
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('list_teachers'))
        
        try:
            cur = connection.cursor()
            
            # Check if username already exists
            cur.execute('SELECT id FROM users WHERE username = %s', (username,))
            if cur.fetchone():
                flash('Username already exists', 'error')
                return redirect(url_for('add_teacher'))
            
            # Insert new teacher
            cur.execute("""
                INSERT INTO users (username, password, role, department)
                VALUES (%s, %s, 'teacher', %s)
            """, (username, password, department))
            connection.commit()
            flash('Teacher added successfully', 'success')
            return redirect(url_for('list_teachers'))
            
        except Exception as e:
            app.logger.error(f'Error adding teacher: {str(e)}')
            flash('An error occurred while adding the teacher. Please try again.', 'error')
            return redirect(url_for('add_teacher'))
        finally:
            if connection:
                connection.close()
    
    return render_template('admin/add_teacher.html')

@app.route('/teachers/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_teacher(id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('list_teachers'))
    
    try:
        cur = connection.cursor()
        
        # Check if teacher exists
        cur.execute('SELECT username FROM users WHERE id = %s AND role = "teacher"', (id,))
        teacher = cur.fetchone()
        
        if not teacher:
            flash('Teacher not found', 'error')
            return redirect(url_for('list_teachers'))
        
        # Delete the teacher
        cur.execute('DELETE FROM users WHERE id = %s AND role = "teacher"', (id,))
        connection.commit()
        
        flash('Teacher deleted successfully', 'success')
        
    except Exception as e:
        app.logger.error(f'Error deleting teacher: {str(e)}')
        flash('An error occurred while deleting the teacher. Please try again.', 'error')
    
    finally:
        if connection:
            connection.close()
    
    return redirect(url_for('list_teachers'))

@app.route('/teachers/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_teacher(id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('list_teachers'))
    
    try:
        cur = connection.cursor()
        
        if request.method == 'POST':
            username = request.form['username']
            department = request.form['department']
            new_password = request.form['new_password']
            
            # Check if username already exists for other teachers
            cur.execute('SELECT id FROM users WHERE username = %s AND id != %s AND role = "teacher"', (username, id))
            if cur.fetchone():
                flash('Username already exists', 'error')
                return redirect(url_for('edit_teacher', id=id))
            
            # Update query starts with username and department
            update_query = 'UPDATE users SET username = %s, department = %s'
            params = [username, department]
            
            # Add password to update if provided
            if new_password:
                hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
                update_query += ', password = %s'
                params.append(hashed_password)
            
            # Complete the query with WHERE clause
            update_query += ' WHERE id = %s AND role = "teacher"'
            params.append(id)
            
            cur.execute(update_query, tuple(params))
            connection.commit()
            
            flash('Teacher updated successfully', 'success')
            return redirect(url_for('list_teachers'))
        
        # Get teacher details for the form
        cur.execute('SELECT id, username, department FROM users WHERE id = %s AND role = "teacher"', (id,))
        teacher = cur.fetchone()
        
        if not teacher:
            cur.close()
            connection.close()
            flash('Teacher not found', 'error')
            return redirect(url_for('list_teachers'))
        
        cur.close()
        connection.close()
        return render_template('admin/edit_teacher.html', teacher=teacher)
        
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error editing teacher: {str(e)}')
        flash('An error occurred while processing your request. Please try again.', 'error')
        return redirect(url_for('list_teachers'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/export/csv')
@login_required
def export_csv():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        cur = connection.cursor()
        
        # Get all students with their placement and internship details
        cur.execute('''
            SELECT 
                s.id, s.name, s.roll_no, s.joining_year, s.department,
                p.company as placement_company, p.package as placement_package,
                p.location as placement_location,
                i.company as internship_company, i.duration as internship_duration,
                i.domain as internship_domain, i.status as internship_status
            FROM students s
            LEFT JOIN placements p ON s.id = p.student_id
            LEFT JOIN internships i ON s.id = i.student_id
        ''')
        students = cur.fetchall()
        cur.close()
        connection.close()
        
        # Create CSV in memory
        si = StringIO()
        writer = csv.writer(si)
        
        # Write headers
        writer.writerow([
            'ID', 'Name', 'Roll No', 'Year', 'Department',
            'Placement Company', 'Package (LPA)', 'Location',
            'Internship Company', 'Duration', 'Domain', 'Status'
        ])
        
        # Write data
        for student in students:
            writer.writerow([
                student['id'],
                student['name'],
                student['roll_no'],
                student['joining_year'],
                student['department'],
                student.get('placement_company', ''),
                student.get('placement_package', ''),
                student.get('placement_location', ''),
                student.get('internship_company', ''),
                student.get('internship_duration', ''),
                student.get('internship_domain', ''),
                student.get('internship_status', '')
            ])
        
        # Create the response
        output = BytesIO()
        output.write(si.getvalue().encode('utf-8'))
        output.seek(0)
        
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name='students_report.csv'
        )
    
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error exporting CSV: {str(e)}')
        flash('An error occurred while exporting data. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/students/<int:student_id>/placement/add', methods=['GET', 'POST'])
@login_required
def add_placement(student_id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    
    try:
        cur = connection.cursor()
        
        # Get student details first to check department
        cur.execute('SELECT department FROM students WHERE id = %s', (student_id,))
        student = cur.fetchone()
        
        if not student:
            flash('Student not found', 'error')
            return redirect(url_for('list_students'))
        
        # Check if teacher has permission to add placement for this student
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if student['department'] != session['department']:
                flash('You can only add placements for students in your department', 'error')
                return redirect(url_for('view_student', id=student_id))
        
        # Check if student already has a placement
        cur.execute('SELECT id FROM placements WHERE student_id = %s', (student_id,))
        existing_placement = cur.fetchone()
        
        if existing_placement:
            flash('Student already has a placement record. Please edit the existing record instead.', 'error')
            return redirect(url_for('view_student', id=student_id))
        
        if request.method == 'POST':
            company = request.form['company']
            package = request.form['package']
            location = request.form['location']
            
            # Handle file uploads
            joining_letter_path = None
            salary_slip_path = None
            
            if 'joining_letter' in request.files:
                file = request.files['joining_letter']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"{student_id}_joining_letter.pdf")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    joining_letter_path = os.path.join('uploads', filename)
            
            if 'salary_slip' in request.files:
                file = request.files['salary_slip']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"{student_id}_salary_slip.pdf")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    salary_slip_path = os.path.join('uploads', filename)
            
            cur.execute("""
                INSERT INTO placements (student_id, company, package, location, joining_letter_path, salary_slip_path)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (student_id, company, package, location, joining_letter_path, salary_slip_path))
            connection.commit()
            cur.close()
            
            flash('Placement details added successfully', 'success')
            return redirect(url_for('view_student', id=student_id))
        
        return render_template('students/add_placement.html', student_id=student_id)
    
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error adding placement: {str(e)}')
        flash('An error occurred while adding placement details. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))

@app.route('/placements/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_placement(id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('list_placements'))
    
    try:
        cur = connection.cursor()
        
        # Get placement details with student department
        cur.execute('''
            SELECT p.*, s.department 
            FROM placements p 
            JOIN students s ON p.student_id = s.id 
            WHERE p.id = %s
        ''', (id,))
        placement = cur.fetchone()
        
        if not placement:
            flash('Placement not found', 'error')
            return redirect(url_for('list_placements'))
        
        # Check if teacher has permission to edit this placement
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if placement['department'] != session['department']:
                flash('You can only edit placements for students in your department', 'error')
                return redirect(url_for('list_placements'))
        
        if request.method == 'POST':
            company = request.form['company']
            package = request.form['package']
            location = request.form['location']
            
            # Handle file uploads
            joining_letter_path = None
            salary_slip_path = None
            
            if 'joining_letter' in request.files:
                file = request.files['joining_letter']
                if file and allowed_file(file.filename):
                    # Get student_id for the filename
                    cur.execute('SELECT student_id FROM placements WHERE id = %s', (id,))
                    result = cur.fetchone()
                    if result:
                        student_id = result['student_id']
                        filename = secure_filename(f"{student_id}_joining_letter_updated.pdf")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        joining_letter_path = os.path.join('uploads', filename)
            
            if 'salary_slip' in request.files:
                file = request.files['salary_slip']
                if file and allowed_file(file.filename):
                    # Get student_id for the filename
                    cur.execute('SELECT student_id FROM placements WHERE id = %s', (id,))
                    result = cur.fetchone()
                    if result:
                        student_id = result['student_id']
                        filename = secure_filename(f"{student_id}_salary_slip_updated.pdf")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        salary_slip_path = os.path.join('uploads', filename)
            
            # Update placement details
            update_query = '''
                UPDATE placements 
                SET company = %s, package = %s, location = %s
            '''
            params = [company, package, location]
            
            if joining_letter_path:
                update_query += ', joining_letter_path = %s'
                params.append(joining_letter_path)
            
            if salary_slip_path:
                update_query += ', salary_slip_path = %s'
                params.append(salary_slip_path)
            
            update_query += ' WHERE id = %s'
            params.append(id)
            
            cur.execute(update_query, tuple(params))
            connection.commit()
            
            flash('Placement details updated successfully', 'success')
            return redirect(url_for('list_placements'))
        
        cur.close()
        connection.close()
        return render_template('students/edit_placement.html', placement=placement)
        
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error editing placement: {str(e)}')
        flash('An error occurred while processing your request. Please try again.', 'error')
        return redirect(url_for('list_placements'))

@app.route('/students/<int:student_id>/internship/add', methods=['GET', 'POST'])
@login_required
def add_internship(student_id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    
    try:
        cur = connection.cursor()
        
        # Get student details first to check department
        cur.execute('SELECT department FROM students WHERE id = %s', (student_id,))
        student = cur.fetchone()
        
        if not student:
            flash('Student not found', 'error')
            return redirect(url_for('list_students'))
        
        # Check if teacher has permission to add internship for this student
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if student['department'] != session['department']:
                flash('You can only add internships for students in your department', 'error')
                return redirect(url_for('view_student', id=student_id))
        
        if request.method == 'POST':
            company = request.form['company']
            duration = request.form['duration']
            domain = request.form['domain']
            status = request.form['status']
            
            # Handle file upload
            certificate_path = None
            if 'completion_certificate' in request.files:
                file = request.files['completion_certificate']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"{student_id}_internship_certificate.pdf")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    certificate_path = os.path.join('uploads', filename)
            
            cur.execute("""
                INSERT INTO internships (student_id, company, duration, domain, completion_certificate_path, status)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (student_id, company, duration, domain, certificate_path, status))
            connection.commit()
            cur.close()
            
            flash('Internship details added successfully', 'success')
            return redirect(url_for('view_student', id=student_id))
        
        return render_template('students/add_internship.html', student_id=student_id)
    
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error adding internship: {str(e)}')
        flash('An error occurred while adding internship details. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))

@app.route('/internships')
@login_required
def list_internships():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        cur = connection.cursor()
        
        # Get all internships with student names
        cur.execute('''
            SELECT i.*, s.name as student_name 
            FROM internships i 
            JOIN students s ON i.student_id = s.id
            ORDER BY i.status = 'ongoing' DESC, i.id DESC
        ''')
        internships = cur.fetchall()
        cur.close()
        connection.close()
        
        return render_template('students/internships.html', internships=internships)
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error listing internships: {str(e)}')
        flash('An error occurred while loading internships. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/internships/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_internship(id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('list_internships'))
    
    try:
        cur = connection.cursor()
        
        # Get internship details with student department
        cur.execute('''
            SELECT i.*, s.department 
            FROM internships i 
            JOIN students s ON i.student_id = s.id 
            WHERE i.id = %s
        ''', (id,))
        internship = cur.fetchone()
        
        if not internship:
            flash('Internship not found', 'error')
            return redirect(url_for('list_internships'))
        
        # Check if teacher has permission to edit this internship
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if internship['department'] != session['department']:
                flash('You can only edit internships for students in your department', 'error')
                return redirect(url_for('list_internships'))
        
        if request.method == 'POST':
            company = request.form['company']
            duration = request.form['duration']
            domain = request.form['domain']
            status = request.form['status']
            
            # Handle file upload
            certificate_path = None
            if 'completion_certificate' in request.files:
                file = request.files['completion_certificate']
                if file and allowed_file(file.filename):
                    # Get student_id for the filename
                    cur.execute('SELECT student_id FROM internships WHERE id = %s', (id,))
                    result = cur.fetchone()
                    if result:
                        student_id = result['student_id']
                        filename = secure_filename(f"{student_id}_internship_certificate_updated.pdf")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        certificate_path = os.path.join('uploads', filename)
            
            # Update internship details
            update_query = '''
                UPDATE internships 
                SET company = %s, duration = %s, domain = %s, status = %s
            '''
            params = [company, duration, domain, status]
            
            if certificate_path:
                update_query += ', completion_certificate_path = %s'
                params.append(certificate_path)
            
            update_query += ' WHERE id = %s'
            params.append(id)
            
            cur.execute(update_query, tuple(params))
            connection.commit()
            
            flash('Internship details updated successfully', 'success')
            return redirect(url_for('list_internships'))
        
        cur.close()
        connection.close()
        return render_template('students/edit_internship.html', internship=internship)
        
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error editing internship: {str(e)}')
        flash('An error occurred while processing your request. Please try again.', 'error')
        return redirect(url_for('list_internships'))

@app.route('/placements')
@login_required
def list_placements():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        cur = connection.cursor()
        
        # Get all placements with student names
        cur.execute('''
            SELECT p.*, s.name as student_name 
            FROM placements p 
            JOIN students s ON p.student_id = s.id
            ORDER BY p.id DESC
        ''')
        placements = cur.fetchall()
        cur.close()
        connection.close()
        
        return render_template('students/placements.html', placements=placements)
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error listing placements: {str(e)}')
        flash('An error occurred while loading placements. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/students/<int:student_id>/academic/add', methods=['GET', 'POST'])
@login_required
def add_academic_performance(student_id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    
    try:
        cur = connection.cursor()
        
        # Get student details for verification
        cur.execute('SELECT * FROM students WHERE id = %s', (student_id,))
        student = cur.fetchone()
        
        if not student:
            flash('Student not found', 'error')
            return redirect(url_for('list_students'))
        
        # If teacher, verify department access
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if student['department'] != session['department']:
                flash('You can only manage results for students in your department', 'error')
                return redirect(url_for('list_students'))
        
        if request.method == 'POST':
            try:
                semester = int(request.form['semester'])
                cgpa = float(request.form['cgpa'])
                sgpa = float(request.form['sgpa'])
                backlogs = int(request.form.get('backlogs', 0))
                
                # Validate input values
                if not (1 <= semester <= 8):
                    flash('Invalid semester value', 'error')
                    return redirect(url_for('add_academic_performance', student_id=student_id))
                
                if not (0 <= cgpa <= 10 and 0 <= sgpa <= 10):
                    flash('CGPA and SGPA must be between 0 and 10', 'error')
                    return redirect(url_for('add_academic_performance', student_id=student_id))
                
                if backlogs < 0:
                    flash('Number of backlogs cannot be negative', 'error')
                    return redirect(url_for('add_academic_performance', student_id=student_id))
                
                # Check if result for this semester already exists
                cur.execute('SELECT id FROM academic_performance WHERE student_id = %s AND semester = %s', 
                           (student_id, semester))
                if cur.fetchone():
                    flash(f'Result for semester {semester} already exists', 'error')
                    return redirect(url_for('add_academic_performance', student_id=student_id))
                
                # Handle marksheet upload
                marksheet_path = None
                if 'marksheet' in request.files:
                    file = request.files['marksheet']
                    if file and file.filename:
                        if not allowed_file(file.filename):
                            flash('Only PDF files are allowed for marksheet', 'error')
                            return redirect(url_for('add_academic_performance', student_id=student_id))
                        
                        filename = secure_filename(f"{student_id}_sem{semester}_marksheet.pdf")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        marksheet_path = os.path.join('uploads', filename)
                
                # Insert academic performance
                cur.execute("""
                    INSERT INTO academic_performance 
                    (student_id, semester, cgpa, sgpa, backlogs, marksheet_path)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (student_id, semester, cgpa, sgpa, backlogs, marksheet_path))
                
                connection.commit()
                flash('Academic performance added successfully', 'success')
                return redirect(url_for('view_student', id=student_id))
                
            except ValueError:
                flash('Invalid input values. Please check your entries.', 'error')
                return redirect(url_for('add_academic_performance', student_id=student_id))
            except Exception as e:
                app.logger.error(f'Error adding academic performance: {str(e)}')
                flash('An error occurred while adding the result. Please try again.', 'error')
                return redirect(url_for('add_academic_performance', student_id=student_id))
        
        cur.close()
        connection.close()
        return render_template('students/add_academic.html', student=student)
        
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error in add_academic_performance: {str(e)}')
        flash('An error occurred while processing your request. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))

@app.route('/students/<int:student_id>/academic/<int:academic_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_academic_performance(student_id, academic_id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    
    try:
        cur = connection.cursor()
        
        # Get student details for verification
        cur.execute('SELECT * FROM students WHERE id = %s', (student_id,))
        student = cur.fetchone()
        
        if not student:
            flash('Student not found', 'error')
            return redirect(url_for('list_students'))
        
        # If teacher, verify department access
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if student['department'] != session['department']:
                flash('You can only manage results for students in your department', 'error')
                return redirect(url_for('list_students'))
        
        # Get academic performance details
        cur.execute('SELECT * FROM academic_performance WHERE id = %s AND student_id = %s', 
                   (academic_id, student_id))
        academic = cur.fetchone()
        
        if not academic:
            flash('Academic record not found', 'error')
            return redirect(url_for('view_student', id=student_id))
        
        if request.method == 'POST':
            cgpa = request.form['cgpa']
            sgpa = request.form['sgpa']
            backlogs = request.form.get('backlogs', 0)
            
            # Handle marksheet upload
            marksheet_path = academic['marksheet_path']
            if 'marksheet' in request.files:
                file = request.files['marksheet']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"{student_id}_sem{academic['semester']}_marksheet_updated.pdf")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    marksheet_path = os.path.join('uploads', filename)
            
            # Update academic performance
            cur.execute("""
                UPDATE academic_performance 
                SET cgpa = %s, sgpa = %s, backlogs = %s, marksheet_path = %s
                WHERE id = %s AND student_id = %s
            """, (cgpa, sgpa, backlogs, marksheet_path, academic_id, student_id))
            
            connection.commit()
            flash('Academic performance updated successfully', 'success')
            return redirect(url_for('view_student', id=student_id))
        
        cur.close()
        connection.close()
        return render_template('students/edit_academic.html', student=student, academic=academic)
        
    except Exception as e:
        if connection:
            connection.close()
        app.logger.error(f'Error editing academic performance: {str(e)}')
        flash('An error occurred while editing academic performance. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))

@app.route('/students/<int:student_id>/academic/<int:academic_id>/delete', methods=['POST'])
@login_required
def delete_academic_performance(student_id, academic_id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    
    try:
        cur = connection.cursor()
        
        # Get student details for verification
        cur.execute('SELECT * FROM students WHERE id = %s', (student_id,))
        student = cur.fetchone()
        
        if not student:
            flash('Student not found', 'error')
            return redirect(url_for('list_students'))
        
        # If teacher, verify department access
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if student['department'] != session['department']:
                flash('You can only manage results for students in your department', 'error')
                return redirect(url_for('list_students'))
        
        # Delete the academic performance record
        cur.execute('DELETE FROM academic_performance WHERE id = %s AND student_id = %s', 
                   (academic_id, student_id))
        connection.commit()
        
        flash('Academic performance record deleted successfully', 'success')
        
    except Exception as e:
        app.logger.error(f'Error deleting academic performance: {str(e)}')
        flash('An error occurred while deleting academic performance. Please try again.', 'error')
    
    finally:
        if connection:
            connection.close()
    
    return redirect(url_for('view_student', id=student_id))

@app.route('/students/<int:student_id>/placement/<int:placement_id>/delete', methods=['POST'])
@login_required
def delete_placement(student_id, placement_id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    
    try:
        cur = connection.cursor()
        
        # Check if placement exists and belongs to the student
        cur.execute('''
            SELECT p.*, s.department 
            FROM placements p 
            JOIN students s ON p.student_id = s.id 
            WHERE p.id = %s AND p.student_id = %s
        ''', (placement_id, student_id))
        placement = cur.fetchone()
        
        if not placement:
            flash('Placement record not found', 'error')
            return redirect(url_for('view_student', id=student_id))
        
        # Check if teacher has permission
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if placement['department'] != session['department']:
                flash('You can only delete placement records for students in your department', 'error')
                return redirect(url_for('view_student', id=student_id))
        
        # Delete associated files
        if placement['joining_letter_path']:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], placement['joining_letter_path']))
            except OSError:
                pass
        
        if placement['salary_slip_path']:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], placement['salary_slip_path']))
            except OSError:
                pass
        
        # Delete placement record
        cur.execute('DELETE FROM placements WHERE id = %s', (placement_id,))
        connection.commit()
        
        flash('Placement record deleted successfully', 'success')
        return redirect(url_for('view_student', id=student_id))
        
    except Exception as e:
        if connection:
            connection.rollback()
        app.logger.error(f'Error deleting placement: {str(e)}')
        flash('An error occurred while deleting the placement record. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    finally:
        if connection:
            connection.close()

@app.route('/students/<int:student_id>/internship/<int:internship_id>/delete', methods=['POST'])
@login_required
def delete_internship(student_id, internship_id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    
    try:
        cur = connection.cursor()
        
        # Check if internship exists and belongs to the student
        cur.execute('''
            SELECT i.*, s.department 
            FROM internships i 
            JOIN students s ON i.student_id = s.id 
            WHERE i.id = %s AND i.student_id = %s
        ''', (internship_id, student_id))
        internship = cur.fetchone()
        
        if not internship:
            flash('Internship record not found', 'error')
            return redirect(url_for('view_student', id=student_id))
        
        # Check if teacher has permission
        if session['role'] == 'teacher' and session['department'] != 'ALL':
            if internship['department'] != session['department']:
                flash('You can only delete internship records for students in your department', 'error')
                return redirect(url_for('view_student', id=student_id))
        
        # Delete associated files
        if internship['completion_certificate_path']:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], internship['completion_certificate_path']))
            except OSError:
                pass
        
        # Delete internship record
        cur.execute('DELETE FROM internships WHERE id = %s', (internship_id,))
        connection.commit()
        
        flash('Internship record deleted successfully', 'success')
        return redirect(url_for('view_student', id=student_id))
        
    except Exception as e:
        if connection:
            connection.rollback()
        app.logger.error(f'Error deleting internship: {str(e)}')
        flash('An error occurred while deleting the internship record. Please try again.', 'error')
        return redirect(url_for('view_student', id=student_id))
    finally:
        if connection:
            connection.close()

@app.route('/students/search')
@login_required
def search_students():
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('list_students'))
    
    try:
        search_query = request.args.get('query', '').strip()
        year_filter = request.args.get('year', '')
        department_filter = request.args.get('department', '')
        
        cur = connection.cursor()
        
        # Build the query based on filters
        query = """
            SELECT s.*, c.mobile_number, c.email, c.father_name, c.father_mobile, c.mother_name, c.mother_mobile,
                   c.student_photo, c.aadhar_card, c.pan_card, c.other_documents
            FROM students s
            LEFT JOIN contact_info c ON s.id = c.student_id
            WHERE 1=1
        """
        params = []
        
        # Add search query condition
        if search_query:
            query += """
                AND (s.name LIKE %s OR s.roll_no LIKE %s OR s.registration_no LIKE %s)
            """
            search_param = f'%{search_query}%'
            params.extend([search_param, search_param, search_param])
        
        # Add year filter condition
        if year_filter:
            if year_filter.startswith('batch_'):
                # Filter by joining year
                joining_year = year_filter.split('_')[1]
                query += " AND s.joining_year = %s"
                params.append(joining_year)
            elif year_filter.startswith('sem_'):
                # Filter by current semester
                semester = year_filter.split('_')[1]
                query += " AND s.current_semester = %s"
                params.append(semester)
        
        # Add department filter condition
        if department_filter and department_filter != 'ALL':
            query += " AND s.department = %s"
            params.append(department_filter)
        
        # Add ordering
        query += " ORDER BY s.roll_no"
        
        # Execute query
        cur.execute(query, params)
        students = cur.fetchall()
        
        # Process the results to calculate academic details
        processed_students = []
        current_year = datetime.now().year
        current_month = datetime.now().month
        academic_year = current_year if current_month >= 7 else current_year - 1
        
        for student in students:
            student_dict = dict(student)
            
            # Calculate academic details
            if student_dict['is_lateral']:
                session_end_year = student_dict['joining_year'] + 3
                years_passed = academic_year - student_dict['joining_year']
                
                # For lateral entry students (3-year program)
                if years_passed < 0:
                    current_semester = 3  # Start from 3rd semester
                    year_of_study = "2nd Year"
                else:
                    if years_passed == 0:  # First year (2022-2023)
                        if current_month >= 7 and current_month <= 12:
                            current_semester = 3  # Odd semester
                        else:
                            current_semester = 4  # Even semester
                        year_of_study = "2nd Year"
                    elif years_passed == 1:  # Second year (2023-2024)
                        if current_month >= 7 and current_month <= 12:
                            current_semester = 5  # Odd semester
                        else:
                            current_semester = 6  # Even semester
                        year_of_study = "3rd Year"
                    elif years_passed == 2:  # Third year (2024-2025)
                        if current_month >= 7 and current_month <= 12:
                            current_semester = 7  # Odd semester
                        else:
                            current_semester = 8  # Even semester
                        year_of_study = "4th Year"
                    else:  # Beyond third year
                        current_semester = 8  # Final semester
                        year_of_study = "4th Year"
            else:
                session_end_year = student_dict['joining_year'] + 4
                years_passed = academic_year - student_dict['joining_year']
                
                if years_passed < 0:
                    current_semester = 1
                    year_of_study = "1st Year"
                else:
                    if years_passed == 0:
                        if current_month >= 7 and current_month <= 12:
                            current_semester = 1
                        else:
                            current_semester = 2
                        year_of_study = "1st Year"
                    elif years_passed == 1:
                        if current_month >= 7 and current_month <= 12:
                            current_semester = 3
                        else:
                            current_semester = 4
                        year_of_study = "2nd Year"
                    elif years_passed == 2:
                        if current_month >= 7 and current_month <= 12:
                            current_semester = 5
                        else:
                            current_semester = 6
                        year_of_study = "3rd Year"
                    else:
                        if current_month >= 7 and current_month <= 12:
                            current_semester = 7
                        else:
                            current_semester = 8
                        year_of_study = "4th Year"
            
            # Update passout status based on student type and current year
            if student_dict['is_lateral']:
                if current_year >= session_end_year:
                    passout_status = "Passed Out"
                elif current_semester == 7:
                    passout_status = "Final Year (Semester 7/8)"
                elif current_semester == 6:
                    passout_status = "Final Year (Semester 6/8)"
                elif current_semester == 5:
                    passout_status = "3rd Year (Semester 5/8)"
                elif current_semester == 4:
                    passout_status = "2nd Year (Semester 4/8)"
                else:
                    passout_status = "2nd Year (Semester 3/8)"
            else:
                if current_year >= session_end_year:
                    passout_status = "Passed Out"
                elif current_semester == 7:
                    passout_status = "Final Year (Semester 7/8)"
                elif current_semester == 6:
                    passout_status = "Final Year (Semester 6/8)"
                elif current_semester == 5:
                    passout_status = "3rd Year (Semester 5/8)"
                elif current_semester == 4:
                    passout_status = "2nd Year (Semester 4/8)"
                else:
                    passout_status = "2nd Year (Semester 3/8)"
            
            # Add calculated fields to student dictionary
            student_dict['year_of_study'] = year_of_study
            student_dict['session'] = f"{student_dict['joining_year']}-{session_end_year}"
            student_dict['passout_status'] = passout_status
            
            processed_students.append(student_dict)
        
        cur.close()
        connection.close()
        
        # Return only the table content
        return render_template('students/table_content.html', 
                             students=processed_students)
        
    except Exception as e:
        if connection:
            connection.close()
        logger.error(f"Error searching students: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'An error occurred while searching students'}), 500

@app.route('/students/<int:id>/export/pdf')
@login_required
def export_student_pdf(id):
    connection = get_db_connection()
    if not connection:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('list_students'))
    
    try:
        cur = connection.cursor()
        
        # Get student details with contact information
        cur.execute("""
            SELECT s.*, c.*
            FROM students s
            LEFT JOIN contact_info c ON s.id = c.student_id
            WHERE s.id = %s
        """, (id,))
        student = cur.fetchone()
        
        if not student:
            flash('Student not found', 'error')
            return redirect(url_for('list_students'))
        
        # Get academic performance
        cur.execute('SELECT * FROM academic_performance WHERE student_id = %s ORDER BY semester', (id,))
        academics = cur.fetchall()
        
        # Get placement details
        cur.execute('SELECT * FROM placements WHERE student_id = %s', (id,))
        placement = cur.fetchone()
        
        # Get all internship details
        cur.execute('SELECT * FROM internships WHERE student_id = %s ORDER BY id DESC', (id,))
        internships = cur.fetchall()
        
        # Create PDF
        # Lazy import ReportLab here so the app can start even if reportlab isn't installed
        try:
            import reportlab.lib
            import reportlab.lib.pagesizes
            import reportlab.platypus
            import reportlab.lib.styles
            import reportlab.lib.units
        except ImportError:
            flash('PDF feature requires ReportLab. Install with: pip install reportlab', 'error')
            return redirect(url_for('view_student', id=id))

        buffer = BytesIO()
        doc = reportlab.platypus.SimpleDocTemplate(buffer, pagesize=reportlab.lib.pagesizes.letter, rightMargin=30, leftMargin=30)
        styles = reportlab.lib.styles.getSampleStyleSheet()
        
        # Custom styles
        title_style = reportlab.lib.styles.ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=0  # Left alignment
        )
        
        section_style = reportlab.lib.styles.ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=reportlab.lib.colors.HexColor('#2c3e50')
        )
        
        normal_style = reportlab.lib.styles.ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=6
        )
        
        story = []
        
        # Create header table
        header_data = []
        
        # Left column content (name and contact info)
        left_column = []
        left_column.append(reportlab.platypus.Paragraph(f"{student['name']}", title_style))
        left_column.append(reportlab.platypus.Spacer(1, 10))
        
        # Contact Information
        contact_info = []
        if student.get('mobile_number'):
            contact_info.append(f"📱 {student['mobile_number']}")
        if student.get('email'):
            contact_info.append(f"✉️ {student['email']}")
        if student.get('address'):
            contact_info.append(f"📍 {student['address']}")
        
        contact_text = " | ".join(contact_info)
        left_column.append(reportlab.platypus.Paragraph(contact_text, normal_style))
        
        # Right column content (photo)
        right_column = []
        if student.get('student_photo'):
            try:
                img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', student['student_photo'])
                if os.path.exists(img_path):
                    img = reportlab.platypus.Image(img_path)
                    img.drawWidth = 1.5 * reportlab.lib.units.inch
                    img.drawHeight = 1.5 * reportlab.lib.units.inch
                    right_column.append(img)
            except Exception as e:
                app.logger.error(f"Error loading photo: {str(e)}")
                app.logger.error(traceback.format_exc())
        
        # Create header table
        header_table = reportlab.platypus.Table([
            [left_column, right_column]
        ], colWidths=[4*reportlab.lib.units.inch, 2*reportlab.lib.units.inch])
        
        # Style header table
        header_table.setStyle(reportlab.platypus.TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (0, 0), 0),
            ('RIGHTPADDING', (1, 0), (1, 0), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        story.append(header_table)
        story.append(reportlab.platypus.Spacer(1, 20))
        
        # Education
        story.append(reportlab.platypus.Paragraph("EDUCATION", section_style))
        story.append(reportlab.platypus.Paragraph(f"Bachelor of Technology in {student['department']}", normal_style))
        story.append(reportlab.platypus.Paragraph(f"Roll Number: {student['roll_no']} | Registration Number: {student['registration_no']}", normal_style))
        
        # Calculate current year of study and session
        current_year = datetime.now().year
        years_passed = current_year - student['joining_year']
        
        if student['is_lateral']:
            year_of_study = "2nd Year" if years_passed == 0 else \
                           "3rd Year" if years_passed == 1 else \
                           "4th Year"
            # For lateral entry students, curriculum is 3 years
            session_end_year = student['joining_year'] + 3
            # Check passout status for lateral entry students
            passout_status = "Passed Out" if student['current_semester'] >= 6 else f"In Progress (Semester {student['current_semester']}/6)"
        else:
            year_of_study = "1st Year" if years_passed == 0 else \
                           "2nd Year" if years_passed == 1 else \
                           "3rd Year" if years_passed == 2 else \
                           "4th Year"
            # For regular students, curriculum is 4 years
            session_end_year = student['joining_year'] + 4
            # Check passout status for regular students
            passout_status = "Passed Out" if student['current_semester'] >= 8 else f"In Progress (Semester {student['current_semester']}/8)"
        
        story.append(reportlab.platypus.Paragraph(f"Year: {year_of_study}", normal_style))
        story.append(reportlab.platypus.Paragraph(f"Session: {student['joining_year']}-{session_end_year}", normal_style))
        story.append(reportlab.platypus.Paragraph(f"Status: {passout_status}", normal_style))
        story.append(reportlab.platypus.Spacer(1, 10))
        
        # Academic Performance
        if academics:
            story.append(reportlab.platypus.Paragraph("ACADEMIC PERFORMANCE", section_style))
            academic_data = [['Semester', 'CGPA', 'SGPA', 'Backlogs']]
            for acad in academics:
                academic_data.append([
                    str(acad['semester']),
                    str(acad['cgpa']),
                    str(acad['sgpa']),
                    str(acad['backlogs'])
                ])
            t = reportlab.platypus.Table(academic_data, colWidths=[1.2*reportlab.lib.units.inch]*4)
            t.setStyle(reportlab.platypus.TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, reportlab.lib.colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), reportlab.lib.colors.HexColor('#f8f9fa')),
                ('TEXTCOLOR', (0, 0), (-1, 0), reportlab.lib.colors.HexColor('#2c3e50')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('TOPPADDING', (0, 0), (-1, 0), 12),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(t)
            story.append(reportlab.platypus.Spacer(1, 20))
        
        # Work Experience (Placement)
        if placement:
            story.append(reportlab.platypus.Paragraph("WORK EXPERIENCE", section_style))
            story.append(reportlab.platypus.Paragraph(f"Company: {placement['company']}", normal_style))
            story.append(reportlab.platypus.Paragraph(f"Position: {placement['package']} LPA", normal_style))
            story.append(reportlab.platypus.Paragraph(f"Location: {placement['location']}", normal_style))
            story.append(reportlab.platypus.Spacer(1, 10))
        
        # Internship Experience
        if internships:
            story.append(reportlab.platypus.Paragraph("INTERNSHIP EXPERIENCE", section_style))
            internship_data = [['Company', 'Duration', 'Domain', 'Status']]
            for internship in internships:
                internship_data.append([
                    internship['company'],
                    internship['duration'],
                    internship['domain'],
                    internship['status'].upper()
                ])
            t = reportlab.platypus.Table(internship_data, colWidths=[1.5*reportlab.lib.units.inch]*4)
            t.setStyle(reportlab.platypus.TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, reportlab.lib.colors.black),
                ('BACKGROUND', (0, 0), (-1, 0), reportlab.lib.colors.HexColor('#f8f9fa')),
                ('TEXTCOLOR', (0, 0), (-1, 0), reportlab.lib.colors.HexColor('#2c3e50')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('TOPPADDING', (0, 0), (-1, 0), 12),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                # Add background color for status column based on status
                ('BACKGROUND', (3, 1), (3, -1), reportlab.lib.colors.HexColor('#e9ecef')),
                ('TEXTCOLOR', (3, 1), (3, -1), reportlab.lib.colors.HexColor('#2c3e50')),
            ]))
            story.append(t)
            story.append(reportlab.platypus.Spacer(1, 20))
        
        # Personal Information
        story.append(reportlab.platypus.Paragraph("PERSONAL INFORMATION", section_style))
        personal_info = []
        if student.get('date_of_birth'):
            personal_info.append(f"Date of Birth: {student['date_of_birth']}")
        if student.get('blood_group'):
            personal_info.append(f"Blood Group: {student['blood_group']}")
        
        for info in personal_info:
            story.append(reportlab.platypus.Paragraph(info, normal_style))
        
        # Parent Information
        if student.get('father_name') or student.get('mother_name'):
            story.append(reportlab.platypus.Spacer(1, 10))
            story.append(reportlab.platypus.Paragraph("PARENT INFORMATION", section_style))
            if student.get('father_name'):
                story.append(reportlab.platypus.Paragraph(f"Father's Name: {student['father_name']}", normal_style))
                if student.get('father_mobile'):
                    story.append(reportlab.platypus.Paragraph(f"Father's Contact: {student['father_mobile']}", normal_style))
            if student.get('mother_name'):
                story.append(reportlab.platypus.Paragraph(f"Mother's Name: {student['mother_name']}", normal_style))
                if student.get('mother_mobile'):
                    story.append(reportlab.platypus.Paragraph(f"Mother's Contact: {student['mother_mobile']}", normal_style))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{student['name']}_CV.pdf"
        )
        
    except Exception as e:
        app.logger.error(f'Error generating PDF: {str(e)}')
        app.logger.error(traceback.format_exc())
        flash('An error occurred while generating the PDF. Please try again.', 'error')
        return redirect(url_for('view_student', id=id))
    finally:
        if connection:
            connection.close()

if __name__ == '__main__':
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    app.run(debug=True, port=5001) 