import mysql.connector
from config import Config
import hashlib

def create_tables():
    try:
        conn = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD
        )
        cursor = conn.cursor()

        # Create database if not exists
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {Config.MYSQL_DB}")
        cursor.execute(f"USE {Config.MYSQL_DB}")

        # Disable foreign key checks
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0")

        # Drop existing tables to ensure clean state
        cursor.execute("DROP TABLE IF EXISTS academic_performance")
        cursor.execute("DROP TABLE IF EXISTS placements")
        cursor.execute("DROP TABLE IF EXISTS internships")
        cursor.execute("DROP TABLE IF EXISTS contact_info")
        cursor.execute("DROP TABLE IF EXISTS student_contacts")  # Drop old table name
        cursor.execute("DROP TABLE IF EXISTS students")
        cursor.execute("DROP TABLE IF EXISTS users")

        # Re-enable foreign key checks
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1")

        # Create Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('admin', 'teacher') NOT NULL,
                department VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create Students table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                roll_no VARCHAR(20) UNIQUE NOT NULL,
                registration_no VARCHAR(20) UNIQUE NOT NULL,
                joining_year INT NOT NULL,
                current_semester INT NOT NULL,
                is_lateral BOOLEAN DEFAULT FALSE,
                department VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)

        # Create Contact Info table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contact_info (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT NOT NULL,
                mobile_number VARCHAR(15),
                email VARCHAR(100),
                address TEXT,
                date_of_birth DATE,
                blood_group VARCHAR(5),
                father_name VARCHAR(100),
                father_mobile VARCHAR(15),
                mother_name VARCHAR(100),
                mother_mobile VARCHAR(15),
                student_photo VARCHAR(255),
                aadhar_card VARCHAR(255),
                pan_card VARCHAR(255),
                other_documents TEXT,
                FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
            )
        """)

        # Create Internships table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS internships (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT,
                company VARCHAR(100) NOT NULL,
                duration VARCHAR(50) NOT NULL,
                domain VARCHAR(100) NOT NULL,
                completion_certificate_path VARCHAR(255),
                status ENUM('ongoing', 'completed') DEFAULT 'ongoing',
                FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
            )
        """)

        # Create Placements table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS placements (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT,
                company VARCHAR(100) NOT NULL,
                package DECIMAL(10,2) NOT NULL,
                location VARCHAR(100) NOT NULL,
                joining_letter_path VARCHAR(255),
                salary_slip_path VARCHAR(255),
                FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
            )
        """)

        # Create Academic Performance table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS academic_performance (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT NOT NULL,
                semester INT NOT NULL,
                cgpa DECIMAL(4,2) NOT NULL,
                sgpa DECIMAL(4,2) NOT NULL,
                backlogs INT DEFAULT 0,
                marksheet_path VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
                UNIQUE KEY unique_student_semester (student_id, semester)
            )
        """)

        # Create default admin account
        admin_password = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("""
            INSERT IGNORE INTO users (username, password, role)
            VALUES ('admin', %s, 'admin')
        """, (admin_password,))

        conn.commit()
        print("Database initialized successfully!")
        print("Default admin credentials:")
        print("Username: admin")
        print("Password: admin123")

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == "__main__":
    create_tables() 