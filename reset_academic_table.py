import mysql.connector
from config import Config

def reset_academic_table():
    try:
        conn = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB
        )
        cursor = conn.cursor()

        # Drop the existing table
        cursor.execute("DROP TABLE IF EXISTS academic_performance")
        
        # Create Academic Performance table with new structure
        cursor.execute("""
            CREATE TABLE academic_performance (
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

        conn.commit()
        print("Academic performance table reset successfully!")

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == "__main__":
    reset_academic_table() 