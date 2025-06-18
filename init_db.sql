-- Create the database
CREATE DATABASE IF NOT EXISTS student_records;
USE student_records;

-- Users table for admin and teacher accounts
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'teacher') NOT NULL,
    department VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Students table for storing basic student information
CREATE TABLE IF NOT EXISTS students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    roll_no VARCHAR(20) UNIQUE NOT NULL,
    registration_no VARCHAR(20) UNIQUE NOT NULL,
    joining_year INT NOT NULL,
    current_semester INT NOT NULL,
    is_lateral BOOLEAN DEFAULT FALSE,
    department VARCHAR(50) NOT NULL,
    address TEXT,
    date_of_birth DATE,
    blood_group VARCHAR(5),
    student_photo_path VARCHAR(255),
    aadhar_card_path VARCHAR(255),
    pan_card_path VARCHAR(255),
    other_documents_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Student Contact Information table
CREATE TABLE IF NOT EXISTS student_contacts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    mobile_no VARCHAR(15),
    email_id VARCHAR(100),
    father_name VARCHAR(100),
    father_mobile VARCHAR(15),
    mother_name VARCHAR(100),
    mother_mobile VARCHAR(15),
    parent_email VARCHAR(100),
    parent_occupation VARCHAR(100),
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

-- Parent/Guardian Information table
CREATE TABLE IF NOT EXISTS parent_guardians (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    relation ENUM('father', 'mother', 'guardian') NOT NULL,
    name VARCHAR(100) NOT NULL,
    mobile_no VARCHAR(15),
    email_id VARCHAR(100),
    occupation VARCHAR(100),
    address TEXT,
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

-- Internships table for tracking student internships
CREATE TABLE IF NOT EXISTS internships (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT,
    company VARCHAR(100) NOT NULL,
    duration VARCHAR(50) NOT NULL,
    domain VARCHAR(100) NOT NULL,
    completion_certificate_path VARCHAR(255),
    status ENUM('ongoing', 'completed') DEFAULT 'ongoing',
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

-- Placements table for tracking student job placements
CREATE TABLE IF NOT EXISTS placements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT,
    company VARCHAR(100) NOT NULL,
    package DECIMAL(10,2) NOT NULL,
    location VARCHAR(100) NOT NULL,
    joining_letter_path VARCHAR(255),
    salary_slip_path VARCHAR(255),
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

-- Academic Performance table for storing semester-wise results
CREATE TABLE IF NOT EXISTS academic_performance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT,
    semester INT NOT NULL,
    cgpa DECIMAL(4,2) NOT NULL,
    sgpa DECIMAL(4,2) NOT NULL,
    backlogs INT DEFAULT 0,
    marksheet_path VARCHAR(255),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

-- Insert default admin account (password: admin123)
INSERT IGNORE INTO users (username, password, role) 
VALUES ('admin', SHA2('admin123', 256), 'admin'); 