# Student Records Management System

A comprehensive web-based system for managing student records, internships, and placements.

## Features

- Role-based authentication (Admin/Teacher)
- Student record management
- Document upload system (PDF)
- Internship and placement tracking
- Academic performance monitoring
- Report generation (PDF/CSV)

## Setup Instructions

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up MySQL database:
```sql
CREATE DATABASE student_records;
```

4. Configure environment variables:
Create a `.env` file with:
```
DB_HOST=localhost
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=student_records
SECRET_KEY=your_secret_key
```

5. Initialize the database:
```bash
python init_db.py
```

6. Run the application:
```bash
python app.py
```

## Project Structure

```
student_records/
├── static/
│   ├── css/
│   ├── js/
│   └── uploads/
├── templates/
│   ├── admin/
│   ├── teacher/
│   └── auth/
├── app.py
├── init_db.py
├── config.py
└── requirements.txt
```

## Tech Stack

- Frontend: HTML, CSS, JavaScript
- Backend: Python (Flask)
- Database: MySQL
- PDF Generation: ReportLab 