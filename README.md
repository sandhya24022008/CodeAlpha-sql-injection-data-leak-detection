# CodeAlpha-sql-injection-data-leak-detection
Project Overview

The SQL Injection Leak Detection System is a Python-based security project designed to identify suspicious SQL injection patterns and protect user data.

It uses parameterized SQL queries, password hashing, AES-256 encryption, and security event logging to improve database security.

Objectives

- Detect common SQL injection patterns.
- Prevent SQL injection using parameterized queries.
- Store passwords as secure password hashes.
- Encrypt sensitive data using AES-256-GCM.
- Record suspicious activities in a security log.
- Demonstrate secure database operations using SQLite.

Technologies Used

- Python
- Flask
- SQLite
- AES-256-GCM Encryption
- Werkzeug Password Hashing
- Regular Expressions
- REST API

Project Structure

sql-injection-leak-detection/
│
├── app.py
├── requirements.txt
├── README.md
└── .gitignore

Features

1. SQL Injection Detection

Checks user input for patterns commonly associated with SQL injection attempts.

2. SQL Injection Prevention

Uses parameterized SQL queries to prevent user input from being executed as SQL commands.

3. Password Security

Uses password hashing instead of storing plain-text passwords.

4. Data Encryption

Uses AES-256-GCM to encrypt sensitive information before storing it in the database.

5. Security Logging

Records registration events, failed logins, successful logins, and suspicious input indicators.

Installation

Install the required packages:

pip install -r requirements.txt

Generate a secure AES key:

python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"

Set the generated key as the "AES_SECRET_KEY" environment variable. Keep it private and do not upload it to GitHub.

Run the application:

python app.py

The local server runs at:

"http://127.0.0.1:5000"

API Endpoints

Method| Endpoint| Purpose
GET| "/"| View project information
GET| "/health"| Check server status
POST| "/register"| Register a user
POST| "/login"| Verify login credentials
GET| "/my-secret/<username>"| Demonstration of encrypted data retrieval

Registration and login endpoints accept JSON requests.

Example registration data:

{
  "username": "student1",
  "password": "ExamplePass123!",
  "secret_data": "Demo sensitive information"
}

Testing

Test the project with normal login inputs and harmless SQL injection test strings in your own local environment.

Check whether suspicious inputs are logged and whether parameterized queries prevent them from changing the SQL query structure.

Security Note

This is an educational prototype, not a production-ready cloud security system. Production deployment requires authentication and authorization for private data, rate limiting, HTTPS, secure key management, and additional security testing.

Conclusion

This project demonstrates basic techniques for identifying suspicious SQL injection patterns and protecting user credentials and sensitive information using secure database queries, password hashing, encryption, and event logging.
