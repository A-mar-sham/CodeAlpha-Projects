import sqlite3
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "super_secret_dev_key_123!" # Used for session management

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Connect to the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Query to check if the user exists
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return "Login successful!"
    else:
        return "Invalid credentials."