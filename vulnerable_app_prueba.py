ffrom flask import Flask, request, render_template, session, redirect, url_for, flash
from markupsafe import escape
import bcrypt
import mysql.connector
import os

app = Flask(__name__)
app.secret_key = "UNA_CLAVE_SECRETA_FIJA_Y_SEGURA"  

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="prueba"
    )

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


@app.route('/')
def index():
    return 'Welcome to the secure Task Manager Application!'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and check_password(password, user['password']):
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))

        return "Invalid credentials!"

    return render_template("login.html")


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, task FROM tasks WHERE user_id = %s", (session['user_id'],))
    tasks = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("dashboard.html", tasks=tasks)


@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = escape(request.form['task'])  

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO tasks (user_id, task) VALUES (%s, %s)", (session['user_id'], task))
    conn.commit()

    cursor.close()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    
    cursor.execute("SELECT user_id FROM tasks WHERE id = %s", (task_id,))
    task = cursor.fetchone()

    if not task or task['user_id'] != session['user_id']:
        return "Unauthorized", 403

    cursor.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
    conn.commit()

    cursor.close()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized", 403

    return "Welcome to the admin panel!"


if __name__ == "__main__":
    app.run(debug=False)
