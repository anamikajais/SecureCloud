from flask import Flask, render_template, request, redirect, session
import bcrypt

from detector import is_malicious
from database import *
from encryption import encrypt_data

app = Flask(__name__)

# Secret key for session management
app.secret_key = "supersecretkey"


# ===================== HOME =====================
@app.route('/')
def home():
    return render_template("login.html")


# ===================== REGISTER =====================
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    # Detect malicious input
    if is_malicious(username) or is_malicious(password):
        add_log("SQL_ATTACK")  # ✅ categorized log
        return "⚠️ Malicious Input Detected!"

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    add_user(username, hashed_password.decode())

    add_log("NORMAL")  # ✅ normal event

    return "✅ User Registered Successfully!"


# ===================== LOGIN =====================
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Detect SQL Injection
    if is_malicious(username) or is_malicious(password):
        add_log("SQL_ATTACK")
        return "⚠️ Malicious Input Detected!"

    stored_password = get_user(username)

    if stored_password:
        if bcrypt.checkpw(password.encode(), stored_password.encode()):
            session['user'] = username
            add_log("NORMAL")
            return redirect('/dashboard')

    add_log("FAILED_LOGIN")  # ✅ failed login tracking
    return "❌ Invalid Login"


# ===================== DASHBOARD =====================
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    
    return render_template("dashboard.html", user=session['user'])


# ===================== SUBMIT DATA =====================
@app.route('/submit', methods=['POST'])
def submit():
    if 'user' not in session:
        return redirect('/')

    data = request.form['data']

    # Detect malicious input
    if is_malicious(data):
        add_log("MALICIOUS_DATA")  # ✅ categorized attack
        return "⚠️ Attack Detected!"

    # Encrypt data
    encrypted_data = encrypt_data(data)

    add_log("NORMAL")

    return "🔐 Data Encrypted Successfully!"


# ===================== ADMIN PANEL =====================
@app.route('/admin')
def admin():
    logs = get_logs()

    # Count attack categories
    sql_attacks = logs.count("SQL_ATTACK")
    failed_logins = logs.count("FAILED_LOGIN")
    malicious_data = logs.count("MALICIOUS_DATA")

    return render_template(
        "admin.html",
        logs=logs,
        sql=sql_attacks,
        failed=failed_logins,
        malicious=malicious_data
    )


# ===================== LOGOUT =====================
@app.route('/logout')
def logout():
    session.pop('user', None)
    add_log("NORMAL")
    return redirect('/')


# ===================== RUN APP =====================
if __name__ == '__main__':
    app.run(debug=True)