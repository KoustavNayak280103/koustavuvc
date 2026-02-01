from flask import Flask, render_template, request, redirect, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "ultraviolet_secure_key_2026"


# ---------------- DATABASE ----------------
def get_db():
    return sqlite3.connect("database.db")


# ---------------- SECURITY ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------- AUTH DECORATORS ----------------
def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return "Unauthorized Access", 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def admin_required(f):
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            return "Forbidden: Admin access required", 403
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


# ---------------- ROUTES ----------------
@app.route('/')
def home():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = hash_password(request.form['password'])
        role = request.form['role']

        db = get_db()
        db.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (username, email, password, role)
        )
        db.commit()

        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = hash_password(request.form['password'])

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email=? AND password=?",
            (email, password)
        ).fetchone()

        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[4]
            return redirect('/dashboard')

        return "Invalid Credentials"

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template(
        'dashboard.html',
        user=session['username'],
        role=session['role']
    )


@app.route('/admin')
@login_required
@admin_required
def admin():
    db = get_db()
    users = db.execute(
        "SELECT id, username, email, role FROM users"
    ).fetchall()

    return render_template('admin.html', users=users)


# -------- ADMIN DELETE USER --------
@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):

    if user_id == session.get('user_id'):
        return "Admin cannot delete own account", 403

    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    return redirect('/admin')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == "__main__":
    app.run(debug=True)
