from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Ganti dengan kunci rahasiamu

# Fungsi untuk membuat koneksi database SQLite
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inisialisasi database
def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        email TEXT NOT NULL,
                        password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

# Halaman Home
@app.route('/')
def home():
    return render_template('homepage.html')

# Halaman Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validasi form
        if not username or not email or not password or not confirm_password:
            flash('Semua kolom harus diisi!', 'error')
        elif password != confirm_password:
            flash('Password tidak cocok!', 'error')
        else:
            # Hash password
            hashed_password = generate_password_hash(password, method='sha256')
            
            # Simpan ke database
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, hashed_password))
            conn.commit()
            conn.close()

            flash('Registrasi berhasil, silakan login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

# Halaman Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Cari user berdasarkan email
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Selamat datang, {user["username"]}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login gagal. Periksa kembali email atau password.', 'error')

    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()  # Inisialisasi database saat aplikasi dijalankan
    app.run(debug=True)
