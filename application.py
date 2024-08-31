import secrets
import string
import datetime
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure random key

def generate_unique_url():
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))

def generate_key():
    return Fernet.generate_key()

# Load the key
key = generate_key()  # In production, load this from a secure location

def encrypt_password(password):
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS stored_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id))''')

    # Create pushed_passwords table with user_id foreign key
    c.execute('''CREATE TABLE IF NOT EXISTS pushed_passwords
                 (url TEXT PRIMARY KEY,
                  password TEXT,
                  expiration TEXT,
                  max_views INTEGER,
                  current_views INTEGER,
                  user_id INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')

    conn.commit()
    conn.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            return "Username and password are required", 400
        
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists", 400
        conn.close()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    username = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            error = "Username and password are required"
        else:
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            conn.close()
            
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                return redirect(url_for('home'))
            else:
                error = "Invalid username or password"
    
    return render_template('login.html', error=error, username=username)



@app.route('/', methods=['GET', 'POST'])
def home():
    login_error = None
    username = None

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'Push Password':
            # Handle password pushing (unchanged)
            password = request.form['password']
            expiration_hours = int(request.form['expiration'])
            max_views = int(request.form['max_views'])
            url = generate_unique_url()

            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute('''INSERT INTO pushed_passwords 
                         (url, password, expiration, max_views, current_views, user_id) 
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                      (url, password, datetime.datetime.now() + datetime.timedelta(hours=expiration_hours), 
                       max_views, 0, session.get('user_id')))
            conn.commit()
            conn.close()

            return redirect(url_for('password_created', url=url))
        
        elif action == 'Login':
            # Handle login
            username = request.form['username']
            password = request.form['password']
            
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            conn.close()
            
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                flash('Logged in successfully!', 'success')
                return redirect(url_for('home'))
            else:
                login_error = 'Invalid username or password'

    return render_template('home.html', logged_in=('user_id' in session), login_error=login_error, username=username)

@app.route('/created/<url>')
def password_created(url):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('SELECT user_id FROM pushed_passwords WHERE url = ?', (url,))
    result = c.fetchone()
    conn.close()

    is_owner = result and result[0] == session.get('user_id')
    
    return render_template('created.html', url=url, is_owner=is_owner)

@app.route('/get/<url>', methods=['GET'])
def get_password(url):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('SELECT password, expiration, max_views, current_views FROM pushed_passwords WHERE url = ?', (url,))
    result = c.fetchone()

    if result and datetime.datetime.now() < datetime.datetime.fromisoformat(result[1]):
        password, expiration, max_views, current_views = result
        if current_views < max_views:
            c.execute('UPDATE pushed_passwords SET current_views = current_views + 1 WHERE url = ?', (url,))
            conn.commit()
            conn.close()
            return render_template('password.html', password=password)
        else:
            c.execute('DELETE FROM pushed_passwords WHERE url = ?', (url,))
            conn.commit()
            conn.close()
            return "Password has reached maximum views and has been deleted.", 404
    else:
        c.execute('DELETE FROM pushed_passwords WHERE url = ?', (url,))
        conn.commit()
        conn.close()
        return "Password not found or expired", 404

@app.route('/my_passwords')
def my_passwords():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('SELECT url, password, expiration, max_views, current_views FROM pushed_passwords WHERE user_id = ?', (session['user_id'],))
    passwords = c.fetchall()
    conn.close()

    return render_template('my_passwords.html', passwords=passwords)

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    website = request.form['website']
    username = request.form['username']
    password = request.form['password']
    notes = request.form['notes']
    
    encrypted_password = encrypt_password(password)
    
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('INSERT INTO stored_passwords (user_id, website, username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)',
              (session['user_id'], website, username, encrypted_password, notes))
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_passwords'))

@app.route('/view_passwords')
def view_passwords():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('SELECT id, website, username, encrypted_password, notes FROM stored_passwords WHERE user_id = ?', (session['user_id'],))
    passwords = c.fetchall()
    conn.close()
    
    decrypted_passwords = [(id, website, username, decrypt_password(encrypted_password), notes) for id, website, username, encrypted_password, notes in passwords]
    
    return render_template('view_passwords.html', passwords=decrypted_passwords)

@app.route('/update_password/<int:id>', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    password_id = request.form['id']
    website = request.form['website']
    username = request.form['username']
    password = request.form['password']
    notes = request.form['notes']
    
    encrypted_password = encrypt_password(password)
    
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('UPDATE stored_passwords SET website = ?, username = ?, encrypted_password = ?, notes = ? WHERE id = ? AND user_id = ?',
              (website, username, encrypted_password, notes, password_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_passwords'))

@app.route('/delete_password/<int:id>', methods=['POST'])
def delete_password(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('DELETE FROM stored_passwords WHERE id = ? AND user_id = ?', (id, session['user_id']))
    conn.commit()
    conn.close()
    
    return redirect(url_for('view_passwords'))

@app.route('/search_passwords', methods=['GET'])
def search_passwords():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('query', '')
    
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('SELECT id, website, username, encrypted_password, notes FROM stored_passwords WHERE user_id = ? AND (website LIKE ? OR username LIKE ?)',
              (session['user_id'], f'%{query}%', f'%{query}%'))
    passwords = c.fetchall()
    conn.close()
    
    decrypted_passwords = [(id, website, username, decrypt_password(encrypted_password), notes) for id, website, username, encrypted_password, notes in passwords]
    
    return render_template('view_passwords.html', passwords=decrypted_passwords, query=query)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)