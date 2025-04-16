import os
import sqlite3
import subprocess
from flask import Flask, request, render_template, redirect, url_for, session, g, flash, send_from_directory

app = Flask(__name__)
app.secret_key = 'super_insecure_secret_key'  # VULNERABILITY: Hardcoded secret key

# VULNERABILITY: Debug mode enabled in production
app.debug = True

# Database setup
DATABASE = 'vulnerable_app.db'
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Create a flag file in a "restricted" area
FLAG_DIR = 'restricted'
if not os.path.exists(FLAG_DIR):
    os.makedirs(FLAG_DIR)
with open(os.path.join(FLAG_DIR, 'flag.txt'), 'w') as f:
    f.write('FLAG{y0u_f0und_th3_h1dd3n_fl4g}')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.executescript(f.read())
        db.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# VULNERABILITY: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABILITY: SQL Injection vulnerability
        # This query is vulnerable because it directly concatenates user input
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        # Insecure way to execute a query
        db = get_db()
        user = db.execute(query).fetchone()
        
        if user:
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('You were logged in')
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('You were logged out')
    return redirect(url_for('index'))

# VULNERABILITY: XSS (Cross-Site Scripting)
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    db = get_db()
    
    if request.method == 'POST':
        # VULNERABILITY: XSS - No sanitization of user input
        comment = request.form['comment']
        user_id = session.get('user_id', 0)  # Default to 0 if not logged in
        
        db.execute('INSERT INTO comments (user_id, content) VALUES (?, ?)',
                  [user_id, comment])
        db.commit()
    
    # Get all comments
    cur = db.execute('SELECT comments.content, users.username FROM comments LEFT JOIN users ON comments.user_id = users.id ORDER BY comments.id DESC')
    comments = cur.fetchall()
    
    return render_template('comments.html', comments=comments)

# VULNERABILITY: IDOR (Insecure Direct Object References)
@app.route('/profile/<int:user_id>')
def profile(user_id):
    # VULNERABILITY: No authentication check - any user can access any profile
    # Should check if the current user has permission to view this profile
    
    db = get_db()
    cur = db.execute('SELECT id, username, email FROM users WHERE id = ?', [user_id])
    user = cur.fetchone()
    
    if user:
        return render_template('profile.html', user=user)
    else:
        flash('User not found')
        return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        db = get_db()
        
        # Check if username already exists
        if db.execute('SELECT id FROM users WHERE username = ?', [username]).fetchone():
            error = 'Username already exists'
        else:
            # VULNERABILITY: Password stored in plaintext
            db.execute('INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)',
                      [username, password, email, 0])
            db.commit()
            flash('You were successfully registered. Please log in.')
            return redirect(url_for('login'))
    
    return render_template('register.html', error=error)

# VULNERABILITY: Arbitrary File Upload with Path Traversal
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        uploaded_file = request.files['file']
        
        if uploaded_file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if uploaded_file:
            # VULNERABILITY: Path Traversal - using user input for file path
            # A malicious user can use "../" to navigate to other directories
            # For example: "../restricted/malicious.php" could overwrite sensitive files
            file_path = request.form.get('path', '')
            save_path = os.path.join(UPLOAD_FOLDER, file_path, uploaded_file.filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            # Save the file
            uploaded_file.save(save_path)
            
            flash(f'File uploaded successfully to {save_path}')
            return redirect(url_for('uploads'))
    
    return render_template('upload.html')

@app.route('/uploads')
def uploads():
    files = []
    for root, dirs, filenames in os.walk(UPLOAD_FOLDER):
        for filename in filenames:
            path = os.path.join(root, filename)
            relative_path = os.path.relpath(path, UPLOAD_FOLDER)
            files.append(relative_path)
    
    return render_template('uploads.html', files=files)

@app.route('/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# VULNERABILITY: Command Injection
@app.route('/admin/tools', methods=['GET', 'POST'])
def admin_tools():
    if not session.get('logged_in'):
        flash('You need to be logged in')
        return redirect(url_for('login'))
    
    # Regular users can still access this page
    # No proper authorization check for admin role
    
    output = None
    if request.method == 'POST':
        # VULNERABILITY: Unsanitized user input is passed to system command
        command = request.form.get('command', '')
        
        # Attempt to mitigate by only allowing certain commands (but still vulnerable)
        allowed_commands = ['ping', 'nslookup', 'traceroute']
        command_parts = command.split()
        
        if command_parts and command_parts[0] in allowed_commands:
            try:
                # VULNERABILITY: Command Injection
                # Commands can be chained with ; | && or other shell operators
                # Example: ping 127.0.0.1 && cat /etc/passwd
                output = subprocess.check_output(command, shell=True, text=True)
            except subprocess.CalledProcessError as e:
                output = str(e)
        else:
            output = "Command not allowed"
    
    return render_template('admin_tools.html', output=output)

# Route to check if we can access the flag
@app.route('/restricted/<path:filename>')
def restricted_file(filename):
    if not session.get('is_admin', False):
        flash('You need admin privileges to access this file')
        return redirect(url_for('index'))
    
    # Even with the check, a user could access this through the upload vulnerability
    return send_from_directory(FLAG_DIR, filename)

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    
    # VULNERABILITY: Host is set to '0.0.0.0' which exposes the app to all network interfaces
    app.run(host='0.0.0.0', port=5000) 