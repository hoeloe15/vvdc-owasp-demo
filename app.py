import os
import sqlite3
import subprocess
import stat
import sys
from flask import Flask, request, render_template, redirect, url_for, session, g, flash, send_from_directory
from werkzeug.utils import secure_filename
import platform # Needed to get current user

# Configuration constants for privilege escalation demo
ROOT_FLAG_CONTENT = "FLAG{c0ngr4tul4t10ns_y0u_h4v3_r00t_4cc3ss}"
USER_FLAG_CONTENT = "FLAG{y0u_f0und_th3_us3r_fl4g_n0w_try_f0r_r00t}"
BACKUP_SCRIPT_PATH = "/tmp/backup_app.sh"
ROOT_FLAG_PATH = "/root/root_flag.txt"
CREDENTIALS_FILE = "/tmp/old_credentials.txt"

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
    f.write(USER_FLAG_CONTENT)

def print_colored(message, color_code):
    """Create colored text for terminal output"""
    return f"\033[{color_code}m{message}\033[0m"

def setup_privilege_escalation():
    """Setup privilege escalation environment from the setup scripts"""
    # Only run privileged operations if running as root
    if os.geteuid() == 0:
        print(print_colored("[+] Setting up privilege escalation environment", "32"))
        
        # Create vulnerable backup script
        create_backup_script()
        
        # Create root flag
        try:
            with open(ROOT_FLAG_PATH, 'w') as f:
                f.write(ROOT_FLAG_CONTENT)
            print(print_colored(f"[+] Created root flag at {ROOT_FLAG_PATH}", "32"))
        except Exception as e:
            print(print_colored(f"[-] Failed to create root flag: {e}", "31"))
        
        # Create fake credentials file
        create_credentials_file()
        
        # Configure sudo for privilege escalation
        configure_sudo_privileges()
        
        # Optionally set SUID on binaries
        modify_suid_binaries()
        
        print(print_colored("[+] Privilege escalation environment setup complete", "32"))
    else:
        print(print_colored("[!] Not running as root - skipping privileged operations", "33"))
        print(print_colored("[!] For full demo functionality, run with sudo/as root", "33"))

def create_backup_script():
    """Create a backup script with command injection vulnerability"""
    print(print_colored("[*] Creating vulnerable backup script...", "34"))
    script_content = """#!/bin/bash
# This script backs up the web application
# VULNERABILITY: This script is allowed to run as root via sudo without password
# and contains command injection in the filename parameter

APP_DIR="."
BACKUP_DIR="/tmp"

# Get backup name from parameter or use default
BACKUP_NAME="${1:-backup_$(date +%s)}"

echo "[+] Backing up application..."
tar czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" "$APP_DIR" 2>/dev/null

# Clean up old backups - VULNERABLE to command injection!
echo "[+] Cleaning up old backups matching pattern: $BACKUP_NAME"
find "$BACKUP_DIR" -name "*$BACKUP_NAME*" -type f -mtime +7 -delete 2>/dev/null

echo "[+] Backup process completed"
"""
    
    with open(BACKUP_SCRIPT_PATH, 'w') as f:
        f.write(script_content)
    
    # Make it executable
    os.chmod(BACKUP_SCRIPT_PATH, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    print(print_colored(f"[+] Created backup script at {BACKUP_SCRIPT_PATH}", "32"))

def create_credentials_file():
    """Create fake credentials file in /tmp"""
    with open(CREDENTIALS_FILE, 'w') as f:
        f.write("""# Old database credentials - DO NOT USE IN PRODUCTION!
DB_USER=dbadmin
DB_PASS=Password123!
DB_HOST=localhost
DB_NAME=webapp_db

# API Keys
API_KEY_PROD=sk_live_51Ks93jDKs39sKDKs99KdkS93
API_KEY_DEV=sk_test_51Ks93jDKs39sKDKs99KdkS93

# Admin credentials (old)
ADMIN_USER=admin
ADMIN_PASS=admin123
""")
    print(print_colored(f"[+] Created fake credentials file at {CREDENTIALS_FILE}", "32"))

def configure_sudo_privileges():
    """Configure sudo to allow multiple privilege escalation paths"""
    try:
        # Use all privilege escalation methods for most comprehensive demo
        sudo_config = "www-data ALL=(ALL) NOPASSWD: /tmp/backup_app.sh, /usr/bin/find, /usr/bin/python3, /usr/bin/perl, /usr/bin/vim"
        
        # Create a new sudoers file
        sudoers_file = "/etc/sudoers.d/vulnerable_app"
        with open(sudoers_file, 'w') as f:
            f.write(sudo_config + "\n")
        os.chmod(sudoers_file, 0o440)
        print(print_colored(f"[+] Configured sudo for www-data user in {sudoers_file}", "32"))
    except Exception as e:
        print(print_colored(f"[-] Failed to configure sudo: {e}", "31"))

def modify_suid_binaries():
    """Set SUID bit on common binaries for GTFObins exploitation"""
    binaries = ['/usr/bin/find', '/usr/bin/vim', '/usr/bin/python3']
    for binary in binaries:
        if os.path.exists(binary):
            try:
                current_perms = os.stat(binary).st_mode
                os.chmod(binary, current_perms | stat.S_ISUID)
                print(print_colored(f"[+] Set SUID bit on {binary}", "32"))
            except Exception as e:
                print(print_colored(f"[-] Failed to set SUID on {binary}: {e}", "31"))

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
    """Initialize the database with schema.sql"""
    # Remove existing database to ensure clean start
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    
    with app.app_context():
        db = get_db()
        try:
            with app.open_resource('schema.sql', mode='r') as f:
                db.executescript(f.read())
            db.commit()
        except Exception as e:
            # Fallback to create tables manually if schema.sql is not available
            db.executescript('''
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS comments;

            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            );

            CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );

            -- Insert sample users
            INSERT INTO users (username, password, email, is_admin) VALUES ('admin', 'admin123', 'admin@example.com', 1);
            INSERT INTO users (username, password, email, is_admin) VALUES ('john', 'password123', 'john@example.com', 0);
            INSERT INTO users (username, password, email, is_admin) VALUES ('user', 'welcome123', 'sarah@example.com', 0);

            -- Insert sample comments
            INSERT INTO comments (user_id, content) VALUES (1, 'Welcome to our vulnerable demo application!');
            INSERT INTO comments (user_id, content) VALUES (2, 'This is a sample comment.');
            INSERT INTO comments (user_id, content) VALUES (3, 'I love this insecure application!');
            ''')
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
            # Use secure_filename to prevent directory traversal in the filename itself
            # and sanitize the filename
            filename = secure_filename(uploaded_file.filename)
            
            # Always save directly in the UPLOAD_FOLDER
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            
            # Create UPLOAD_FOLDER if it doesn't exist (should exist, but safe check)
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            
            # Save the file
            uploaded_file.save(save_path)
            
            # Updated flash message
            flash(f'File uploaded successfully as {filename} to the uploads folder')
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
    # Construct the full path safely within the UPLOAD_FOLDER
    # Normalize path to prevent escaping UPLOAD_FOLDER with ../
    base_dir = os.path.abspath(UPLOAD_FOLDER)
    requested_path = os.path.abspath(os.path.join(base_dir, filename))

    # Security check: Ensure the requested path is still within the UPLOAD_FOLDER
    if not requested_path.startswith(base_dir):
        flash('Access denied: Invalid path.')
        return redirect(url_for('uploads'))

    # Check if the requested file exists
    if not os.path.isfile(requested_path):
        flash('File not found.')
        return redirect(url_for('uploads'))

    # --- NEW LOGIC for executing exec.py ---
    if os.path.basename(requested_path) == 'exec.py':
        try:
            with open(requested_path, 'r') as f:
                python_code = f.read()

            if python_code:
                # Execute the Python code read from the file
                # WARNING: exec() is extremely dangerous with untrusted input!
                # This is intentionally vulnerable for the demo.
                exec(python_code)
                # If exec() runs successfully (e.g., starts a reverse shell),
                # we might not reach this return statement.
                # If it completes without error/blocking, return a success message.
                return "Python code executed successfully (check listener).", 200
            else:
                return "The file 'exec.py' is empty.", 400

        except Exception as e:
            # If execution fails, return the error
            return f"<pre>Error executing Python code: {str(e)}</pre>", 500
    # --- END NEW LOGIC ---

    # For any other file, serve it for download as before
    # Use send_from_directory for safer file serving
    return send_from_directory(os.path.dirname(requested_path), os.path.basename(requested_path))

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

# --- NEW WEB TERMINAL ROUTE --- 
@app.route('/webterminal', methods=['GET', 'POST'])
def web_terminal():
    output = None
    current_user = None
    try:
        # Try to get the current user for display
        if platform.system() == "Windows":
            current_user = os.getenv('USERNAME')
        else:
            # On Linux/macOS, use whoami command
            current_user = subprocess.check_output('whoami', text=True).strip()
    except Exception:
        current_user = 'unknown' # Fallback

    if request.method == 'POST':
        command = request.form.get('cmd', '')
        if command:
            try:
                # Execute the command using subprocess
                # shell=True is needed for many shell commands but is risky
                # This is intentionally vulnerable for the demo
                output = subprocess.check_output(
                    command,
                    shell=True,
                    stderr=subprocess.STDOUT, # Combine stdout and stderr
                    text=True
                )
            except subprocess.CalledProcessError as e:
                # If the command returns non-zero exit code
                output = e.output
            except Exception as e:
                # Other errors (e.g., command not found on Windows if shell=False)
                output = f"Error executing command: {str(e)}"
        else:
            output = "No command entered."
            
    return render_template('web_terminal.html', output=output, current_user=current_user)
# --- END WEB TERMINAL ROUTE ---

@app.route('/demo-info')
def demo_info():
    """Display information about the demo vulnerabilities and paths to exploitation"""
    # Get current system info for display
    hostname = "Unknown"
    try:
        hostname = subprocess.check_output("hostname", shell=True, text=True).strip()
    except:
        pass
    
    # Check if running as root
    is_root = os.geteuid() == 0
    
    # Check if backup script exists
    backup_script_exists = os.path.exists(BACKUP_SCRIPT_PATH)
    
    # Check if sudoers is configured
    sudoers_configured = False
    try:
        sudoers_check = subprocess.check_output("sudo -l -U www-data 2>/dev/null || echo 'Not configured'", 
                                              shell=True, text=True).strip()
        sudoers_configured = "Not configured" not in sudoers_check
    except:
        pass
    
    return render_template('demo_info.html', 
                         hostname=hostname,
                         is_root=is_root,
                         backup_script_exists=backup_script_exists,
                         sudoers_configured=sudoers_configured)

if __name__ == '__main__':
    # Initialize the database if it doesn't exist
    if not os.path.exists(DATABASE):
        init_db()
    
    # Setup privilege escalation environment
    setup_privilege_escalation()
    
    # VULNERABILITY: Host is set to '0.0.0.0' which exposes the app to all network interfaces
    app.run(host='0.0.0.0', port=5000) 