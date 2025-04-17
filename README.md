# Vulnerable Web Application Demo with Privilege Escalation

This Flask web application was intentionally designed with security vulnerabilities for educational and demonstration purposes. It demonstrates common web security issues according to the OWASP Top 10 and provides a complete attack chain from initial exploitation to privilege escalation.

## ⚠️ Warning ⚠️

**This application is intentionally vulnerable and should only be used in a controlled environment for educational purposes.**

**DO NOT deploy this application in a production environment, expose it to the public internet, or use it with real user data.**

## Included Vulnerabilities

### Web Application Vulnerabilities
1. **SQL Injection**: The login form is vulnerable to SQL injection attacks.
2. **Cross-Site Scripting (XSS)**: The comments section allows execution of arbitrary JavaScript.
3. **Insecure Direct Object References (IDOR)**: User profiles can be accessed by manipulating URL parameters.
4. **Path Traversal**: File upload functionality allows saving files to unauthorized locations.
5. **Command Injection**: Admin tools allow executing arbitrary system commands.
6. **Security Misconfiguration**: The application runs in debug mode and has other security misconfigurations.
7. **Sensitive Data Exposure**: Passwords are stored in plaintext in the database.

### Privilege Escalation Vectors
1. **Vulnerable Backup Script**: The backup script can be exploited through command injection.
2. **SUID Binaries**: Common binaries are configured with SUID permissions.
3. **Sudo Privileges**: The www-data user has sudo privileges for certain commands without a password.
4. **Sensitive Files**: Hidden credentials files are available for discovery.

## Setup Instructions

### Option 1: Deploy to Cloud (Recommended)

Use the provided deployment script to deploy to Azure:

```
./deploy-app.sh
```

This will:
- Build the Docker container
- Push it to Azure Container Registry
- Deploy to Azure Container Instances
- Provide you with a unique URL to access the application

### Option 2: Running with Docker Locally

```
docker-compose -f docker-compose.prod.yml up -d --build
```

Access the application at http://localhost:5000

### Option 3: Running Locally

1. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application (with sudo for full privilege escalation functionality):
   ```
   sudo python app.py
   ```

4. Access the application at http://127.0.0.1:5000

## Database Information

The application uses SQLite for its database:
- A fresh database is created each time the application starts
- Sample users are automatically created with credentials:
  - Username: `admin`, Password: `admin123` (admin user)
  - Username: `john`, Password: `password123` (regular user)
  - Username: `user`, Password: `welcome123` (regular user)

### SQL Injection Techniques

The login form is vulnerable to several SQL injection techniques:

1. **Basic Authentication Bypass**:
   - Username: `' OR '1'='1` (with any password)
   - Username: `' OR 1=1 --` (with any password)
   
2. **Admin Access**:
   - Username: `admin' --` (with any password)

When these SQL injections work, they log you in as the first user in the database (typically the admin user).

The query sent to the database would look like:
```sql
-- For "' OR '1'='1":
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything'

-- For "admin' --":
SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```

## Complete Attack Chain Demonstration

The application facilitates a complete attack chain demonstration:

1. **Initial Access**: Exploit web vulnerabilities (SQL injection, path traversal)
2. **Reverse Shell**: Upload and execute a PHP reverse shell
3. **Discovery**: Find sensitive files and hidden flags
4. **Privilege Escalation**: Use the configured vectors to gain root access
5. **Capture the Flag**: Find and capture the root flag

## Demo Environment Features

- **Interactive Demo Page**: Visit `/demo-info` to view available vulnerabilities and privilege escalation methods
- **User Flag**: Located at `restricted/flag.txt`
- **Root Flag**: Located at `/root/root_flag.txt` (only accessible after privilege escalation)
- **Multiple Privilege Escalation Paths**: Choose from various methods including backup script injection, SUID binaries, and sudo permissions

## Educational Purpose

This application is designed for:
- Cybersecurity training and demonstrations
- Penetration testing practice
- Educational workshops on web security
- Learning about privilege escalation techniques

Remember to practice ethical hacking and only use these techniques in controlled, authorized environments. 