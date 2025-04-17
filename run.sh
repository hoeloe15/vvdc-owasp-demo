#!/bin/bash

# Run script for OWASP Vulnerability and Privilege Escalation Demo

echo -e "\033[1;33m===== OWASP Vulnerability and Privilege Escalation Demo =====\033[0m"
echo -e "\033[1;31mWARNING: This application is intentionally vulnerable.\033[0m"
echo -e "\033[1;31mDO NOT expose to public networks or production environments.\033[0m"
echo ""

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[1;31mWarning: Not running as root. Privilege escalation features will be limited.\033[0m"
    echo "For full demo functionality, run with sudo: sudo ./run.sh"
    echo ""
    read -p "Continue without root privileges? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting. Please restart with sudo for full functionality."
        exit 1
    fi
fi

# Setup virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "\033[1;34mSetting up virtual environment...\033[0m"
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Check if database exists, create if not
if [ ! -f "vulnerable_app.db" ]; then
    echo -e "\033[1;34mInitializing database...\033[0m"
    python -c "from app import init_db; init_db()"
fi

echo -e "\033[1;32mStarting vulnerable web application...\033[0m"
echo -e "\033[1;36mAccess the application at: http://localhost:5000\033[0m"
echo -e "\033[1;36mView demo instructions at: http://localhost:5000/demo-info\033[0m"
echo ""
echo -e "\033[1;33mPress Ctrl+C to stop the application\033[0m"

# Run the Flask application
python app.py 