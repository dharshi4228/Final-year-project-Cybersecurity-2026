<?php
// parse_honeypot.php
$host = 'localhost';
$db   = 'soc_dashboard';
$user = 'root';
$pass = 'Mstracker@123';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

    $file = '/var/log/honeypot/ssh_activity.json';
    if (!file_exists($file)) die("Error: Log file not found at $file");

    $handle = fopen($file, 'r');
    $insert = $pdo->prepare("INSERT IGNORE INTO ssh_events (event_time, src_ip, username, status, message) VALUES (?, ?, ?, ?, ?)");
    $count = 0;

    while (($line = fgets($handle)) !== false) {
        $line = trim($line);
        if (empty($line)) continue;

        $ip = '';
        $username = '';
        $status = 'info';
        $timestamp = '';

        // 1. EXTRACT TIMESTAMP (Jan 19 12:32:10)
        if (preg_match('/^([A-Z][a-z]{2}\s+\d+\s+[\d:]+)/', $line, $time_match)) {
            $timestamp = date('Y-m-d H:i:s', strtotime($time_match[1] . " " . date('Y')));
        } else {
            $timestamp = date('Y-m-d H:i:s'); // Fallback to now
        }

        // 2. PATTERN MATCHING FOR THE LOG DATA
        if (strpos($line, 'Failed password') !== false) {
            // Match: Failed password for root from 91.202.233.33
            preg_match('/for (invalid user )?(\S+) from ([\d\.]+)/', $line, $matches);
            $username = $matches[2] ?? '-';
            $ip = $matches[3] ?? '-';
            $status = 'failed';
        } elseif (strpos($line, 'rhost=') !== false) {
            // Match: rhost=124.237.43.209 user=root
            preg_match('/rhost=([\d\.]+)/', $line, $ip_m);
            preg_match('/user=(\S+)/', $line, $user_m);
            $ip = $ip_m[1] ?? '-';
            $username = $user_m[1] ?? '-';
            $status = (strpos($line, 'failure') !== false) ? 'failed' : 'info';
        }

        // 3. INSERT IF VALID DATA FOUND
        if ($ip !== '' && $ip !== '-') {
            $insert->execute([$timestamp, $ip, $username, $status, $line]);
            $count++;
        }
    }
    fclose($handle);
    header("Location: index.php?refreshed=$count");
} catch (Exception $e) {
    die("Error: " . $e->getMessage());
}
