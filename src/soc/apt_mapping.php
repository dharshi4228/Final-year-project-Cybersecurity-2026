<?php
// 1. DB CONNECTION
$host = 'localhost';
$db   = 'soc_dashboard';
$user = 'root';
$pass = 'Mstracker@123';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// 2. DYNAMIC TIME FILTER LOGIC
// Get range from URL (e.g., apt_mapping.php?range=7d), default to 24h
$range = $_GET['range'] ?? '24h';

$interval = match ($range) {
    '3d'    => '3 DAY',
    '7d'    => '7 DAY',
    'month' => '1 MONTH',
    default => '24 HOUR' // '24h'
};

// 3. EXPANDED APT DICTIONARY
$apt_intel = [
    'T1110' => ['name' => 'Brute Force', 'groups' => 'APT28 (Fancy Bear), APT33', 'sev' => 'High'],
    'T1078' => ['name' => 'Valid Accounts', 'groups' => 'APT29 (Cozy Bear)', 'sev' => 'Critical'],
    'T1059' => ['name' => 'Command & Scripting Interpreter', 'groups' => 'Lazarus Group', 'sev' => 'Critical'],
    'T1105' => ['name' => 'Ingress Tool Transfer (wget/curl)', 'groups' => 'APT41 (Double Dragon)', 'sev' => 'Medium']
];

// 4. DATA FETCHING (Using the dynamic interval)
$query = "SELECT src_ip, username, message, status, event_time 
          FROM ssh_events 
          WHERE event_time >= DATE_SUB(NOW(), INTERVAL $interval)
          ORDER BY event_time DESC";

$events = $pdo->query($query)->fetchAll(PDO::FETCH_ASSOC);

$mapped_results = [];
$seen_matches = []; // Prevents duplicate rows for the same IP/TTP combo

foreach ($events as $e) {
    $ttp_code = '';

    // Advanced Behavioral Logic
    if (strpos($e['message'], 'Failed password') !== false) {
        $ttp_code = 'T1110';
    } elseif (strpos($e['message'], 'Accepted password') !== false) {
        $ttp_code = 'T1078';
    } elseif (strpos($e['message'], 'wget') !== false || strpos($e['message'], 'curl') !== false) {
        $ttp_code = 'T1105';
    } elseif (strpos($e['message'], 'python') !== false || strpos($e['message'], 'sh') !== false) {
        $ttp_code = 'T1059';
    }

    // Mapping and Deduplication
    if ($ttp_code && isset($apt_intel[$ttp_code])) {
        $match_key = $e['src_ip'] . $ttp_code;

        if (!isset($seen_matches[$match_key])) {
            $mapped_results[] = [
                'ip'        => $e['src_ip'],
                'ttp'       => $ttp_code,
                'technique' => $apt_intel[$ttp_code]['name'],
                'apt'       => $apt_intel[$ttp_code]['groups'],
                'severity'  => $apt_intel[$ttp_code]['sev'],
                'last_seen' => $e['event_time']
            ];
            $seen_matches[$match_key] = true;
        }
    }
}
