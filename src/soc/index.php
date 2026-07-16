<?php
// 1. SYSTEM CONFIG & DB CONNECTION
ini_set('display_errors', 1);
error_reporting(E_ALL);

$host = 'localhost';
$db   = 'soc_dashboard';
$user = 'root';
$pass = 'Mstracker@123';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("<div style='color:white;background:red;padding:10px;'>DB Error: " . $e->getMessage() . "</div>");
}

// 2. NEW: ADVANCED TIME RANGE FILTER
$range = $_GET['range'] ?? '24h';
$interval = match ($range) {
    '3d' => '3 DAY',
    '7d' => '7 DAY',
    '30d' => '30 DAY',
    default => '24 HOUR'
};
$whereClause = "WHERE event_time >= DATE_SUB(NOW(), INTERVAL $interval)";

// 3. APT INTELLIGENCE DICTIONARY
$apt_intel = [
    'T1110' => ['name' => 'Brute Force', 'groups' => 'APT28 (Fancy Bear), APT33', 'sev' => 'High'],
    'T1078' => ['name' => 'Valid Accounts', 'groups' => 'APT29 (Cozy Bear)', 'sev' => 'Critical'],
    'T1059' => ['name' => 'Command & Scripting Interpreter', 'groups' => 'Lazarus Group', 'sev' => 'Critical'],
    'T1105' => ['name' => 'Ingress Tool Transfer (wget/curl)', 'groups' => 'APT41 (Double Dragon)', 'sev' => 'Medium'],
    'T1046' => ['name' => 'Network Service Scanning', 'groups' => 'APT10 (Stone Panda)', 'sev' => 'Low']
];

// 4. DATA QUERIES
// KPIs
$stats = $pdo->query("SELECT 
    COUNT(*) as total, 
    COUNT(DISTINCT src_ip) as unique_ips,
    (SELECT COUNT(*) FROM ssh_events $whereClause AND (message LIKE '%curl%' OR message LIKE '%wget%')) as total_cmds,
    (SELECT COUNT(*) FROM ssh_events $whereClause AND (status = 'success' OR message LIKE '%Accepted%')) as malware_cnt
FROM ssh_events $whereClause")->fetch(PDO::FETCH_ASSOC);

// Attacker Profiling (Personas)
$profiles = $pdo->query("SELECT src_ip, COUNT(*) as hits, COUNT(DISTINCT username) as users, GROUP_CONCAT(DISTINCT message SEPARATOR ' ') as msgs FROM ssh_events $whereClause GROUP BY src_ip ORDER BY hits DESC LIMIT 15")->fetchAll();

// Timeline & Charts
$timeline = $pdo->query("SELECT DATE_FORMAT(event_time, '%m-%d %H:00') as hr, COUNT(*) as qty FROM ssh_events $whereClause GROUP BY hr ORDER BY hr ASC")->fetchAll();
$typeStats = $pdo->query("SELECT status as type, COUNT(*) as count FROM ssh_events $whereClause GROUP BY status")->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Vande Bharat | APT Intelligence SOC</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg: #0b0d0f;
            --panel: #161b22;
            --border: #30363d;
            --blue: #006d9c;
            --red: #a32626;
            --yellow: #b58900;
            --green: #5cc05c;
            --text: #c9d1d9;
            --text-dim: #8b949e;
        }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Segoe UI', sans-serif;
            margin: 0;
            padding: 20px;
        }

        header {
            border-bottom: 2px solid var(--green);
            padding-bottom: 10px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .controls {
            background: var(--panel);
            padding: 10px;
            border-radius: 4px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        select {
            background: #0d1117;
            color: white;
            border: 1px solid var(--border);
            padding: 5px;
            border-radius: 3px;
        }

        .kpi-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-bottom: 20px;
        }

        .kpi-card {
            padding: 15px;
            border-radius: 4px;
            color: white;
        }

        .kpi-card .val {
            font-size: 28px;
            font-weight: bold;
            display: block;
        }

        .kpi-card .lbl {
            font-size: 11px;
            text-transform: uppercase;
            opacity: 0.8;
        }

        .tabs {
            display: flex;
            background: #0d1117;
            border-bottom: 2px solid var(--border);
            margin-bottom: 20px;
        }

        .tab {
            padding: 12px 20px;
            cursor: pointer;
            color: var(--text-dim);
            font-size: 13px;
            font-weight: bold;
        }

        .tab.active {
            border-bottom: 2px solid var(--green);
            color: var(--green);
            background: rgba(92, 192, 92, 0.05);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .panel {
            background: var(--panel);
            padding: 15px;
            border-radius: 4px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }

        th {
            text-align: left;
            color: var(--text-dim);
            border-bottom: 1px solid var(--border);
            padding: 10px;
        }

        td {
            padding: 10px;
            border-bottom: 1px solid #21262d;
        }

        .badge {
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
            border: 1px solid;
        }

        code {
            color: var(--yellow);
        }
    </style>
</head>

<body>

    <header>
        <div>
            <h1>Vande Bharat <span>> Mini Splunk</span></h1>
            <div style="font-size:12px;color:var(--text-dim);">Threat Intelligence & APT Attribution Dashboard</div>
        </div>
        <a href="raw.php" style="background:var(--yellow); color:black; padding:8px 15px; border-radius:4px; font-weight:bold; text-decoration:none; font-size:12px;">RAW DATA </a>
        <a href="parse_honeypot.php" style="background:var(--green); color:black; padding:8px 15px; border-radius:4px; font-weight:bold; text-decoration:none; font-size:12px;">REFRESH LOGS</a>

    </header>

    <div class="controls">
        <form method="GET" id="filterForm">
            <label style="font-size:13px;">Analysis Timeframe: </label>
            <select name="range" onchange="document.getElementById('filterForm').submit()">
                <option value="24h" <?= $range == '24h' ? 'selected' : '' ?>>Last 24 Hours</option>
                <option value="3d" <?= $range == '3d' ? 'selected' : '' ?>>Last 3 Days</option>
                <option value="7d" <?= $range == '7d' ? 'selected' : '' ?>>Last 7 Days</option>
                <option value="30d" <?= $range == '30d' ? 'selected' : '' ?>>Last 30 Days (Month)</option>
            </select>
        </form>
    </div>

    <div class="kpi-row">
        <div class="kpi-card" style="background: var(--blue);"><span class="lbl">Total Hits</span><span class="val"><?= number_format($stats['total']) ?></span></div>
        <div class="kpi-card" style="background: var(--red);"><span class="lbl">Unique Attackers</span><span class="val"><?= number_format($stats['unique_ips']) ?></span></div>
        <div class="kpi-card" style="background: var(--yellow);"><span class="lbl">Payloads Detected</span><span class="val"><?= number_format($stats['total_cmds']) ?></span></div>
        <div class="kpi-card" style="background: var(--green);"><span class="lbl">Exploits Logged</span><span class="val"><?= number_format($stats['malware_cnt']) ?></span></div>
    </div>

    <div class="tabs">
        <div class="tab active" onclick="openTab(event, 'overview')">Overview</div>
        <div class="tab" onclick="openTab(event, 'ssh')">SSH Attack Analysis</div>
        <div class="tab" onclick="openTab(event, 'malware')">Malware Analysis</div>
        <div class="tab" onclick="openTab(event, 'profiling')">Attacker Profiling</div>
        <div class="tab" onclick="openTab(event, 'apt')">MITRE APT Mapping</div>
    </div>

    <div id="overview" class="tab-content active">
        <div style="display:grid; grid-template-columns: 1fr 2fr; gap:20px;">
            <div class="panel">
                <h2>Threat Distribution</h2><canvas id="typeChart"></canvas>
            </div>
            <div class="panel">
                <h2>Attack Timeline</h2><canvas id="lineChart"></canvas>
            </div>
        </div>
    </div>

    <div id="ssh" class="tab-content">
        <div class="panel">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2>Recent Authentication Events (Last 50)</h2>
                <span style="color: var(--text-dim); font-size: 12px;">Monitoring: T1110 & T1078</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP Address</th>
                        <th>User</th>
                        <th>Status</th>
                        <th>Intelligence</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    // Increased LIMIT to 50 for better visibility
                    $ssh_logs = $pdo->query("SELECT * FROM ssh_events $whereClause ORDER BY event_time DESC LIMIT 50")->fetchAll();

                    foreach ($ssh_logs as $l):
                        // LOGIC: If message contains 'Accepted', force status to Success
                        $raw_msg = strtolower($l['message']);
                        $status = $l['status'];

                        if (strpos($raw_msg, 'accepted') !== false) {
                            $status = 'success';
                        }

                        $isSuccess = ($status == 'success');
                        $color = $isSuccess ? 'var(--green)' : 'var(--red)';
                        $bg = $isSuccess ? 'rgba(92, 192, 92, 0.15)' : 'transparent';
                    ?>
                        <tr style="background: <?= $bg ?>;">
                            <td><?= $l['event_time'] ?></td>
                            <td style="color:var(--blue); font-weight:bold;"><?= $l['src_ip'] ?></td>
                            <td><code><?= htmlspecialchars($l['username']) ?></code></td>
                            <td>
                                <span class="badge" style="border-color: <?= $color ?>; color: <?= $color ?>;">
                                    <?= strtoupper($status) ?>
                                </span>
                            </td>
                            <td style="font-size: 10px; color: var(--text-dim);">
                                <?= $isSuccess ? "⚠️ <b>CRITICAL: Unauthorized Access</b>" : "Brute Force Attempt" ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div id="malware" class="tab-content">
        <div class="panel">
            <h2>Payload & Command Signatures</h2>
            <p style="font-size: 11px; color: var(--text-dim); margin-bottom: 10px;">
                Detecting T1105: Ingress Tool Transfer signatures (curl/wget)
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Source IP</th>
                        <th>Command Execution</th>
                        <th>MD5 Payload Hash</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    // Ensure $whereClause exists; if not, default to empty or a specific range
                    $sqlWhere = isset($whereClause) ? $whereClause : "WHERE 1=1";

                    // Query for tool transfer patterns
                    $malware_query = "SELECT event_time, src_ip, message 
                                 FROM ssh_events 
                                 $sqlWhere 
                                 AND (message LIKE '%curl%' OR message LIKE '%wget%' OR message LIKE '%chmod%') 
                                 ORDER BY event_time DESC 
                                 LIMIT 15";

                    $stmt = $pdo->query($malware_query);
                    $malware_list = $stmt->fetchAll(PDO::FETCH_ASSOC);

                    if (count($malware_list) > 0) {
                        foreach ($malware_list as $m) {
                            // Sanitize message for HTML display
                            $safe_msg = htmlspecialchars($m['message']);
                            $display_msg = strlen($safe_msg) > 60 ? substr($safe_msg, 0, 60) . "..." : $safe_msg;
                            $payload_hash = md5($m['message']);

                            echo "<tr>
                                <td>{$m['event_time']}</td>
                                <td style='color:var(--blue); font-weight:bold;'>{$m['src_ip']}</td>
                                <td><code style='color:var(--yellow);'>{$display_msg}</code></td>
                                <td><code style='font-size:10px; color:var(--text-dim);'>{$payload_hash}</code></td>
                              </tr>";
                        }
                    } else {
                        echo "<tr><td colspan='4' style='text-align:center;'>No malware payloads detected in this time range.</td></tr>";
                    }
                    ?>
                </tbody>
            </table>
        </div>
    </div>

    <div id="profiling" class="tab-content">
        <div class="panel">
            <h2>Behavioral Personas</h2>
            <table>
                <tr>
                    <th>IP</th>
                    <th>Persona</th>
                    <th>Hits</th>
                    <th>Unique Users</th>
                    <th>Threat Score</th>
                </tr>
                <?php foreach ($profiles as $p):
                    $score = min(100, ($p['hits'] * 2) + ($p['users'] * 5));
                    $persona = ($p['users'] > 10) ? "Botnet" : "Scout";
                ?>
                    <tr>
                        <td><b><?= $p['src_ip'] ?></b></td>
                        <td><span class="badge" style="color:var(--blue)"><?= $persona ?></span></td>
                        <td><?= $p['hits'] ?></td>
                        <td><?= $p['users'] ?></td>
                        <td>
                            <div style="width:100px; background:#30363d; height:8px; border-radius:4px;">
                                <div style="width:<?= $score ?>%; background:<?= $score > 75 ? 'var(--red)' : 'var(--yellow)' ?>; height:100%; border-radius:4px;"></div>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </table>
        </div>
    </div>

    <div id="apt" class="tab-content">
        <div class="panel">
            <h2 style="color:var(--red);">Advanced MITRE ATT&CK Attribution</h2>
            <table>
                <thead>
                    <tr>
                        <th>Attacker IP</th>
                        <th>TTP ID</th>
                        <th>Technique</th>
                        <th>Attribution</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    // 1. EXPANDED TTP DICTIONARY
                    $apt_intel = [
                        'T1110' => ['name' => 'Brute Force', 'groups' => 'APT28, APT33', 'sev' => 'High'],
                        'T1105' => ['name' => 'Ingress Tool Transfer', 'groups' => 'APT41, Lazarus', 'sev' => 'Medium'],
                        'T1059' => ['name' => 'Command & Scripting Interpreter', 'groups' => 'FIN7, APT29', 'sev' => 'Critical'],
                        'T1082' => ['name' => 'System Information Discovery', 'groups' => 'General Recon', 'sev' => 'Low'],
                        'T1018' => ['name' => 'Remote Service Discovery', 'groups' => 'APT10', 'sev' => 'Medium'],
                        'T1027' => ['name' => 'Obfuscated Files/Information', 'groups' => 'Multiple APTs', 'sev' => 'High']
                    ];

                    // 2. FETCH DATA
                    $sqlWhere = isset($whereClause) ? $whereClause : "WHERE 1=1";
                    $raw_events = $pdo->query("SELECT src_ip, message FROM ssh_events $sqlWhere")->fetchAll(PDO::FETCH_ASSOC);

                    $distinct_mappings = [];

                    // 3. MULTI-LEVEL FINGERPRINTING LOGIC
                    foreach ($raw_events as $e) {
                        $ttp = '';
                        $msg = strtolower($e['message']);

                        // Logic for T1059 (Execution via Python/Bash)
                        if (strpos($msg, 'python') !== false || strpos($msg, 'perl') !== false || strpos($msg, 'bash -i') !== false) {
                            $ttp = 'T1059';
                        }
                        // Logic for T1105 (Tool Transfer)
                        elseif (strpos($msg, 'wget') !== false || strpos($msg, 'curl') !== false || strpos($msg, 'tftp') !== false) {
                            $ttp = 'T1105';
                        }
                        // Logic for T1082 (System Discovery - e.g. uname, lscpu)
                        elseif (strpos($msg, 'uname -a') !== false || strpos($msg, 'cat /etc/issue') !== false) {
                            $ttp = 'T1082';
                        }
                        // Logic for T1027 (Obfuscation - e.g. base64)
                        elseif (strpos($msg, 'base64 -d') !== false) {
                            $ttp = 'T1027';
                        }
                        // Default to T1110 (Brute Force) only if failed login is detected
                        elseif (strpos($msg, 'failed') !== false || strpos($msg, 'invalid user') !== false) {
                            $ttp = 'T1110';
                        }

                        // 4. APPLY DISTINCT FILTER (One IP per TTP)
                        if ($ttp && isset($apt_intel[$ttp])) {
                            $unique_key = $e['src_ip'] . $ttp;
                            if (!isset($distinct_mappings[$unique_key])) {
                                $distinct_mappings[$unique_key] = [
                                    'ip'   => $e['src_ip'],
                                    'ttp'  => $ttp,
                                    'tech' => $apt_intel[$ttp]['name'],
                                    'apt'  => $apt_intel[$ttp]['groups'],
                                    'sev'  => $apt_intel[$ttp]['sev']
                                ];
                            }
                        }
                    }

                    // 5. RENDER TABLE
                    foreach ($distinct_mappings as $row) {
                        $color = match ($row['sev']) {
                            'Critical' => 'var(--red)',
                            'High'     => 'var(--yellow)',
                            'Medium'   => 'var(--blue)',
                            default    => 'var(--text-dim)'
                        };
                        echo "<tr>
                            <td><b>{$row['ip']}</b></td>
                            <td><code style='color:var(--yellow)'>{$row['ttp']}</code></td>
                            <td>{$row['tech']}</td>
                            <td style='color:var(--green)'>{$row['apt']}</td>
                            <td><span class='badge' style='border-color:{$color}; color:{$color}'>{$row['sev']}</span></td>
                          </tr>";
                    }
                    ?>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function openTab(evt, name) {
            var i, content, tabs;
            content = document.getElementsByClassName("tab-content");
            for (i = 0; i < content.length; i++) content[i].classList.remove("active");
            tabs = document.getElementsByClassName("tab");
            for (i = 0; i < tabs.length; i++) tabs[i].classList.remove("active");
            document.getElementById(name).classList.add("active");
            evt.currentTarget.classList.add("active");
        }
        new Chart(document.getElementById('typeChart'), {
            type: 'doughnut',
            data: {
                labels: <?= json_encode(array_column($typeStats, 'type')) ?>,
                datasets: [{
                    data: <?= json_encode(array_column($typeStats, 'count')) ?>,
                    backgroundColor: ['#a32626', '#5cc05c', '#b58900']
                }]
            }
        });
        new Chart(document.getElementById('lineChart'), {
            type: 'line',
            data: {
                labels: <?= json_encode(array_column($timeline, 'hr')) ?>,
                datasets: [{
                    label: 'Attacks',
                    data: <?= json_encode(array_column($timeline, 'qty')) ?>,
                    borderColor: '#5cc05c',
                    fill: true,
                    tension: 0.3
                }]
            }
        });
    </script>
</body>

</html>