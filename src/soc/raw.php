<?php
// ================= CONFIG =================
$logFile = '/var/log/honeypot/ssh_activity.json';
$linesToShow = 40;

// ================= AJAX REQUEST =================
if (isset($_GET['ajax']) && $_GET['ajax'] === '1') {

    if (!file_exists($logFile) || !is_readable($logFile)) {
        http_response_code(404);
        echo "Log file not found or not readable";
        exit;
    }

    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $lastLines = array_slice($lines, -$linesToShow);

    header('Content-Type: text/plain');
    echo implode("\n", $lastLines);
    exit;
}
?>

<!DOCTYPE html>
<html>

<head>
    <title>SOC Live Honeypot Logs</title>

    <style>
        body {
            background: #0d1117;
            color: #c9d1d9;
            font-family: Consolas, monospace;
            margin: 0;
            padding: 20px;
        }

        h2 {
            color: #58a6ff;
            margin-bottom: 10px;
        }

        #logBox {
            background: #010409;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 15px;
            height: 450px;
            overflow-y: auto;
            white-space: pre-wrap;
            font-size: 13px;
        }

        .status {
            margin-top: 8px;
            font-size: 12px;
            color: #8b949e;
        }
    </style>
</head>

<body>

    <h2>🛡️ SOC Honeypot – Live SSH Logs</h2>

    <div id="logBox">Loading logs...</div>
    <div class="status">Auto refresh: every 2 seconds</div>

    <script>
        function loadLogs() {
            fetch('?ajax=1')
                .then(response => response.text())
                .then(data => {
                    const box = document.getElementById('logBox');
                    box.textContent = data;
                    box.scrollTop = box.scrollHeight; // Auto-scroll
                })
                .catch(() => {
                    document.getElementById('logBox').textContent = 'Error loading logs';
                });
        }

        // Initial load
        loadLogs();

        // Refresh every 2 seconds
        setInterval(loadLogs, 2000);
    </script>

</body>

</html>