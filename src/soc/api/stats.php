<?php
header('Content-Type: application/json');

$pdo = new PDO("mysql:host=localhost;dbname=soc_dashboard;charset=utf8", "root", "Mstracker@123", [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
]);

$start = $_GET['start'] ?? null;
$end = $_GET['end'] ?? null;

$where = '';
$params = [];

if ($start && $end) {
    $where = "WHERE event_time BETWEEN ? AND ?";
    $params = [$start . ' 00:00:00', $end . ' 23:59:59'];
}

// Total attacks
$stmt = $pdo->prepare("SELECT COUNT(*) as total_attacks FROM ssh_events $where");
$stmt->execute($params);
$total = $stmt->fetch(PDO::FETCH_ASSOC)['total_attacks'];

// Unique IPs
$stmt = $pdo->prepare("SELECT COUNT(DISTINCT src_ip) as unique_ips FROM ssh_events $where");
$stmt->execute($params);
$unique_ips = $stmt->fetch(PDO::FETCH_ASSOC)['unique_ips'];

// Success
$stmt = $pdo->prepare("SELECT COUNT(*) as success FROM ssh_events $where AND status='success'");
$stmt->execute($params);
$success = $stmt->fetch(PDO::FETCH_ASSOC)['success'];

// Failed
$stmt = $pdo->prepare("SELECT COUNT(*) as failed FROM ssh_events $where AND status='failed'");
$stmt->execute($params);
$failed = $stmt->fetch(PDO::FETCH_ASSOC)['failed'];

echo json_encode([
    'total_attacks' => (int)$total,
    'unique_ips' => (int)$unique_ips,
    'success' => (int)$success,
    'failed' => (int)$failed
]);
