<?php
header('Content-Type: application/json');

$pdo = new PDO("mysql:host=localhost;dbname=soc_dashboard;charset=utf8", "root", "Mstracker@123", [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
]);

$start = $_GET['start'] ?? null;
$end = $_GET['end'] ?? null;
$page = max(1, intval($_GET['page'] ?? 1));
$limit = 100; // rows per page
$offset = ($page - 1) * $limit;

$where = '';
$params = [];
if ($start && $end) {
    $where = "WHERE event_time BETWEEN ? AND ?";
    $params = [$start . ' 00:00:00', $end . ' 23:59:59'];
}

// Total rows for pagination
$stmt = $pdo->prepare("SELECT COUNT(*) as total FROM ssh_events $where");
$stmt->execute($params);
$totalRows = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
$totalPages = ceil($totalRows / $limit);

// Fetch paginated events
$stmt = $pdo->prepare("
    SELECT event_time, src_ip, username, status, message
    FROM ssh_events
    $where
    ORDER BY event_time DESC
    LIMIT $limit OFFSET $offset
");
$stmt->execute($params);
$data = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo json_encode(['data' => $data, 'totalPages' => $totalPages]);
