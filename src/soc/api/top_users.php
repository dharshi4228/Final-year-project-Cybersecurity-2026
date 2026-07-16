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

$stmt = $pdo->prepare("
    SELECT username, COUNT(*) as total 
    FROM ssh_events
    $where
    GROUP BY username
    ORDER BY total DESC
    LIMIT 10
");
$stmt->execute($params);
$data = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo json_encode($data);
