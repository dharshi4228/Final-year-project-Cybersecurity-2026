<?php
require "../config.php";

$sql = "
SELECT 
  m.tactic,
  m.technique,
  m.technique_id,
  COUNT(*) AS total
FROM ssh_events s
JOIN mitre_map m
  ON s.message LIKE CONCAT('%', m.keyword, '%')
GROUP BY m.technique_id
ORDER BY total DESC
";

$stmt = $pdo->query($sql);
echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
