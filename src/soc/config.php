<?php
$host = "localhost";
$db   = "soc_dashboard";
$user = "root";
$pass = "Mstracker@123";

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$db;charset=utf8",
        $user,
        $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    die("DB Connection Failed");
}
