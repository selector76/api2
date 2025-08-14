<?php
#file_put_contents('auth_debug.log', print_r($_SERVER, true));
require 'config.php';
header('Content-Type: application/json');

// Funkcja do autoryzacji
function require_auth($validUser, $validPass) {
    global $authEnabled;

    if (!$authEnabled) return;

    $user = null;
    $pass = null;

    // ustawienia dla apache
    if (isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
        $user = $_SERVER['PHP_AUTH_USER'];
        $pass = $_SERVER['PHP_AUTH_PW'];
    } else {

        $authHeader = null;

        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $authHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        } elseif (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            if (isset($headers['Authorization'])) {
                $authHeader = $headers['Authorization'];
            }
        }

        if ($authHeader && stripos($authHeader, 'Basic ') === 0) {
            $decoded = base64_decode(substr($authHeader, 6));
            if ($decoded) {
                list($user, $pass) = explode(':', $decoded, 2);
            }
        }
    }

    if ($user !== $validUser || $pass !== $validPass) {
        unauthorized();
    }
}

function unauthorized() {
    header('HTTP/1.1 401 Unauthorized');
    header('WWW-Authenticate: Basic realm="API Access"');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

require_auth($validUser, $validPass);
$table  = $_GET['table'] ?? '';
$where  = $_GET['where'] ?? '';  // np. "price>100"
$limit  = isset($_GET['limit']) ? intval($_GET['limit']) : 100;
$limit  = min(max($limit, 1), 1000); // max 1000

if (!array_key_exists($table, $allowedTables)) {
    http_response_code(400);
    echo json_encode(['error' => 'Nieprawidłowa tabela']);
    exit;
}

try {
    $pdo = new PDO("mysql:host=$dbHost;port=$dbPort;dbname=$dbName;charset=utf8mb4", $dbUser, $dbPass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $columns = implode(", ", array_map(fn($col) => "`$col`", $allowedTables[$table]));
    $sql = "SELECT $columns FROM `$table`";
    $params = [];

    if (isset($_GET['key'], $_GET['op'], $_GET['val'])) {
        $key = $_GET['key'];
        $op  = $_GET['op'];
        $val = $_GET['val'];

        $allowedOps = ['=', '>', '<', '>=', '<=', '!=', 'LIKE'];
        if (!in_array($op, $allowedOps) || !in_array($key, $allowedTables[$table])) {
            throw new Exception('Niedozwolone filtrowanie');
        }

        $sql .= " WHERE `$key` $op :val";
        $params[':val'] = $val;
    }

    $sql .= " LIMIT $limit";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Błąd bazy danych', 'details' => $e->getMessage()]);
    exit;
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
    exit;
}
