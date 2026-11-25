<?php
declare(strict_types=1);

$configFile = dirname(__DIR__) . '/config/config.php';
if (!is_file($configFile)) {
    http_response_code(503);
    exit('Configuración pendiente. Consulta las instrucciones de instalación.');
}
$config = require $configFile;
if (!is_array($config) || ($config['db_user'] ?? '') === 'TU_USUARIO') {
    http_response_code(503);
    exit('Configuración incompleta.');
}
if (($config['mode'] ?? '') !== 'demo') {
    http_response_code(503);
    exit('Modo de correo no configurado.');
}

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') === '443');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', $isHttps ? '1' : '0');
session_name('EQ9SESSID');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/clinica_avisos/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax'
]);
if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Cache-Control: no-store, private');
if ($isHttps) { header('Strict-Transport-Security: max-age=31536000'); }

set_exception_handler(static function (Throwable $e): void {
    error_log('[equipo-9] ' . $e->getMessage());
    http_response_code(500);
    echo 'Ocurrió un error interno. Contacta al responsable del sistema.';
});

require_once __DIR__ . '/security.php';
require_once __DIR__ . '/database.php';
