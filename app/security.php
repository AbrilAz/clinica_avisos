<?php
declare(strict_types=1);
function e(?string $value): string { return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function tokenCsrf(): string {
    if (!isset($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
    return $_SESSION['csrf'];
}
function csrfValido(): bool {
    return isset($_POST['csrf'], $_SESSION['csrf']) && is_string($_POST['csrf'])
        && hash_equals((string)$_SESSION['csrf'], $_POST['csrf']);
}
function requirePostCsrf(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !csrfValido()) {
        http_response_code(403); exit('Solicitud no autorizada. Actualiza la página e inténtalo otra vez.');
    }
}
function redirect(string $page): never { header('Location: ' . $page, true, 303); exit; }
function normalizarCorreo(string $email): string { return strtolower(trim($email)); }
function correoInstitucional(string $email): bool {
    global $config;
    return strlen($email) <= 150 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false
        && str_ends_with($email, '@' . strtolower((string)$config['institution_domain']));
}
function flash(string $message, string $type = 'info'): void { $_SESSION['flash'] = ['message' => $message, 'type' => $type]; }
function takeFlash(): ?array { $x = $_SESSION['flash'] ?? null; unset($_SESSION['flash']); return is_array($x) ? $x : null; }
function limite(string $scope, string $key, int $max, int $seconds): bool {
    $path = dirname(__DIR__) . '/storage/limites/' . hash('sha256', $scope . ':' . $key) . '.json';
    $handle = fopen($path, 'c+'); if ($handle === false) { throw new RuntimeException('Error de límite'); }
    try {
        if (!flock($handle, LOCK_EX)) { throw new RuntimeException('Error de bloqueo'); }
        $old = stream_get_contents($handle);
        $data = json_decode($old ?: '', true);
        $now = time();
        if (!is_array($data) || ($data['start'] ?? 0) <= $now - $seconds) { $data = ['start' => $now, 'count' => 0]; }
        $allowed = $data['count'] < $max;
        $data['count']++;
        rewind($handle); ftruncate($handle, 0);
        fwrite($handle, json_encode($data, JSON_THROW_ON_ERROR)); fflush($handle);
        return $allowed;
    } finally { flock($handle, LOCK_UN); fclose($handle); }
}
function clientIp(): string { return (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'); }
function currentUser(): ?array {
    if (!isset($_SESSION['uid']) || !is_int($_SESSION['uid'])) { return null; }
    if (isset($_SESSION['last_activity']) && time() - (int)$_SESSION['last_activity'] > 1800) {
        $_SESSION = []; session_regenerate_id(true); return null;
    }
    $s = db()->prepare('SELECT u.id_usuario, u.nombre_completo, u.estado_cuenta, u.fecha_registro, c.correo_electronico, r.nombre_rol
        FROM usuarios u INNER JOIN correos_autorizados c ON c.id_correo=u.id_correo
        INNER JOIN roles r ON r.id_rol=c.id_rol WHERE u.id_usuario=? LIMIT 1');
    $s->execute([$_SESSION['uid']]); $user=$s->fetch();
    if (!$user || $user['estado_cuenta'] !== 'activa') { $_SESSION=[]; session_regenerate_id(true); return null; }
    $_SESSION['last_activity'] = time();
    return $user;
}
function requireUser(): array {
    $user = currentUser();
    if ($user === null) { redirect('index.php'); }
    return $user;
}
