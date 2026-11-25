<?php
require dirname(__DIR__).'/app/bootstrap.php';
if (currentUser() !== null) { redirect('perfil.php'); }
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requirePostCsrf();
    $correo=normalizarCorreo((string)($_POST['correo'] ?? ''));
    $code=trim((string)($_POST['codigo'] ?? ''));
    $ok=false;
    if (correoInstitucional($correo) && preg_match('/^[0-9]{8}$/D', $code)
        && limite('verify-ip', clientIp(), 25, 3600) && limite('verify-correo', $correo, 6, 3600)) {
        $s=db()->prepare('SELECT u.id_usuario,u.token_verificacion_hash,u.token_expiracion
            FROM usuarios u JOIN correos_autorizados c ON c.id_correo=u.id_correo
            WHERE c.correo_electronico=? AND u.estado_cuenta=\'pendiente\' LIMIT 1');
        $s->execute([$correo]); $u=$s->fetch();
        if ($u && $u['token_verificacion_hash'] && $u['token_expiracion'] && strtotime($u['token_expiracion']) > time()) {
            $ok=password_verify($code, $u['token_verificacion_hash']);
            if ($ok) {
                $up=db()->prepare("UPDATE usuarios SET estado_cuenta='activa', token_verificacion_hash=NULL, token_expiracion=NULL, fecha_verificacion=NOW() WHERE id_usuario=? AND estado_cuenta='pendiente'");
                $up->execute([$u['id_usuario']]);
                $path=dirname(__DIR__).'/storage/verificaciones/'.hash('sha256',$correo).'.txt';
                if (is_file($path)) { @unlink($path); }
            }
        }
    }
    flash($ok ? 'Cuenta activada. Ahora puedes iniciar sesión.' : 'No se pudo verificar el código. Revisa los datos o solicita ayuda al responsable.', $ok ? 'success':'error');
    redirect($ok ? 'index.php' : 'verificar_correo.php');
}
$notice=takeFlash(); $title='Verificar cuenta'; $page='verify'; require dirname(__DIR__).'/app/views/_header.php';
?>
<main class="simple-shell"><div class="simple-card"><div class="brand"><span class="brand-icon" aria-hidden="true">✚</span><div><strong>Clínica Robotizada</strong><small>Sistema de Avisos · UMAM</small></div></div>
<h1>Verificar cuenta</h1><p class="intro">Introduce el código de 8 dígitos de la demostración. El responsable del servidor puede consultarlo de forma privada. Caduca en 15 minutos.</p>
<?php if ($notice): ?><div class="alert <?= e($notice['type']) ?>" role="alert"><?= e($notice['message']) ?></div><?php endif; ?>
<form method="post" action="verificar_correo.php"><input type="hidden" name="csrf" value="<?= e(tokenCsrf()) ?>"><label for="correo">Correo institucional</label><input id="correo" name="correo" type="email" maxlength="150" required value="<?= e((string)($_SESSION['pending_email'] ?? '')) ?>"><label for="codigo">Código de verificación</label><input id="codigo" name="codigo" type="text" inputmode="numeric" pattern="[0-9]{8}" maxlength="8" autocomplete="one-time-code" required placeholder="8 dígitos"><button class="primary-button" type="submit">Verificar cuenta</button></form><p class="note">Modo académico: esta verificación no prueba la titularidad de un correo real.</p><div class="center-link"><a href="index.php">Volver al inicio de sesión</a></div></div></main>
<?php require dirname(__DIR__).'/app/views/_footer.php'; ?>
