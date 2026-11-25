<?php
require dirname(__DIR__) . '/app/bootstrap.php';
if (currentUser() !== null) { redirect('perfil.php'); }
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requirePostCsrf();
    $correo = normalizarCorreo((string)($_POST['correo'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $allowed = limite('login-ip', clientIp(), 35, 900) && limite('login-correo', $correo, 8, 900);
    if ($allowed && correoInstitucional($correo) && strlen($password) <= 1024) {
        $s=db()->prepare('SELECT u.id_usuario, u.password_hash, u.estado_cuenta
            FROM usuarios u INNER JOIN correos_autorizados c ON u.id_correo=c.id_correo
            WHERE c.correo_electronico=? LIMIT 1');
        $s->execute([$correo]); $user=$s->fetch();
        $dummy='$2y$12$FQUZg0Ug9lWXVuP8fhVa7.HFdwtfqvLm2zjku4QQoovCmcqwQM4MS';
        $valid = password_verify($password, $user['password_hash'] ?? $dummy);
        if ($user && $valid && $user['estado_cuenta'] === 'activa') {
            session_regenerate_id(true);
            $_SESSION['uid']=(int)$user['id_usuario'];
            $_SESSION['last_activity']=time();
            unset($_SESSION['csrf']);
            redirect('perfil.php');
        }
    }
    flash('No se pudo iniciar sesión. Revisa tus datos o el estado de tu cuenta.', 'error');
    redirect('index.php');
}
$notice=takeFlash(); $title='Inicio de sesión'; $page='login';
require dirname(__DIR__) . '/app/views/_header.php';
?>
<div class="split">
  <section class="hero" aria-label="Ilustración de la Clínica Robotizada">
    <div class="hero-image" role="img" aria-label="Fachada ilustrada de la Clínica Robotizada"></div>
    <div class="hero-copy"><span class="eyebrow"></span><h1>¡Bienvenido!</h1><p>Sistema Web Seguro de Avisos de la Clínica Robotizada.</p><p class="hero-muted">Consulta información institucional de manera segura.</p></div>
  </section>
  <section class="form-side"><div class="form-card">
    <div class="brand"><span class="brand-icon" aria-hidden="true">✚</span><div><strong>Clínica Robotizada</strong><small>Sistema de Avisos · UMAM</small></div></div>
    <h2>Iniciar sesión</h2><p class="intro">Accede con tu cuenta institucional autorizada.</p>
    <?php if ($notice): ?><div class="alert <?= e($notice['type']) ?>" role="alert"><?= e($notice['message']) ?></div><?php endif; ?>
    <form method="post" action="index.php" autocomplete="on">
      <input type="hidden" name="csrf" value="<?= e(tokenCsrf()) ?>">
      <label for="correo">Correo institucional</label>
      <input id="correo" name="correo" type="email" autocomplete="username" maxlength="150" required placeholder="Nombre.Apellido@aulavirtual.umam.mx">
      <label for="password">Contraseña</label>
      <div class="password-wrap"><input id="password" name="password" type="password" autocomplete="current-password" required placeholder="Ingresa tu contraseña"><button class="toggle-password" type="button" data-toggle-password="password" aria-label="Mostrar contraseña">Mostrar</button></div>
      <button class="primary-button" type="submit">Iniciar sesión</button>
    </form>
    <div class="center-link"><span>¿Aún no tienes cuenta?</span> <a href="registro.php">Crear cuenta</a></div>
    <p class="note">El acceso está limitado a correos previamente autorizados.</p>
  </div></section>
</div>
<?php require dirname(__DIR__) . '/app/views/_footer.php'; ?>
