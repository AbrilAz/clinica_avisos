<?php
require dirname(__DIR__) . '/app/bootstrap.php';
if (currentUser() !== null) { redirect('perfil.php'); }
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requirePostCsrf();
    $nombres = trim((string)($_POST['nombres'] ?? ''));
    $apellidoPaterno = trim((string)($_POST['apellido_paterno'] ?? ''));
    $apellidoMaterno = trim((string)($_POST['apellido_materno'] ?? ''));
    $nombre = trim($nombres . ' ' . $apellidoPaterno . ' ' . $apellidoMaterno);
    $correo=normalizarCorreo((string)($_POST['correo'] ?? ''));
    $password=(string)($_POST['password'] ?? '');
    $confirmar=(string)($_POST['confirmar'] ?? '');
    $validField = static function (string $value, bool $required): bool {
        $length = mb_strlen($value, 'UTF-8');
        return (!$required && $length === 0)
            || ($length >= 1 && $length <= 100 && !preg_match('/[<>\x00-\x1F]/u', $value));
    };
    $validName = $validField($nombres, true)
        && $validField($apellidoPaterno, true)
        && $validField($apellidoMaterno, false)
        && mb_strlen($nombre, 'UTF-8') <= 100;
    $validPass=strlen($password) >= 12 && strlen($password) <= 72 && hash_equals($password, $confirmar);
    if (!limite('registro-ip', clientIp(), 12, 3600)) {
        flash('Demasiadas solicitudes. Inténtalo más tarde.', 'error'); redirect('registro.php');
    }
    if (!$validName || !correoInstitucional($correo) || !$validPass || !isset($_POST['acepto'])) {
        flash('Revisa los datos: Datos invalidos.', 'error'); redirect('registro.php');
    }
    $s=db()->prepare('SELECT c.id_correo, r.nombre_rol FROM correos_autorizados c
        INNER JOIN roles r ON r.id_rol=c.id_rol
        WHERE c.correo_electronico=? LIMIT 1');
    $s->execute([$correo]); $auth=$s->fetch();
    if ($auth && in_array($auth['nombre_rol'], ['profesor','estudiante'], true)) {
        $already=db()->prepare('SELECT id_usuario FROM usuarios WHERE id_correo=?');
        $already->execute([$auth['id_correo']]);
        if (!$already->fetch()) {
            $code=(string)random_int(10000000, 99999999);
            $expires=date('Y-m-d H:i:s', time()+900);
            $hash=password_hash($password, PASSWORD_DEFAULT);
            $tokenHash=password_hash($code, PASSWORD_DEFAULT);
            try {
                db()->beginTransaction();
                $insert=db()->prepare("INSERT INTO usuarios(id_correo,nombre_completo,nombres,apellido_paterno,apellido_materno,password_hash,estado_cuenta,token_verificacion_hash,token_expiracion) VALUES(?,?,?,?,?,?,'pendiente',?,?)");
                $insert->execute([$auth['id_correo'],$nombre,$nombres,$apellidoPaterno,$apellidoMaterno !== '' ? $apellidoMaterno : null,$hash,$tokenHash,$expires]);
                // Solo dentro de storage privado; nunca disponible por HTTP.
                $path=dirname(__DIR__).'/storage/verificaciones/'.hash('sha256',$correo).'.txt';
                $content="DEMOSTRACIÓN: No acredita propiedad real del correo.\nCorreo: {$correo}\nCódigo: {$code}\nCaduca: {$expires}\n";
                if (file_put_contents($path,$content,LOCK_EX) === false) { throw new RuntimeException('No se pudo guardar código de demostración'); }
                @chmod($path,0600);
                db()->commit();
            } catch (PDOException $ex) {
                if (db()->inTransaction()) { db()->rollBack(); }
                if (($ex->errorInfo[1] ?? null) !== 1062) { throw $ex; }
            } catch (Throwable $ex) {
                if (db()->inTransaction()) { db()->rollBack(); }
                throw $ex;
            }
        }
    }
    $_SESSION['pending_email']=$correo;
    flash('Si el correo está autorizado y no tiene cuenta, se generó un código de demostración. Solicítalo al responsable del sistema.', 'info');
    redirect('verificar_correo.php');
}
$notice=takeFlash(); $title='Crear cuenta'; $page='register'; require dirname(__DIR__).'/app/views/_header.php';
?>
<div class="split">
  <section class="hero" aria-label="Ilustración de la Clínica Robotizada"><div class="hero-image" role="img" aria-label="Fachada ilustrada de la Clínica Robotizada"></div><div class="hero-copy"><span class="eyebrow">UMAM · Equipo 9</span><h1>¡Crea tu cuenta!</h1><p>Únete al sistema de avisos de la Clínica Robotizada.</p><p class="hero-muted">Registro exclusivo con autorización institucional.</p></div></section>
  <section class="form-side"><div class="form-card"><div class="brand"><span class="brand-icon" aria-hidden="true">✚</span><div><strong>Clínica Robotizada</strong><small>Sistema de Avisos · UMAM</small></div></div><h2>Crear cuenta</h2><p class="intro">Completa tus datos para solicitar el acceso.</p>
    <?php if ($notice): ?><div class="alert <?= e($notice['type']) ?>" role="alert"><?= e($notice['message']) ?></div><?php endif; ?>
    <form method="post" action="registro.php">
      <input type="hidden" name="csrf" value="<?= e(tokenCsrf()) ?>">
      <label for="nombres">Nombre(s)</label><input id="nombres" name="nombres" type="text" maxlength="100" autocomplete="given-name" required placeholder="Ingresa tu nombre(s)">
      <label for="apellido_paterno">Apellido paterno</label><input id="apellido_paterno" name="apellido_paterno" type="text" maxlength="100" autocomplete="family-name" required placeholder="Ingresa tu apellido paterno">
      <label for="apellido_materno">Apellido materno (opcional)</label><input id="apellido_materno" name="apellido_materno" type="text" maxlength="100" placeholder="Ingresa tu apellido materno">
      <label for="correo">Correo institucional</label><input id="correo" name="correo" type="email" maxlength="150" autocomplete="email" required placeholder="Nombre.Apellido@aulavirtual.umam.mx">
      <label for="password">Contraseña</label><div class="password-wrap"><input id="password" name="password" type="password" minlength="12" maxlength="72" autocomplete="new-password" required aria-describedby="password-help" placeholder="Crea una contraseña"><button class="toggle-password" type="button" data-toggle-password="password" aria-label="Mostrar contraseña">Mostrar</button></div><p id="password-help" class="hint">Usa al menos 12 caracteres y máximo 72 bytes; se permiten frases de contraseña.</p>
      <label for="confirmar">Confirmar contraseña</label><div class="password-wrap"><input id="confirmar" name="confirmar" type="password" minlength="12" maxlength="72" autocomplete="new-password" required placeholder="Confirma tu contraseña"><button class="toggle-password" type="button" data-toggle-password="confirmar" aria-label="Mostrar confirmación de contraseña">Mostrar</button></div>
      <label class="check"><input type="checkbox" name="acepto" value="1" required> <span>He leído el <a href="privacidad.php">aviso de uso académico y privacidad</a>.</span></label>
      <button type="submit" class="primary-button">Crear cuenta</button>
    </form>
    <div class="center-link">¿Ya tienes cuenta? <a href="index.php">Iniciar sesión</a></div>
    <p class="note">El rol se asigna por autorización previa; no se elige al registrarse.</p>
  </div></section>
</div>
<?php require dirname(__DIR__).'/app/views/_footer.php'; ?>
