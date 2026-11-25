<?php
require dirname(__DIR__).'/app/bootstrap.php';
$title='Uso académico y privacidad'; $page='privacy'; require dirname(__DIR__).'/app/views/_header.php';
?>
<main class="simple-shell"><div class="simple-card"><h1>Uso académico y privacidad</h1><p>Este sistema es un prototipo académico de la Clínica Robotizada UMAM, destinado a evaluar autenticación y control de acceso.</p><p>Se almacenan nombre, correo institucional autorizado, contraseña en formato hash y fechas de registro y verificación. Los datos no deben incluir información clínica real.</p><p>Durante las pruebas, los códigos se consultan localmente en un directorio privado del servidor. No se enviarán correos reales.</p><p>El acceso a las cuentas se limita al personal autorizado para la evaluación. Para rectificaciones o eliminación de datos de prueba, contacta al responsable del proyecto.</p><div class="center-link"><a href="registro.php">Volver a crear cuenta</a></div></div></main>
<?php require dirname(__DIR__).'/app/views/_footer.php'; ?>
