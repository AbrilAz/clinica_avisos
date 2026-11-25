<?php
// EJECUTAR SOLO EN CONSOLA LOCAL: php C:\xampp\htdocs\clinica_avisos\scripts\crear-superusuario.php
// Archivo privado: protegido por Apache, solo uso CLI local.
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(403); exit('Solo consola.'); }
require dirname(__DIR__).'/app/bootstrap.php';
function prompt(string $label): string { echo $label; return trim((string)fgets(STDIN)); }
$email=normalizarCorreo(prompt('Correo ficticio autorizado del superusuario: '));
$name=prompt('Nombre completo: ');
$password=prompt('Contraseña (se muestra al escribir; 12 a 72 bytes): ');
if (!correoInstitucional($email) || mb_strlen($name) < 3 || mb_strlen($name) > 100 || strlen($password) < 12 || strlen($password) > 72) { exit("Datos inválidos.\n"); }
// No crear superusuario si ya existe uno activo.
$s=db()->query("SELECT COUNT(*) FROM usuarios u JOIN correos_autorizados c ON c.id_correo=u.id_correo JOIN roles r ON r.id_rol=c.id_rol WHERE r.nombre_rol='superusuario' AND u.estado_cuenta='activa'");
if ((int)$s->fetchColumn() > 0) { exit("Ya existe un superusuario activo.\n"); }
try {
    db()->beginTransaction();
    $s=db()->query("SELECT id_rol FROM roles WHERE nombre_rol='superusuario'");
    $role=$s->fetchColumn(); if (!$role) { throw new RuntimeException('Falta rol superusuario'); }
    $s=db()->prepare('INSERT INTO correos_autorizados(correo_electronico,id_rol) VALUES(?,?)');
    $s->execute([$email,$role]);
    $id=(int)db()->lastInsertId();
    $s=db()->prepare("INSERT INTO usuarios(id_correo,nombre_completo,password_hash,estado_cuenta,fecha_verificacion) VALUES(?,?,?,'activa',NOW())");
    $s->execute([$id,$name,password_hash($password,PASSWORD_DEFAULT)]);
    db()->commit(); echo "Cuenta inicial de demostración creada. Elimina o protege este script tras la instalación.\n";
} catch(Throwable $e) { if (db()->inTransaction()) db()->rollBack(); echo "No se pudo crear. Verifica que el correo no exista y que estén las seis tablas.\n"; exit(1); }
