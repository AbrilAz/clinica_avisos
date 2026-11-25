<?php
// EJECUTAR SOLO EN CONSOLA: php mostrar-codigo.php Nombre.Apellido@aulavirtual.umam.mx
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
$email=strtolower(trim((string)($argv[1] ?? '')));
if (!filter_var($email,FILTER_VALIDATE_EMAIL) || !str_ends_with($email,'@aulavirtual.umam.mx')) { exit("Especifica un correo institucional válido.\n"); }
$file=dirname(__DIR__).'/storage/verificaciones/'.hash('sha256',$email).'.txt';
if (!is_file($file)) { exit("Sin código pendiente para ese correo.\n"); }
echo file_get_contents($file);
