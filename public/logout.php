<?php
require dirname(__DIR__).'/app/bootstrap.php';
requirePostCsrf();
$_SESSION=[];
if (ini_get('session.use_cookies')) {
    $p=session_get_cookie_params();
    setcookie(session_name(), '', ['expires'=>time()-3600,'path'=>$p['path'],'domain'=>$p['domain'],'secure'=>$p['secure'],'httponly'=>$p['httponly'],'samesite'=>$p['samesite']]);
}
session_destroy();
redirect('index.php');
