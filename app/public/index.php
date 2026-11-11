<?php
/**
 * TBAV marketing site — front controller + geo-gate.
 * Config comes from environment (set in Coolify; never committed):
 *   TBAV_UNLOCK_SECRET    secret for the /unlock?key=... bypass link
 *   TBAV_WHITELIST_IPS    comma/space separated IPs or CIDRs always allowed
 *   TBAV_BLOCK_COUNTRIES  comma separated ISO codes to block (default "KE")
 *   TBAV_COOKIE_DAYS      unlock-cookie lifetime in days (default 180)
 */

$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_readable($autoload)) require_once $autoload;
require_once __DIR__ . '/../private/gate.php';

$UNLOCK_SECRET = (string) (getenv('TBAV_UNLOCK_SECRET') ?: '');
$WHITELIST = preg_split('/[\s,]+/', (string)(getenv('TBAV_WHITELIST_IPS') ?: ''), -1, PREG_SPLIT_NO_EMPTY);
$BLOCK = array_map('strtoupper', preg_split('/[\s,]+/', (string)(getenv('TBAV_BLOCK_COUNTRIES') ?: 'KE'), -1, PREG_SPLIT_NO_EMPTY));
$COOKIE_DAYS = (int) (getenv('TBAV_COOKIE_DAYS') ?: 180);
$COOKIE_NAME = 'tbav_access';

$ip   = client_ip($_SERVER);
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$cookieToken = $UNLOCK_SECRET !== '' ? hash_hmac('sha256', 'tbav-unlock', $UNLOCK_SECRET) : '';

// --- /unlock?key=SECRET -> set bypass cookie ---
if ($path === '/unlock') {
    if ($UNLOCK_SECRET !== '' && hash_equals($UNLOCK_SECRET, (string)($_GET['key'] ?? ''))) {
        setcookie($COOKIE_NAME, $cookieToken, [
            'expires'  => time() + $COOKIE_DAYS * 86400,
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        header('Location: /');
        echo 'Access granted. Redirecting…';
        exit;
    }
    http_response_code(403);
    echo 'Invalid key.';
    exit;
}

// --- decide access ---
$cookieValid = $UNLOCK_SECRET !== ''
    && isset($_COOKIE[$COOKIE_NAME])
    && hash_equals($cookieToken, (string)$_COOKIE[$COOKIE_NAME]);

$country = ($cookieValid || ip_in_list($ip, $WHITELIST)) ? '' : country_of($ip);

if (decide($ip, $country, $WHITELIST, $BLOCK, $cookieValid) === 'block') {
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    readfile(__DIR__ . '/../private/blocked.html');
    exit;
}

// --- serve the site ---
header('Content-Type: text/html; charset=utf-8');
readfile(__DIR__ . '/../private/site.html');
