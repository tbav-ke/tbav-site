<?php
/**
 * TBAV marketing site — front controller + geo-gate.
 * Routes:
 *   /unlock?key=SECRET  set a 180-day browser pass AND whitelist the caller's IP
 *   POST /submit        contact form -> persistent CSV + email notification
 *   everything else     geo-gated site (blocks configured countries)
 * Config via environment (set in Coolify; never committed):
 *   TBAV_UNLOCK_SECRET    secret for /unlock
 *   TBAV_WHITELIST_IPS    comma/space separated IPs or CIDRs always allowed
 *   TBAV_BLOCK_COUNTRIES  comma separated ISO codes to block (default "KE")
 *   TBAV_COOKIE_DAYS      unlock-cookie lifetime in days (default 180)
 *   TBAV_SMTP_HOST/PORT/USER/PASS/SECURE, TBAV_MAIL_TO, TBAV_MAIL_FROM  (email)
 */

$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_readable($autoload)) require_once $autoload;
require_once __DIR__ . '/../private/gate.php';

$UNLOCK_SECRET = (string) (getenv('TBAV_UNLOCK_SECRET') ?: '');
$ENV_WHITELIST = preg_split('/[\s,]+/', (string)(getenv('TBAV_WHITELIST_IPS') ?: ''), -1, PREG_SPLIT_NO_EMPTY);
$WHITELIST = array_merge($ENV_WHITELIST, dynamic_whitelist());
$BLOCK = array_map('strtoupper', preg_split('/[\s,]+/', (string)(getenv('TBAV_BLOCK_COUNTRIES') ?: 'KE'), -1, PREG_SPLIT_NO_EMPTY));
$COOKIE_DAYS = (int) (getenv('TBAV_COOKIE_DAYS') ?: 180);
$COOKIE_NAME = 'tbav_access';

$ip     = client_ip($_SERVER);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$cookieToken = $UNLOCK_SECRET !== '' ? hash_hmac('sha256', 'tbav-unlock', $UNLOCK_SECRET) : '';

// --- /unlock?key=SECRET -> set browser pass AND whitelist this IP ---
if ($path === '/unlock') {
    if ($UNLOCK_SECRET !== '' && hash_equals($UNLOCK_SECRET, (string)($_GET['key'] ?? ''))) {
        setcookie($COOKIE_NAME, $cookieToken, [
            'expires'  => time() + $COOKIE_DAYS * 86400,
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        add_dynamic_ip($ip);
        header('Location: /');
        echo 'Access granted. Redirecting…';
        exit;
    }
    http_response_code(403);
    echo 'Invalid key.';
    exit;
}

// --- POST /submit -> contact form (store + email) ---
if ($path === '/submit' && $method === 'POST') {
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    // Honeypot: silently accept (and drop) bots that fill the hidden field.
    if (!empty($_POST['website'])) { echo json_encode(['ok' => true]); exit; }

    $f = ['ip' => $ip];
    foreach (['name', 'company', 'country', 'email', 'sector', 'message'] as $k) {
        $f[$k] = mb_substr(trim((string)($_POST[$k] ?? '')), 0, 2000);
    }
    // Every field is required; email must be valid; the description must be real.
    if ($f['name'] === '' || $f['company'] === '' || $f['country'] === ''
        || $f['sector'] === '' || mb_strlen($f['message']) < 15
        || !filter_var($f['email'], FILTER_VALIDATE_EMAIL)) {
        http_response_code(422);
        echo json_encode(['ok' => false, 'error' => 'invalid']);
        exit;
    }
    // Bot/spam hardening (office + whitelisted IPs are exempt so testing is never blocked):
    //   - submit-too-fast time trap (a human cannot complete this form in < 2.5s; a direct POST sends elapsed=0)
    //   - URL-in-name / link-stuffing heuristics
    //   - per-IP rate limit
    // On any trip we return a fake success so bots learn nothing; nothing is stored or emailed.
    $trusted = ip_in_list($ip, $WHITELIST);
    $elapsed = (int)($_POST['elapsed'] ?? 0);
    if (!$trusted && ($elapsed < 2500 || looks_like_spam($f) || !rate_ok($ip))) {
        echo json_encode(['ok' => true]);
        exit;
    }
    $saved  = save_lead($f);
    $mailed = send_lead_email($f);
    echo json_encode(['ok' => ($saved || $mailed)]);
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
