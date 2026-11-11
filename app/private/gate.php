<?php
/**
 * TBAV geo-gate — core logic (pure, unit-testable; no side effects).
 *
 * Blocks visitors from configured countries (default: Kenya "KE"), while always
 * allowing: (a) whitelisted IPs/CIDRs, and (b) holders of a valid unlock cookie.
 * Fails OPEN: if the visitor's country can't be determined, access is allowed —
 * a mis-located international visitor should never be wrongly shut out.
 */

/** Real client IP behind Traefik: Traefik appends the connecting IP as the
 *  RIGHTMOST entry of X-Forwarded-For, so a client cannot spoof its country
 *  by pre-setting the header. Falls back to REMOTE_ADDR. */
function client_ip(array $server): string {
    if (!empty($server['HTTP_X_FORWARDED_FOR'])) {
        $parts = array_map('trim', explode(',', $server['HTTP_X_FORWARDED_FOR']));
        $ip = end($parts);
        if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
    }
    return $server['REMOTE_ADDR'] ?? '0.0.0.0';
}

/** True if $ip matches any plain IP or CIDR in $list. */
function ip_in_list(string $ip, array $list): bool {
    foreach ($list as $entry) {
        if ($entry === '') continue;
        if (strpos($entry, '/') === false) {
            if ($ip === $entry) return true;
        } elseif (cidr_match($ip, $entry)) {
            return true;
        }
    }
    return false;
}

/** CIDR membership test, IPv4 and IPv6. */
function cidr_match(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    list($subnet, $bits) = explode('/', $cidr, 2);
    $bits = (int)$bits;
    $ipb = @inet_pton($ip);
    $sub = @inet_pton($subnet);
    if ($ipb === false || $sub === false || strlen($ipb) !== strlen($sub)) return false;
    $bytes = intdiv($bits, 8);
    $rem   = $bits % 8;
    if ($bytes > 0 && substr($ipb, 0, $bytes) !== substr($sub, 0, $bytes)) return false;
    if ($rem > 0) {
        $mask = chr((0xff << (8 - $rem)) & 0xff);
        if ((substr($ipb, $bytes, 1) & $mask) !== (substr($sub, $bytes, 1) & $mask)) return false;
    }
    return true;
}

/**
 * Decide access. Returns 'allow' or 'block'.
 * @param string $ip          resolved client IP
 * @param string $country     ISO-3166 alpha-2 (may be '' when unknown)
 * @param array  $whitelist   IPs / CIDRs always allowed
 * @param array  $block       upper-case ISO codes to block
 * @param bool   $cookieValid holder of a valid unlock cookie
 */
function decide(string $ip, string $country, array $whitelist, array $block, bool $cookieValid): string {
    if (ip_in_list($ip, $whitelist)) return 'allow';
    if ($cookieValid)                return 'allow';
    $country = strtoupper($country);
    if ($country !== '' && in_array($country, $block, true)) return 'block';
    return 'allow'; // unknown country -> fail open
}

/** Look up country for an IP: bundled DB-IP mmdb first, ip-api.com fallback, '' if unknown. */
function country_of(string $ip): string {
    $db = __DIR__ . '/../geo/country.mmdb';
    if (is_readable($db) && class_exists('\GeoIp2\Database\Reader')) {
        try {
            $reader = new \GeoIp2\Database\Reader($db);
            return strtoupper($reader->country($ip)->country->isoCode ?? '');
        } catch (\Throwable $e) { /* fall through to API */ }
    }
    return country_via_api($ip);
}

/** Fallback country lookup via ip-api.com, cached 24h on disk. */
function country_via_api(string $ip): string {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';
    $dir = sys_get_temp_dir() . '/tbav_geo';
    @mkdir($dir, 0700, true);
    $cf = $dir . '/' . md5($ip);
    if (is_readable($cf) && (time() - filemtime($cf) < 86400)) {
        return trim((string)file_get_contents($cf));
    }
    $ctx = stream_context_create(['http' => ['timeout' => 2]]);
    $resp = @file_get_contents('http://ip-api.com/json/' . urlencode($ip) . '?fields=countryCode', false, $ctx);
    $cc = '';
    if ($resp) { $j = json_decode($resp, true); $cc = strtoupper($j['countryCode'] ?? ''); }
    if ($cc !== '') @file_put_contents($cf, $cc);
    return $cc;
}

/** Persistent data directory (overridable for local testing). */
function data_dir(): string {
    return rtrim(getenv('TBAV_DATA_DIR') ?: '/var/www/data', '/');
}

/** IPs/CIDRs added at runtime via the unlock link (persisted across redeploys). */
function dynamic_whitelist(): array {
    $f = data_dir() . '/allowed_ips.txt';
    if (!is_readable($f)) return [];
    $lines = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $out = [];
    foreach ($lines as $l) {
        $l = trim($l);
        if ($l !== '' && $l[0] !== '#') $out[] = $l;
    }
    return $out;
}

/** Append an IP to the persistent whitelist (deduped). */
function add_dynamic_ip(string $ip): void {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return;
    $dir = data_dir();
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    if (in_array($ip, dynamic_whitelist(), true)) return;
    @file_put_contents($dir . '/allowed_ips.txt', $ip . "\n", FILE_APPEND | LOCK_EX);
}

/** Heuristic spam check for a submitted lead. Returns true if it looks like a bot. */
function looks_like_spam(array $f): bool {
    // A URL in the name or company field is a near-certain bot signal.
    foreach (['name', 'company'] as $k) {
        if (preg_match('~https?://|www\.~i', (string)($f[$k] ?? ''))) return true;
    }
    $msg = (string)($f['message'] ?? '');
    // Link-stuffed messages (two or more URLs) or BBCode link spam.
    if (preg_match_all('~https?://~i', $msg, $m) >= 2) return true;
    if (preg_match('~\[url[=\]]|\[/url\]~i', $msg)) return true;
    return false;
}

/**
 * Per-IP submission rate limit, persisted on disk. Prunes entries older than
 * the window, counts this IP's recent submissions, and records the new attempt
 * when under the cap. Fails OPEN on any storage error (never blocks a real lead).
 * Returns true if the submission is allowed.
 */
function rate_ok(string $ip, int $max = 10, int $window = 3600): bool {
    $dir = data_dir();
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    $file = $dir . '/rate.log';
    $fh = @fopen($file, 'c+');
    if (!$fh) return true;
    @flock($fh, LOCK_EX);
    $now  = time();
    $keep = [];
    $count = 0;
    rewind($fh);
    while (($line = fgets($fh)) !== false) {
        $line = trim($line);
        if ($line === '') continue;
        list($t, $xip) = array_pad(explode(' ', $line, 2), 2, '');
        $t = (int)$t;
        if ($now - $t > $window) continue; // prune
        $keep[] = $t . ' ' . $xip;
        if ($xip === $ip) $count++;
    }
    $allowed = $count < $max;
    if ($allowed) $keep[] = $now . ' ' . $ip;
    @ftruncate($fh, 0);
    rewind($fh);
    @fwrite($fh, $keep ? implode("\n", $keep) . "\n" : '');
    @flock($fh, LOCK_UN);
    @fclose($fh);
    return $allowed;
}

/** Append a lead to the persistent CSV. Returns true on success. */
function save_lead(array $f): bool {
    $dir = data_dir();
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    $file = $dir . '/leads.csv';
    $new = !is_file($file);
    $fh = @fopen($file, 'a');
    if (!$fh) return false;
    @flock($fh, LOCK_EX);
    if ($new) @fputcsv($fh, ['timestamp', 'ip', 'name', 'company', 'country', 'email', 'sector', 'message']);
    @fputcsv($fh, [date('c'), $f['ip'] ?? '', $f['name'] ?? '', $f['company'] ?? '', $f['country'] ?? '', $f['email'] ?? '', $f['sector'] ?? '', $f['message'] ?? '']);
    @flock($fh, LOCK_UN);
    @fclose($fh);
    return true;
}

/** Email a lead via SMTP (configured through env). Returns true if sent. */
function send_lead_email(array $f): bool {
    $host = getenv('TBAV_SMTP_HOST');
    if (!$host || !class_exists('\\PHPMailer\\PHPMailer\\PHPMailer')) return false;
    $to   = getenv('TBAV_MAIL_TO')   ?: 'mail@tenderbridgeafrica.com';
    $from = getenv('TBAV_MAIL_FROM') ?: $to;
    $user = getenv('TBAV_SMTP_USER') ?: $from;
    $pass = getenv('TBAV_SMTP_PASS') ?: '';
    $port = (int) (getenv('TBAV_SMTP_PORT') ?: 587);
    $secure = strtolower(getenv('TBAV_SMTP_SECURE') ?: 'tls');
    try {
        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = $host;
        $mail->SMTPAuth = true;
        $mail->Username = $user;
        $mail->Password = $pass;
        $mail->SMTPSecure = ($secure === 'ssl')
            ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS
            : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = $port;
        $mail->CharSet = 'UTF-8';
        $mail->setFrom($from, 'TBAV Website');
        $mail->addAddress($to);
        if (filter_var($f['email'] ?? '', FILTER_VALIDATE_EMAIL)) {
            $mail->addReplyTo($f['email'], $f['name'] ?? '');
        }
        $mail->Subject = 'New brief request: ' . (($f['company'] ?? '') ?: 'Unknown')
            . (($f['sector'] ?? '') ? ' (' . $f['sector'] . ')' : '');
        $mail->Body =
            "New opportunity-brief request from the website:\n\n" .
            "Name:    " . ($f['name'] ?? '') . "\n" .
            "Company: " . ($f['company'] ?? '') . "\n" .
            "Country: " . ($f['country'] ?? '') . "\n" .
            "Email:   " . ($f['email'] ?? '') . "\n" .
            "Sector:  " . ($f['sector'] ?? '') . "\n" .
            "Message: " . ($f['message'] ?? '') . "\n\n" .
            "IP: " . ($f['ip'] ?? '') . "   Time: " . date('c') . "\n";
        $mail->send();
        return true;
    } catch (\Throwable $e) {
        error_log('TBAV mail error: ' . $e->getMessage());
        return false;
    }
}
