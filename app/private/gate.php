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
