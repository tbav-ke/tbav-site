<?php
require_once __DIR__ . '/app/private/gate.php';

$pass = 0; $fail = 0;
function check($label, $got, $want) {
    global $pass, $fail;
    $ok = ($got === $want);
    printf("[%s] %s  (got: %s, want: %s)\n", $ok ? 'PASS' : 'FAIL', $label,
        var_export($got, true), var_export($want, true));
    $ok ? $pass++ : $fail++;
}

$KE_IP = '41.90.64.1';   // a Kenyan range (Safaricom)
$US_IP = '8.8.8.8';
$block = ['KE'];

// --- decide(): the access decision ---
check('KE visitor is blocked',            decide($KE_IP, 'KE', [], $block, false), 'block');
check('US visitor is allowed',            decide($US_IP, 'US', [], $block, false), 'allow');
check('KE but whitelisted (exact IP)',    decide($KE_IP, 'KE', [$KE_IP], $block, false), 'allow');
check('KE but whitelisted (CIDR)',        decide($KE_IP, 'KE', ['41.90.0.0/16'], $block, false), 'allow');
check('KE but valid unlock cookie',       decide($KE_IP, 'KE', [], $block, true), 'allow');
check('unknown country fails OPEN',       decide($KE_IP, '',   [], $block, false), 'allow');
check('lowercase country still blocks',   decide($KE_IP, 'ke', [], $block, false), 'block');

// --- cidr_match() ---
check('IPv4 inside /16',   cidr_match('41.90.64.1', '41.90.0.0/16'), true);
check('IPv4 outside /16',  cidr_match('41.91.0.1',  '41.90.0.0/16'), false);
check('IPv4 inside /24',   cidr_match('197.248.3.9','197.248.3.0/24'), true);
check('IPv4 /32 exact',    cidr_match('5.6.7.8',    '5.6.7.8/32'), true);
check('IPv6 inside /32',   cidr_match('2c0f:fe38::1','2c0f:fe38::/32'), true);
check('bad input no crash', cidr_match('not-an-ip', '41.90.0.0/16'), false);

// --- ip_in_list() ---
check('match in mixed list', ip_in_list('203.0.113.5', ['198.51.100.0/24','203.0.113.5']), true);
check('no match in list',    ip_in_list('203.0.113.9', ['198.51.100.0/24','203.0.113.5']), false);
check('empty list',          ip_in_list('203.0.113.5', []), false);

// --- client_ip(): Traefik appends real IP as RIGHTMOST of XFF (anti-spoof) ---
check('XFF single IP',   client_ip(['HTTP_X_FORWARDED_FOR' => '203.0.113.7']), '203.0.113.7');
check('XFF rightmost wins (spoof attempt)',
      client_ip(['HTTP_X_FORWARDED_FOR' => '1.1.1.1, 203.0.113.7']), '203.0.113.7');
check('falls back to REMOTE_ADDR', client_ip(['REMOTE_ADDR' => '10.0.0.5']), '10.0.0.5');
check('ignores garbage XFF -> REMOTE_ADDR',
      client_ip(['HTTP_X_FORWARDED_FOR' => 'junk', 'REMOTE_ADDR' => '10.0.0.9']), '10.0.0.9');

echo "\n================  $pass passed, $fail failed  ================\n";
exit($fail === 0 ? 0 : 1);
