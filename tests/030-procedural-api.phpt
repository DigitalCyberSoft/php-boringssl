--TEST--
Procedural function API - PHP-idiomatic boringssl_* functions
--EXTENSIONS--
boringssl
--FILE--
<?php
// Test the procedural API that mirrors PHP's traditional function style
// (like curl_init/curl_setopt/curl_exec, openssl_encrypt, socket_create, etc.)

// Test 1: Full Chrome-like config using procedural functions
$ctx = boringssl_context_new();
boringssl_context_set_min_proto_version($ctx, BoringSSL\TLS1_2_VERSION);
boringssl_context_set_max_proto_version($ctx, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_cipher_list($ctx,
    'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' .
    'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
);
boringssl_context_set_groups_list($ctx, 'X25519:P-256:P-384');
boringssl_context_set_verify_algorithm_prefs($ctx, [
    BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
    BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
    BoringSSL\SIGALG_RSA_PKCS1_SHA256,
]);
boringssl_context_set_grease($ctx, true);
boringssl_context_set_permute_extensions($ctx, true);
boringssl_context_add_cert_compression_alg($ctx, BoringSSL\CERT_COMPRESS_BROTLI);
boringssl_context_add_application_settings($ctx, 'h2', '');
boringssl_context_set_alps_use_new_codepoint($ctx, true);
boringssl_context_set_early_data($ctx, false);
echo "Context configured\n";

// Test 2: Connect and do I/O
$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn = boringssl_new_connection($ctx);
boringssl_set_stream($conn, $tcp);
boringssl_connect($conn);

echo "Cipher: " . boringssl_get_cipher($conn) . "\n";
echo "Group: " . boringssl_get_group($conn) . "\n";
echo "Version: 0x" . dechex(boringssl_get_version($conn)) . "\n";

boringssl_write($conn, "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$resp = boringssl_read($conn, 64);
echo "Response: " . strtok($resp, "\r\n") . "\n";

$pending = boringssl_pending($conn);
echo "Pending > 0: " . ($pending > 0 ? "yes" : "no") . "\n";

boringssl_shutdown($conn);
fclose($tcp);

// Test 3: Server context
$server_ctx = boringssl_context_new_server();
echo "Server context: " . get_class($server_ctx) . "\n";

// Test 4: Objects returned by procedural functions work with OOP methods
$ctx2 = boringssl_context_new();
boringssl_context_set_min_proto_version($ctx2, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_max_proto_version($ctx2, BoringSSL\TLS1_3_VERSION);
boringssl_context_set_groups_list($ctx2, 'X25519');

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = boringssl_new_connection($ctx2);
boringssl_set_stream($conn2, $tcp2);
boringssl_connect($conn2);

// Mix procedural and OOP
echo "Procedural cipher: " . boringssl_get_cipher($conn2) . "\n";
echo "OOP cipher: " . $conn2->getNegotiatedCipher() . "\n";
echo "Match: " . (boringssl_get_cipher($conn2) === $conn2->getNegotiatedCipher() ? "yes" : "FAIL") . "\n";

boringssl_shutdown($conn2);
fclose($tcp2);

// Test 5: Session functions
$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = boringssl_new_connection($ctx2);
boringssl_set_stream($conn3, $tcp3);
boringssl_connect($conn3);
boringssl_write($conn3, "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
boringssl_read($conn3, 256);

$session = boringssl_get_session($conn3);
if ($session !== null) {
    $bytes = boringssl_session_to_bytes($session);
    echo "Session serialized: " . strlen($bytes) . " bytes\n";
    $restored = boringssl_session_from_bytes($bytes, $ctx2);
    echo "Session restored: " . get_class($restored) . "\n";
    echo "Timeout: " . boringssl_session_get_timeout($session) . "s\n";
} else {
    echo "Session: not available\n";
}

boringssl_shutdown($conn3);
fclose($tcp3);

// Test 6: Error handling same as OOP
try {
    boringssl_context_set_groups_list($ctx, 'INVALID_GROUP');
    echo "FAIL\n";
} catch (BoringSSL\Exception $e) {
    echo "Error handling: works\n";
}

// Test 7: Function exists checks
$fns = [
    'boringssl_context_new', 'boringssl_context_new_server',
    'boringssl_context_set_cipher_list', 'boringssl_context_set_groups_list',
    'boringssl_context_set_grease', 'boringssl_context_set_permute_extensions',
    'boringssl_context_add_cert_compression_alg',
    'boringssl_new_connection', 'boringssl_set_stream', 'boringssl_set_fd',
    'boringssl_connect', 'boringssl_accept',
    'boringssl_read', 'boringssl_write', 'boringssl_pending', 'boringssl_shutdown',
    'boringssl_get_cipher', 'boringssl_get_group', 'boringssl_get_version',
    'boringssl_get_session', 'boringssl_set_session',
    'boringssl_session_from_bytes', 'boringssl_session_to_bytes',
    'boringssl_session_get_id', 'boringssl_session_get_timeout',
    'boringssl_session_has_ticket',
];
$all_exist = true;
foreach ($fns as $fn) {
    if (!function_exists($fn)) { echo "MISSING: $fn\n"; $all_exist = false; }
}
echo "All " . count($fns) . " functions registered: " . ($all_exist ? "yes" : "FAIL") . "\n";

echo "Procedural API tests passed\n";
?>
--EXPECTF--
Context configured
Cipher: TLS_AES_128_GCM_SHA256
Group: X25519
Version: 0x304
Response: HTTP/1.1 200 OK
Pending > 0: yes
Server context: BoringSSL\Context
Procedural cipher: TLS_AES_128_GCM_SHA256
OOP cipher: TLS_AES_128_GCM_SHA256
Match: yes
Session %s
%a
Error handling: works
All 26 functions registered: yes
Procedural API tests passed
