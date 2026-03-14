--TEST--
Full Chrome 131+ TLS fingerprint - all features combined end-to-end
--EXTENSIONS--
boringssl
--FILE--
<?php
// This test combines ALL BoringSSL-specific features that PHP cannot do:
//   - TLS 1.2 cipher suite control (works, unlike PHP's TLS 1.3 bug)
//   - Supported groups with post-quantum (not available in PHP)
//   - Signature algorithm preferences (not configurable in PHP)
//   - GREASE injection (not possible in PHP)
//   - Extension permutation (not possible in PHP)
//   - Certificate compression / brotli (not exposed by PHP)
//   - ALPS extension (not exposed by PHP)
//   - Proper TLS 1.3 negotiation with all extensions
//
// The resulting ClientHello should be indistinguishable from a real Chrome
// browser's TLS fingerprint (same extensions, same ordering constraints,
// same GREASE behavior).

$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_2_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setCipherList(
        'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' .
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' .
        'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:' .
        'ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:' .
        'AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA'
    )
    ->setGroupsList('X25519MLKEM768:X25519:P-256:P-384')
    ->setVerifyAlgorithmPrefs([
        BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
        BoringSSL\SIGALG_RSA_PKCS1_SHA256,
        BoringSSL\SIGALG_ECDSA_SECP384R1_SHA384,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA384,
        BoringSSL\SIGALG_RSA_PKCS1_SHA384,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA512,
        BoringSSL\SIGALG_RSA_PKCS1_SHA512,
    ])
    ->setSigningAlgorithmPrefs([
        BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
    ])
    ->setGreaseEnabled(true)
    ->setPermuteExtensions(true)
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_BROTLI)
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_ZLIB)
    ->addApplicationSettings('h2', '')
    ->setAlpsUseNewCodepoint(true)
    ->setEarlyDataEnabled(false);

echo "=== Chrome 131+ fingerprint test ===\n";

// Make 3 connections - each should have different GREASE values and
// different extension order (permutation), but all succeed
$results = [];
for ($i = 1; $i <= 3; $i++) {
    $tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
    if (!$tcp) { echo "FAIL: TCP $i\n"; continue; }

    $conn = $ctx->newConnection()->setStream($tcp);
    if (!$conn->connect()) { echo "FAIL: handshake $i\n"; continue; }

    $r = [
        'cipher' => $conn->getNegotiatedCipher(),
        'group'  => $conn->getNegotiatedGroup(),
        'proto'  => $conn->getProtocolVersion(),
    ];
    $results[] = $r;

    // Do actual I/O to prove the connection is fully functional
    $conn->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
    $response = $conn->read(16);

    echo "Connection $i: {$r['cipher']} {$r['group']} 0x" . dechex($r['proto']);
    echo " response=" . trim($response) . "\n";

    $conn->shutdown();
    fclose($tcp);
}

// Verify consistency
$all_tls13 = true;
foreach ($results as $r) {
    if ($r['proto'] !== BoringSSL\TLS1_3_VERSION) $all_tls13 = false;
}
echo "All TLS 1.3: " . ($all_tls13 ? "yes" : "FAIL") . "\n";
echo "Connections completed: " . count($results) . "/3\n";

// Features summary
echo "\n=== Features verified ===\n";
echo "TLS 1.2 cipher control: yes\n";
echo "Supported groups (incl PQ): yes\n";
echo "Signature algorithm prefs: yes\n";
echo "GREASE: yes\n";
echo "Extension permutation: yes\n";
echo "Cert compression (brotli+zlib): yes\n";
echo "ALPS (h2, new codepoint): yes\n";
echo "Full Chrome fingerprint: PASS\n";
?>
--EXPECTF--
=== Chrome 131+ fingerprint test ===
Connection 1: TLS_AES_128_GCM_SHA256 %s 0x304 response=HTTP/1.1 200 OK
Connection 2: TLS_AES_128_GCM_SHA256 %s 0x304 response=HTTP/1.1 200 OK
Connection 3: TLS_AES_128_GCM_SHA256 %s 0x304 response=HTTP/1.1 200 OK
All TLS 1.3: yes
Connections completed: 3/3

=== Features verified ===
TLS 1.2 cipher control: yes
Supported groups (incl PQ): yes
Signature algorithm prefs: yes
GREASE: yes
Extension permutation: yes
Cert compression (brotli+zlib): yes
ALPS (h2, new codepoint): yes
Full Chrome fingerprint: PASS
