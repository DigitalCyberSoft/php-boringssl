--TEST--
TLS extension permutation (Chrome 119+) - not possible in PHP
--EXTENSIONS--
boringssl
--FILE--
<?php
// Chrome 119+ randomizes TLS extension order per connection using BoringSSL's
// SSL_CTX_set_permute_extensions. PHP has no control over extension ordering.
//
// The permutation is re-randomized for each SSL_connect call. We verify:
// 1. Multiple connections with permutation all succeed
// 2. The permutation doesn't break any TLS features
// 3. Combined with GREASE for maximum fingerprint variation

// Test 1: Permutation enabled, multiple connections
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256:P-384')
    ->setGreaseEnabled(true)
    ->setPermuteExtensions(true)
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_BROTLI)
    ->addApplicationSettings('h2', '')
    ->setAlpsUseNewCodepoint(true);

$results = [];
for ($i = 0; $i < 5; $i++) {
    $tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
    if (!$tcp) { echo "FAIL: TCP connect $i\n"; continue; }
    $conn = $ctx->newConnection()->setStream($tcp);
    if ($conn->connect()) {
        $results[] = [
            'cipher' => $conn->getNegotiatedCipher(),
            'group' => $conn->getNegotiatedGroup(),
            'version' => $conn->getProtocolVersion(),
        ];
    } else {
        echo "FAIL: handshake $i\n";
    }
    $conn->shutdown();
    fclose($tcp);
}

echo "Permuted connections: " . count($results) . "/5 succeeded\n";

// All should negotiate TLS 1.3
$all_tls13 = true;
foreach ($results as $r) {
    if ($r['version'] !== BoringSSL\TLS1_3_VERSION) {
        $all_tls13 = false;
    }
}
echo "All TLS 1.3: " . ($all_tls13 ? "yes" : "FAIL") . "\n";

// Test 2: Permutation disabled (deterministic order)
$ctx2 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->setPermuteExtensions(false);

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx2->newConnection()->setStream($tcp2);
$conn2->connect();
echo "Non-permuted: " . $conn2->getNegotiatedCipher() . "\n";
$conn2->shutdown();
fclose($tcp2);

echo "Extension permutation tests passed\n";
?>
--EXPECT--
Permuted connections: 5/5 succeeded
All TLS 1.3: yes
Non-permuted: TLS_AES_128_GCM_SHA256
Extension permutation tests passed
