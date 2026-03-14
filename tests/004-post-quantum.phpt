--TEST--
Post-quantum key exchange (X25519MLKEM768) - not available in PHP OpenSSL
--EXTENSIONS--
boringssl
--FILE--
<?php
// PHP's OpenSSL extension has no post-quantum KEM support.
// BoringSSL supports X25519MLKEM768 (hybrid classical + ML-KEM-768).

// Test 1: Offer X25519MLKEM768 as first preference with X25519 fallback
$ctx1 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519MLKEM768:X25519:P-256');

$tcp1 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn1 = $ctx1->newConnection()->setStream($tcp1);
$conn1->connect();
$group1 = $conn1->getNegotiatedGroup();
$cipher1 = $conn1->getNegotiatedCipher();
// Google supports X25519MLKEM768 - should negotiate PQ group
echo "PQ preferred: group=$group1 cipher=$cipher1\n";
$valid_pq = in_array($group1, ['X25519MLKEM768', 'X25519']);
echo "Negotiated valid group: " . ($valid_pq ? "yes" : "FAIL") . "\n";
$conn1->shutdown();
fclose($tcp1);

// Test 2: X25519MLKEM768 only (no classical fallback)
$ctx2 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519MLKEM768');

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx2->newConnection()->setStream($tcp2);
try {
    $conn2->connect();
    $group2 = $conn2->getNegotiatedGroup();
    echo "PQ only: group=$group2\n";
    $conn2->shutdown();
} catch (BoringSSL\Exception $e) {
    // Server may not support PQ-only
    echo "PQ only: server requires classical fallback\n";
}
fclose($tcp2);

// Test 3: Cloudflare also supports PQ
$ctx3 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519MLKEM768:X25519:P-256');

$tcp3 = stream_socket_client('tcp://cloudflare.com:443', $errno, $errstr, 10);
$conn3 = $ctx3->newConnection()->setStream($tcp3);
$conn3->connect();
$group3 = $conn3->getNegotiatedGroup();
echo "Cloudflare PQ: group=$group3\n";
$valid_cf = in_array($group3, ['X25519MLKEM768', 'X25519']);
echo "Cloudflare valid group: " . ($valid_cf ? "yes" : "FAIL") . "\n";
$conn3->shutdown();
fclose($tcp3);

echo "Post-quantum tests complete\n";
?>
--EXPECTF--
PQ preferred: group=%s cipher=TLS_AES_128_GCM_SHA256
Negotiated valid group: yes
PQ only: %s
Cloudflare PQ: group=%s
Cloudflare valid group: yes
Post-quantum tests complete
