--TEST--
Signature algorithm preferences - not configurable via PHP stream_context
--EXTENSIONS--
boringssl
--FILE--
<?php
// PHP's openssl extension uses compiled-in defaults for signature algorithms
// and provides no override. BoringSSL allows full control.

// Test 1: ECDSA + RSA-PSS algorithms (modern set)
$ctx1 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setVerifyAlgorithmPrefs([
        BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
        BoringSSL\SIGALG_ECDSA_SECP384R1_SHA384,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA384,
    ])
    ->setGroupsList('X25519:P-256');

$tcp1 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn1 = $ctx1->newConnection()->setStream($tcp1);
$conn1->connect();
echo "ECDSA+RSA-PSS: " . $conn1->getNegotiatedCipher() . " (v0x" . dechex($conn1->getProtocolVersion()) . ")\n";
$conn1->shutdown();
fclose($tcp1);

// Test 2: RSA PKCS#1 only (legacy set) - still works for verification
$ctx2 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setVerifyAlgorithmPrefs([
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA384,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA512,
        BoringSSL\SIGALG_RSA_PKCS1_SHA256,
        BoringSSL\SIGALG_RSA_PKCS1_SHA384,
    ])
    ->setGroupsList('X25519:P-256');

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx2->newConnection()->setStream($tcp2);
$conn2->connect();
echo "RSA only: " . $conn2->getNegotiatedCipher() . " (v0x" . dechex($conn2->getProtocolVersion()) . ")\n";
$conn2->shutdown();
fclose($tcp2);

// Test 3: Signing algorithm preferences (for mTLS client certs)
$ctx3 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setSigningAlgorithmPrefs([
        BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
    ])
    ->setVerifyAlgorithmPrefs([
        BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
        BoringSSL\SIGALG_RSA_PKCS1_SHA256,
    ])
    ->setGroupsList('X25519:P-256');

$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = $ctx3->newConnection()->setStream($tcp3);
$conn3->connect();
echo "With signing prefs: " . $conn3->getNegotiatedCipher() . " (v0x" . dechex($conn3->getProtocolVersion()) . ")\n";
$conn3->shutdown();
fclose($tcp3);

// Test 4: Empty array should fail
try {
    (new BoringSSL\Context())->new()->setVerifyAlgorithmPrefs([]);
    echo "FAIL: empty array should have thrown\n";
} catch (ValueError $e) {
    echo "Empty array rejected: OK\n";
}

echo "All signature algorithm tests passed\n";
?>
--EXPECT--
ECDSA+RSA-PSS: TLS_AES_128_GCM_SHA256 (v0x304)
RSA only: TLS_AES_128_GCM_SHA256 (v0x304)
With signing prefs: TLS_AES_128_GCM_SHA256 (v0x304)
Empty array rejected: OK
All signature algorithm tests passed
