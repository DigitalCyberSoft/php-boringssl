--TEST--
TLS 1.3 cipher suite negotiation - PHP OpenSSL silently ignores cipher config
--EXTENSIONS--
boringssl
--FILE--
<?php
// PHP's openssl extension accepts TLS 1.3 cipher suite config via
// stream_context but silently ignores it (known PHP bug).
//
// BoringSSL takes a different approach: TLS 1.3 ciphers have a built-in
// preference order and are always all enabled. TLS 1.2 ciphers are fully
// configurable via setCipherList(). This test verifies both.

// Test 1: TLS 1.3 always negotiates (ciphers are built-in)
$ctx1 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

$tcp1 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn1 = $ctx1->newConnection()->setStream($tcp1);
$conn1->connect();
$cipher1 = $conn1->getNegotiatedCipher();
$version1 = $conn1->getProtocolVersion();
echo "TLS 1.3 cipher: $cipher1\n";
echo "Protocol: 0x" . dechex($version1) . "\n";
$conn1->shutdown();
fclose($tcp1);

// Test 2: TLS 1.2 cipher control works - force CHACHA20
$ctx2 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_2_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_2_VERSION)
    ->setGroupsList('X25519:P-256')
    ->setCipherList('ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305');

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx2->newConnection()->setStream($tcp2);
$conn2->connect();
$cipher2 = $conn2->getNegotiatedCipher();
echo "TLS 1.2 CHACHA20 only: $cipher2\n";
$conn2->shutdown();
fclose($tcp2);

// Test 3: TLS 1.2 cipher control - force AES-256
$ctx3 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_2_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_2_VERSION)
    ->setGroupsList('X25519:P-256')
    ->setCipherList('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384');

$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = $ctx3->newConnection()->setStream($tcp3);
$conn3->connect();
$cipher3 = $conn3->getNegotiatedCipher();
echo "TLS 1.2 AES-256 only: $cipher3\n";
$conn3->shutdown();
fclose($tcp3);

// Verify TLS 1.2 ciphers are distinct
if ($cipher2 !== $cipher3) {
    echo "TLS 1.2 cipher control works: distinct ciphers negotiated\n";
} else {
    echo "FAIL: TLS 1.2 ciphers not distinct\n";
}

// Test 4: setCipherSuites emits notice (BoringSSL doesn't support it)
$ctx4 = (new BoringSSL\Context())->new();
$ctx4->setCipherSuites('TLS_AES_256_GCM_SHA384');
echo "setCipherSuites accepted (no-op with notice)\n";
?>
--EXPECTF--
TLS 1.3 cipher: TLS_AES_128_GCM_SHA256
Protocol: 0x304
TLS 1.2 CHACHA20 only: ECDHE-RSA-CHACHA20-POLY1305
TLS 1.2 AES-256 only: ECDHE-RSA-AES256-GCM-SHA384
TLS 1.2 cipher control works: distinct ciphers negotiated

Notice: BoringSSL\Context::setCipherSuites(): BoringSSL does not support configuring TLS 1.3 cipher suites. TLS 1.3 ciphers have a built-in preference order and are always enabled. Use setCipherList() for TLS 1.2 cipher control. in %s on line %d
setCipherSuites accepted (no-op with notice)
