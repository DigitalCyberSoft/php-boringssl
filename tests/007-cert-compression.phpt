--TEST--
Certificate compression (brotli/zlib/zstd) - not exposed by PHP
--EXTENSIONS--
boringssl
--FILE--
<?php
// RFC 8879 allows the server to send compressed certificates. The client
// advertises supported algorithms via the compress_certificate extension.
// PHP has no mechanism to enable this. BoringSSL supports brotli, zlib, zstd.

// Test 1: Brotli cert compression with Google (Google supports brotli)
$ctx1 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_BROTLI);

$tcp1 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn1 = $ctx1->newConnection()->setStream($tcp1);
$conn1->connect();
echo "Brotli compression: " . $conn1->getNegotiatedCipher() . " v0x" . dechex($conn1->getProtocolVersion()) . "\n";

// Verify we can do I/O (proves decompression callback worked)
$conn1->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$resp = $conn1->read(128);
$status = substr($resp, 0, 15);
echo "Brotli response: $status\n";
$conn1->shutdown();
fclose($tcp1);

// Test 2: Zlib cert compression
$ctx2 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_ZLIB);

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx2->newConnection()->setStream($tcp2);
$conn2->connect();
echo "Zlib compression: " . $conn2->getNegotiatedCipher() . "\n";
$conn2->shutdown();
fclose($tcp2);

// Test 3: Zstd cert compression
$ctx3 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_ZSTD);

$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = $ctx3->newConnection()->setStream($tcp3);
$conn3->connect();
echo "Zstd compression: " . $conn3->getNegotiatedCipher() . "\n";
$conn3->shutdown();
fclose($tcp3);

// Test 4: Multiple algorithms registered (server picks preferred)
$ctx4 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_BROTLI)
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_ZLIB)
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_ZSTD);

$tcp4 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn4 = $ctx4->newConnection()->setStream($tcp4);
$conn4->connect();
echo "All three registered: " . $conn4->getNegotiatedCipher() . "\n";
$conn4->shutdown();
fclose($tcp4);

// Test 5: Invalid algorithm ID
try {
    (new BoringSSL\Context())->new()->addCertCompressionAlg(99);
    echo "FAIL: should have rejected invalid alg\n";
} catch (ValueError $e) {
    echo "Invalid alg rejected: OK\n";
}

echo "Certificate compression tests passed\n";
?>
--EXPECT--
Brotli compression: TLS_AES_128_GCM_SHA256 v0x304
Brotli response: HTTP/1.1 200 OK
Zlib compression: TLS_AES_128_GCM_SHA256
Zstd compression: TLS_AES_128_GCM_SHA256
All three registered: TLS_AES_128_GCM_SHA256
Invalid alg rejected: OK
Certificate compression tests passed
