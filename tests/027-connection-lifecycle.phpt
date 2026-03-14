--TEST--
Connection lifecycle - context reuse, multiple connections, cleanup
--EXTENSIONS--
boringssl
--FILE--
<?php
// Test that a single context can spawn multiple connections and that
// cleanup happens correctly (no leaks, no double-free).

$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->setGreaseEnabled(true)
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_BROTLI);

// Test 1: Multiple connections from same context
$connections = [];
for ($i = 0; $i < 3; $i++) {
    $tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
    $conn = $ctx->newConnection()->setStream($tcp);
    $conn->connect();
    $connections[] = ['conn' => $conn, 'tcp' => $tcp];
}

echo "Opened 3 connections from same context\n";

// All should be independently functional
for ($i = 0; $i < 3; $i++) {
    $c = $connections[$i]['conn'];
    $c->write("HEAD / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
    $resp = $c->read(64);
    echo "Connection $i: " . strtok($resp, "\r\n") . "\n";
}

// Shutdown in reverse order
for ($i = 2; $i >= 0; $i--) {
    $connections[$i]['conn']->shutdown();
    fclose($connections[$i]['tcp']);
}
echo "All 3 shut down in reverse order\n";
unset($connections);

// Test 2: Connection outlives its scope (GC)
function make_connection($ctx) {
    $tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
    $conn = $ctx->newConnection()->setStream($tcp);
    $conn->connect();
    $cipher = $conn->getNegotiatedCipher();
    $conn->shutdown();
    fclose($tcp);
    return $cipher;
}

$cipher = make_connection($ctx);
echo "Connection from function: $cipher\n";

// Test 3: Context survives after connections are freed
// The context holds the SSL_CTX which is ref-counted in BoringSSL
$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();
echo "After GC: " . $conn->getNegotiatedCipher() . "\n";
$conn->shutdown();
fclose($tcp);

// Test 4: Rapid create-connect-destroy cycle
for ($i = 0; $i < 5; $i++) {
    $tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
    $conn = $ctx->newConnection()->setStream($tcp);
    $conn->connect();
    $conn->write("HEAD / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
    $conn->read(64);
    $conn->shutdown();
    fclose($tcp);
    unset($conn);
}
echo "5 rapid cycles completed\n";

// Test 5: Multiple contexts
$ctx_a = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519');

$ctx_b = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('P-256');

$tcp_a = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$tcp_b = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);

$conn_a = $ctx_a->newConnection()->setStream($tcp_a);
$conn_b = $ctx_b->newConnection()->setStream($tcp_b);

$conn_a->connect();
$conn_b->connect();

echo "Context A group: " . $conn_a->getNegotiatedGroup() . "\n";
echo "Context B group: " . $conn_b->getNegotiatedGroup() . "\n";

$conn_a->shutdown(); fclose($tcp_a);
$conn_b->shutdown(); fclose($tcp_b);

echo "Lifecycle tests passed\n";
?>
--EXPECT--
Opened 3 connections from same context
Connection 0: HTTP/1.1 200 OK
Connection 1: HTTP/1.1 200 OK
Connection 2: HTTP/1.1 200 OK
All 3 shut down in reverse order
Connection from function: TLS_AES_128_GCM_SHA256
After GC: TLS_AES_128_GCM_SHA256
5 rapid cycles completed
Context A group: X25519
Context B group: P-256
Lifecycle tests passed
