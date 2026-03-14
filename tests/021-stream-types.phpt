--TEST--
setStream() with different PHP stream types
--EXTENSIONS--
boringssl
--FILE--
<?php
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

// Test 1: stream_socket_client (TCP stream)
$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn1 = $ctx->newConnection()->setStream($tcp);
$conn1->connect();
echo "stream_socket_client: " . $conn1->getNegotiatedCipher() . "\n";
$conn1->shutdown();
fclose($tcp);

// Test 2: fsockopen (legacy PHP socket function)
$fsock = fsockopen('www.google.com', 443, $errno, $errstr, 10);
if (!$fsock) { echo "FAIL: fsockopen\n"; exit; }
$conn2 = $ctx->newConnection()->setStream($fsock);
$conn2->connect();
echo "fsockopen: " . $conn2->getNegotiatedCipher() . "\n";
$conn2->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$resp = $conn2->read(32);
echo "fsockopen I/O: " . strtok($resp, "\r\n") . "\n";
$conn2->shutdown();
fclose($fsock);

// Test 3: File stream - has an fd but TLS handshake will fail (not a socket)
$tmpfile = tmpfile();
$conn3 = $ctx->newConnection()->setStream($tmpfile);
try {
    $conn3->connect();
    echo "File stream connect: succeeded (unexpected but fd is valid)\n";
} catch (BoringSSL\Exception $e) {
    echo "File stream connect failed: OK (not a network socket)\n";
}
fclose($tmpfile);

// Test 4: Null argument
try {
    $ctx->newConnection()->setStream(null);
    echo "FAIL: should reject null\n";
} catch (\TypeError $e) {
    echo "Null rejected: OK\n";
}

// Test 5: Already-closed stream
$tcp5 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
fclose($tcp5);
try {
    $ctx->newConnection()->setStream($tcp5);
    echo "FAIL: should reject closed stream\n";
} catch (\TypeError $e) {
    echo "Closed stream rejected: TypeError\n";
}

// Test 6: Non-stream type
try {
    $ctx->newConnection()->setStream(42);
    echo "FAIL: should reject integer\n";
} catch (\TypeError $e) {
    echo "Integer rejected: OK\n";
}

try {
    $ctx->newConnection()->setStream("not a stream");
    echo "FAIL: should reject string\n";
} catch (\TypeError $e) {
    echo "String rejected: OK\n";
}

echo "Stream type tests passed\n";
?>
--EXPECTF--
stream_socket_client: TLS_AES_128_GCM_SHA256
fsockopen: TLS_AES_128_GCM_SHA256
fsockopen I/O: HTTP/1.1 200 OK
File stream connect failed: OK (not a network socket)
Null rejected: OK
Closed stream rejected: TypeError
Integer rejected: OK
String rejected: OK
Stream type tests passed
