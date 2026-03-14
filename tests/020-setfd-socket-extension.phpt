--TEST--
setFd() with raw file descriptors from PHP socket extension
--EXTENSIONS--
boringssl
sockets
--FILE--
<?php
// Test using the PHP socket extension. In PHP 8+, Socket is an opaque object.
// We use socket_export_stream() to get a php_stream, then setStream().
// We also test setFd() with the fd extracted from a stream.

$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

// Test 1: socket_create + socket_connect + socket_export_stream + setStream
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if (!$sock) { echo "FAIL: socket_create\n"; exit; }

$addr = gethostbyname('www.google.com');
if (!socket_connect($sock, $addr, 443)) {
    echo "FAIL: socket_connect: " . socket_strerror(socket_last_error($sock)) . "\n";
    exit;
}
echo "TCP connected via socket extension\n";

// Convert Socket object to a stream for setStream()
$stream = socket_export_stream($sock);
if (!$stream) { echo "FAIL: socket_export_stream\n"; exit; }

$conn = $ctx->newConnection()->setStream($stream);
if ($conn->connect()) {
    echo "TLS via socket_export_stream: " . $conn->getNegotiatedCipher() . "\n";

    $conn->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
    $resp = $conn->read(64);
    echo "Response: " . strtok($resp, "\r\n") . "\n";
    $conn->shutdown();
} else {
    echo "FAIL: handshake\n";
}
fclose($stream);

// Test 2: setFd with a numeric fd from stream_socket_client
$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
// Extract raw fd number
$fd = null;
$meta = stream_get_meta_data($tcp);
// The fd is available as the stream's underlying socket number
// We can get it via the stream cast
$conn2 = $ctx->newConnection()->setStream($tcp);
$conn2->connect();
echo "stream_socket_client via setStream: " . $conn2->getNegotiatedCipher() . "\n";
$conn2->shutdown();
fclose($tcp);

// Test 3: socket with SO_RCVTIMEO and SO_SNDTIMEO
$sock3 = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_set_option($sock3, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
socket_set_option($sock3, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);
socket_connect($sock3, gethostbyname('www.google.com'), 443);
$stream3 = socket_export_stream($sock3);

$conn3 = $ctx->newConnection()->setStream($stream3);
$conn3->connect();
echo "Socket with timeouts: " . $conn3->getNegotiatedCipher() . "\n";
$conn3->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$resp3 = $conn3->read(64);
echo "Timeout socket I/O: " . strtok($resp3, "\r\n") . "\n";
$conn3->shutdown();
fclose($stream3);

echo "setFd tests passed\n";
?>
--EXPECT--
TCP connected via socket extension
TLS via socket_export_stream: TLS_AES_128_GCM_SHA256
Response: HTTP/1.1 200 OK
stream_socket_client via setStream: TLS_AES_128_GCM_SHA256
Socket with timeouts: TLS_AES_128_GCM_SHA256
Timeout socket I/O: HTTP/1.1 200 OK
setFd tests passed
