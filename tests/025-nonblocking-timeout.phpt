--TEST--
Non-blocking sockets and timeout behavior
--EXTENSIONS--
boringssl
sockets
--FILE--
<?php
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

// Test 1: Blocking stream with timeout
$tcp1 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
stream_set_timeout($tcp1, 5);
$conn1 = $ctx->newConnection()->setStream($tcp1);
$conn1->connect();
echo "Blocking stream with timeout: " . $conn1->getNegotiatedCipher() . "\n";
$conn1->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$resp = $conn1->read(128);
echo "Read: " . strtok($resp, "\r\n") . "\n";
$conn1->shutdown();
fclose($tcp1);

// Test 2: Unreachable host TCP timeout
$start = microtime(true);
$tcp2 = @stream_socket_client('tcp://192.0.2.1:443', $errno, $errstr, 2);
$elapsed = microtime(true) - $start;
if ($tcp2 === false) {
    echo "Unreachable host: TCP timeout after " . round($elapsed, 0) . "s\n";
} else {
    echo "Unreachable host: unexpectedly connected\n";
    fclose($tcp2);
}

// Test 3: Handshake to non-TLS port
$tcp3 = @stream_socket_client('tcp://www.google.com:80', $errno, $errstr, 5);
if ($tcp3) {
    $conn3 = $ctx->newConnection()->setStream($tcp3);
    try {
        $conn3->connect();
        echo "FAIL: should not handshake on port 80\n";
    } catch (BoringSSL\Exception $e) {
        echo "Non-TLS port: handshake failed as expected\n";
    }
    fclose($tcp3);
}

// Test 4: Socket with SO_RCVTIMEO via socket_export_stream
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);
socket_connect($sock, gethostbyname('www.google.com'), 443);
socket_set_block($sock);
$stream4 = socket_export_stream($sock);

$conn4 = $ctx->newConnection()->setStream($stream4);
$conn4->connect();
echo "Socket with SO_RCVTIMEO: " . $conn4->getNegotiatedCipher() . "\n";
$conn4->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$resp4 = $conn4->read(64);
echo "Socket read: " . strtok($resp4, "\r\n") . "\n";
$conn4->shutdown();
fclose($stream4);

// Test 5: Very small stream read buffer
$tcp5 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
stream_set_read_buffer($tcp5, 64);
$conn5 = $ctx->newConnection()->setStream($tcp5);
$conn5->connect();
echo "Small read buffer: " . $conn5->getNegotiatedCipher() . "\n";
$conn5->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$resp5 = $conn5->read(32);
echo "Small buffer read: " . strlen($resp5) . " bytes\n";
$conn5->shutdown();
fclose($tcp5);

echo "Timeout tests passed\n";
?>
--EXPECTF--
Blocking stream with timeout: TLS_AES_128_GCM_SHA256
Read: HTTP/1.1 200 OK
Unreachable host: TCP timeout after %ds
Non-TLS port: handshake failed as expected
Socket with SO_RCVTIMEO: TLS_AES_128_GCM_SHA256
Socket read: HTTP/1.1 200 OK
Small read buffer: TLS_AES_128_GCM_SHA256
Small buffer read: 32 bytes
Timeout tests passed
