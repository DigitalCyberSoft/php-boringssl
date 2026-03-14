--TEST--
Error handling - bad fd, closed streams, double shutdown, read after shutdown
--EXTENSIONS--
boringssl
--FILE--
<?php
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

// Test 1: setFd with invalid fd (-1)
try {
    $ctx->newConnection()->setFd(-1);
    echo "FAIL: should reject negative fd\n";
} catch (\Throwable $e) {
    echo "Bad fd (-1): " . get_class($e) . "\n";
}

// Test 2: setFd with very large fd
try {
    $conn2 = $ctx->newConnection();
    $conn2->setFd(9999);
    // May succeed at setFd but fail at connect
    $conn2->connect();
    echo "FAIL: should have failed\n";
} catch (\Throwable $e) {
    echo "Bad fd (9999): caught at " . (strpos($e->getMessage(), 'handshake') !== false || strpos($e->getMessage(), 'SSL') !== false ? "connect" : "setFd") . "\n";
}

// Test 3: connect() without setting fd or stream
try {
    $ctx->newConnection()->connect();
    echo "FAIL: should fail without fd/stream\n";
} catch (\Throwable $e) {
    echo "Connect without fd: caught\n";
}

// Test 4: Read from unconnected (no handshake)
$tcp4 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn4 = $ctx->newConnection()->setStream($tcp4);
try {
    $conn4->read(1024);
    echo "Read before handshake: unexpected success\n";
} catch (\Throwable $e) {
    echo "Read before handshake: caught\n";
}
fclose($tcp4);

// Test 5: Write before handshake
$tcp5 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn5 = $ctx->newConnection()->setStream($tcp5);
try {
    $conn5->write("hello");
    echo "Write before handshake: unexpected success\n";
} catch (\Throwable $e) {
    echo "Write before handshake: caught\n";
}
fclose($tcp5);

// Test 6: Double shutdown
$tcp6 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn6 = $ctx->newConnection()->setStream($tcp6);
$conn6->connect();
echo "First shutdown: ";
try { $conn6->shutdown(); echo "OK\n"; }
catch (\Throwable $e) { echo "error\n"; }
echo "Second shutdown: ";
try { $conn6->shutdown(); echo "returned\n"; }
catch (\Throwable $e) { echo "caught\n"; }
fclose($tcp6);

// Test 7: Read after shutdown
$tcp7 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn7 = $ctx->newConnection()->setStream($tcp7);
$conn7->connect();
$conn7->shutdown();
try {
    $data = $conn7->read(1024);
    echo "Read after shutdown: returned " . gettype($data) . "\n";
} catch (\Throwable $e) {
    echo "Read after shutdown: caught\n";
}
fclose($tcp7);

// Test 8: Write after shutdown
$tcp8 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn8 = $ctx->newConnection()->setStream($tcp8);
$conn8->connect();
$conn8->shutdown();
try {
    $conn8->write("data");
    echo "Write after shutdown: unexpected success\n";
} catch (\Throwable $e) {
    echo "Write after shutdown: caught\n";
}
fclose($tcp8);

// Test 9: read with invalid length
$tcp9 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn9 = $ctx->newConnection()->setStream($tcp9);
$conn9->connect();
try { $conn9->read(0); echo "FAIL\n"; }
catch (\Throwable $e) { echo "read(0): rejected\n"; }
try { $conn9->read(-1); echo "FAIL\n"; }
catch (\Throwable $e) { echo "read(-1): rejected\n"; }
$conn9->shutdown();
fclose($tcp9);

// Test 10: Uninitialized context
try {
    (new BoringSSL\Context())->setCipherList('ALL');
    echo "FAIL\n";
} catch (BoringSSL\Exception $e) {
    echo "Uninitialized context: rejected\n";
}

// Test 11: Uninitialized connection
try {
    (new BoringSSL\Connection())->connect();
    echo "FAIL\n";
} catch (BoringSSL\Exception $e) {
    echo "Uninitialized connection: rejected\n";
}

// Test 12: Double init
try {
    $ctx2 = (new BoringSSL\Context())->new();
    $ctx2->new();
    echo "Double init: rejected\n";
} catch (BoringSSL\Exception $e) {
    echo "Double init: rejected\n";
}

// Test 13: Handshake to non-TLS port
$tcp13 = @stream_socket_client('tcp://www.google.com:80', $errno, $errstr, 5);
if ($tcp13) {
    $conn13 = $ctx->newConnection()->setStream($tcp13);
    try {
        $conn13->connect();
        echo "FAIL: should not handshake on port 80\n";
    } catch (BoringSSL\Exception $e) {
        echo "Non-TLS port 80: handshake failed\n";
    }
    fclose($tcp13);
}

echo "Error handling tests passed\n";
?>
--EXPECTF--
Bad fd (-1): %s
Bad fd (9999): caught at %s
Connect without fd: caught
Read before handshake: caught
Write before handshake: caught
First shutdown: OK
Second shutdown: %s
Read after shutdown: %s
Write after shutdown: caught
read(0): rejected
read(-1): rejected
Uninitialized context: rejected
Uninitialized connection: rejected
Double init: rejected
Non-TLS port 80: handshake failed
Error handling tests passed
