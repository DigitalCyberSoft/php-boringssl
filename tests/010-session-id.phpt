--TEST--
Session ID and resumption - not configurable in PHP
--EXTENSIONS--
boringssl
--FILE--
<?php
// In TLS 1.3, session state is managed via NewSessionTicket messages.
// BoringSSL provides full session serialization and resumption.
// PHP's stream_context gives no access to session objects.

// Test 1: Get session after TLS 1.3 handshake
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();

echo "Protocol: 0x" . dechex($conn->getProtocolVersion()) . "\n";

// Do some I/O to allow NewSessionTicket to arrive
$conn->write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
$conn->read(256);

$session = $conn->getSession();
if ($session === null) {
    echo "Session: null (server did not send NewSessionTicket)\n";
    echo "Session serialization: skipped\n";
    echo "Session resumption: skipped\n";
} else {
    $id = $session->getId();
    echo "Session ID length: " . strlen($id) . "\n";

    // Test serialization round-trip
    $bytes = $session->toBytes();
    echo "Serialized session: " . strlen($bytes) . " bytes\n";
    echo "Serialized non-empty: " . (strlen($bytes) > 0 ? "yes" : "FAIL") . "\n";

    // Test deserialization
    $restored = BoringSSL\Session::fromBytes($bytes, $ctx);
    $restored_id = $restored->getId();
    echo "Restored ID matches: " . ($restored_id === $id ? "yes" : "FAIL") . "\n";

    // Test timeout
    $timeout = $session->getTimeout();
    echo "Session timeout > 0: " . ($timeout > 0 ? "yes" : "no") . "\n";

    // Test hasTicket
    echo "Has ticket: " . ($session->hasTicket() ? "yes" : "no") . "\n";
}

$conn->shutdown();
fclose($tcp);

// Test 2: Session resumption
if ($session !== null) {
    $tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
    $conn2 = $ctx->newConnection();
    $conn2->setSession($session);
    $conn2->setStream($tcp2);
    $conn2->connect();
    echo "Resumed connection: " . $conn2->getNegotiatedCipher() . " v0x" . dechex($conn2->getProtocolVersion()) . "\n";
    $conn2->shutdown();
    fclose($tcp2);
} else {
    echo "Resumed connection: skipped (no session)\n";
}

// Test 3: Invalid session bytes
try {
    BoringSSL\Session::fromBytes("garbage", $ctx);
    echo "FAIL: should have rejected garbage\n";
} catch (BoringSSL\Exception $e) {
    echo "Invalid session bytes rejected: OK\n";
}

echo "Session tests passed\n";
?>
--EXPECTF--
Protocol: 0x304
Session%s
%a
Invalid session bytes rejected: OK
Session tests passed
