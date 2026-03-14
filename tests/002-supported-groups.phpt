--TEST--
Supported groups / elliptic curves - not configurable in PHP OpenSSL
--EXTENSIONS--
boringssl
--FILE--
<?php
// PHP's stream_context has no mechanism to control which elliptic curves
// or supported groups are offered. BoringSSL exposes full control.

// Test 1: X25519 only
$ctx1 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519');

$tcp1 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn1 = $ctx1->newConnection()->setStream($tcp1);
$conn1->connect();
echo "X25519 only: " . $conn1->getNegotiatedGroup() . "\n";
$conn1->shutdown();
fclose($tcp1);

// Test 2: P-256 only
$ctx2 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('P-256');

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx2->newConnection()->setStream($tcp2);
$conn2->connect();
echo "P-256 only: " . $conn2->getNegotiatedGroup() . "\n";
$conn2->shutdown();
fclose($tcp2);

// Test 3: Multiple groups offered - server selects from available key shares
// In TLS 1.3, the client sends key_share for the first group. If the server
// doesn't support it, it sends HelloRetryRequest. When the client offers
// P-256 first, BoringSSL sends a P-256 key share. The server may still
// prefer X25519 and trigger a HelloRetryRequest, or accept P-256.
$ctx3 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('P-256:X25519:P-384');

$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = $ctx3->newConnection()->setStream($tcp3);
$conn3->connect();
$group3 = $conn3->getNegotiatedGroup();
$valid3 = in_array($group3, ['P-256', 'X25519']);
echo "Multiple groups offered: $group3 (valid=" . ($valid3 ? "yes" : "FAIL") . ")\n";
$conn3->shutdown();
fclose($tcp3);

// Test 4: Multiple groups, X25519 preferred
$ctx4 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256:P-384');

$tcp4 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn4 = $ctx4->newConnection()->setStream($tcp4);
$conn4->connect();
echo "X25519 first preference: " . $conn4->getNegotiatedGroup() . "\n";
$conn4->shutdown();
fclose($tcp4);

// Test 5: Invalid group name
try {
    (new BoringSSL\Context())->new()->setGroupsList('INVALID_GROUP');
    echo "FAIL: should have rejected invalid group\n";
} catch (BoringSSL\Exception $e) {
    echo "Invalid group rejected: OK\n";
}
?>
--EXPECTF--
X25519 only: X25519
P-256 only: P-256
Multiple groups offered: %s (valid=yes)
X25519 first preference: X25519
Invalid group rejected: OK
