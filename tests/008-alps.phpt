--TEST--
ALPS (Application-Layer Protocol Settings) - Chrome-specific, not exposed by PHP
--EXTENSIONS--
boringssl
--FILE--
<?php
// ALPS allows application-layer settings exchange during the TLS handshake.
// Chrome uses this for HTTP/2 SETTINGS negotiation. PHP has no ALPS support.

// Test 1: ALPS for h2 with new codepoint (Chrome current behavior)
$ctx1 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->addApplicationSettings('h2', '')
    ->setAlpsUseNewCodepoint(true);

$tcp1 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn1 = $ctx1->newConnection()->setStream($tcp1);
$conn1->connect();
echo "ALPS h2 new codepoint: " . $conn1->getNegotiatedCipher() . "\n";

// Check if server sent peer application settings
$peer_settings = $conn1->getPeerApplicationSettings('h2');
echo "Peer settings length: " . strlen($peer_settings) . "\n";
echo "Has peer settings: " . (strlen($peer_settings) > 0 ? "yes" : "no") . "\n";
$conn1->shutdown();
fclose($tcp1);

// Test 2: ALPS for h2 with legacy codepoint
$ctx2 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->addApplicationSettings('h2', '')
    ->setAlpsUseNewCodepoint(false);

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx2->newConnection()->setStream($tcp2);
$conn2->connect();
echo "ALPS h2 legacy codepoint: " . $conn2->getNegotiatedCipher() . "\n";
$conn2->shutdown();
fclose($tcp2);

// Test 3: ALPS with non-empty settings payload (HTTP/2 SETTINGS frame)
// A minimal HTTP/2 SETTINGS frame: SETTINGS_MAX_CONCURRENT_STREAMS=100
$h2_settings = pack('nN', 0x03, 100);  // type=3, value=100
$ctx3 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->addApplicationSettings('h2', $h2_settings)
    ->setAlpsUseNewCodepoint(true);

$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = $ctx3->newConnection()->setStream($tcp3);
$conn3->connect();
echo "ALPS with settings payload: " . $conn3->getNegotiatedCipher() . "\n";
$conn3->shutdown();
fclose($tcp3);

// Test 4: Multiple ALPN protocols with ALPS
$ctx4 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->addApplicationSettings('h2', '')
    ->addApplicationSettings('http/1.1', '')
    ->setAlpsUseNewCodepoint(true);

$tcp4 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn4 = $ctx4->newConnection()->setStream($tcp4);
$conn4->connect();
echo "ALPS multi-proto: " . $conn4->getNegotiatedCipher() . "\n";
$conn4->shutdown();
fclose($tcp4);

echo "ALPS tests passed\n";
?>
--EXPECTF--
ALPS h2 new codepoint: TLS_AES_128_GCM_SHA256
Peer settings length: %d
Has peer settings: %s
ALPS h2 legacy codepoint: TLS_AES_128_GCM_SHA256
ALPS with settings payload: TLS_AES_128_GCM_SHA256
ALPS multi-proto: TLS_AES_128_GCM_SHA256
ALPS tests passed
