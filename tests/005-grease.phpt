--TEST--
GREASE (RFC 8701) injection - not possible in PHP
--EXTENSIONS--
boringssl
--FILE--
<?php
// GREASE (Generate Random Extensions And Sustain Extensibility) injects fake
// reserved values into cipher suites, groups, extensions, versions, and key
// shares. PHP has no mechanism to enable this. BoringSSL has a single toggle.
//
// We can't inspect the wire-level ClientHello from PHP, but we verify:
// 1. GREASE-enabled connections succeed (servers must ignore GREASE values)
// 2. Multiple connections with GREASE each succeed (values are randomized)

// Test 1: GREASE enabled, connect to Google
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256:P-384')
    ->setGreaseEnabled(true);

$successes = 0;
for ($i = 0; $i < 3; $i++) {
    $tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
    if (!$tcp) { echo "FAIL: TCP connect $i\n"; continue; }
    $conn = $ctx->newConnection()->setStream($tcp);
    if ($conn->connect()) {
        $successes++;
    }
    $conn->shutdown();
    fclose($tcp);
}
echo "GREASE connections succeeded: $successes/3\n";

// Test 2: GREASE with Cloudflare (different server implementation)
$tcp2 = stream_socket_client('tcp://cloudflare.com:443', $errno, $errstr, 10);
$conn2 = $ctx->newConnection()->setStream($tcp2);
$conn2->connect();
echo "GREASE + Cloudflare: " . $conn2->getNegotiatedCipher() . "\n";
$conn2->shutdown();
fclose($tcp2);

// Test 3: GREASE disabled should also work (baseline)
$ctx_no_grease = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256')
    ->setGreaseEnabled(false);

$tcp3 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn3 = $ctx_no_grease->newConnection()->setStream($tcp3);
$conn3->connect();
echo "No GREASE baseline: " . $conn3->getNegotiatedCipher() . "\n";
$conn3->shutdown();
fclose($tcp3);

echo "GREASE tests passed\n";
?>
--EXPECT--
GREASE connections succeeded: 3/3
GREASE + Cloudflare: TLS_AES_128_GCM_SHA256
No GREASE baseline: TLS_AES_128_GCM_SHA256
GREASE tests passed
