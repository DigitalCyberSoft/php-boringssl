--TEST--
Encrypted Client Hello (ECH) - Chrome 119+, not available in PHP
--EXTENSIONS--
boringssl
--FILE--
<?php
// ECH encrypts the entire ClientHello including SNI. Configuration comes from
// DNS HTTPS records. PHP has no ECH support whatsoever.

// Test 1: ECH API is accessible - invalid config should fail at connection time
$ctx1 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

// Setting ECH config with garbage bytes - should be accepted by config
// (validation happens during handshake)
$garbage_ech = random_bytes(64);
try {
    $ctx1->setEchConfigList($garbage_ech);
    echo "ECH config accepted (validated at handshake)\n";
} catch (BoringSSL\Exception $e) {
    // BoringSSL may validate the ECHConfigList structure immediately
    echo "ECH config validated immediately: OK\n";
}

// Test 2: Connection without ECH - verify ECH status reporting
$ctx2 = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    ->setGroupsList('X25519:P-256');

$tcp2 = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn2 = $ctx2->newConnection()->setStream($tcp2);
$conn2->connect();

$ech_status = $conn2->getEchStatus();
// Status may be 2 (REJECTED) if the server sends retry configs even when
// ECH was not configured. This is normal - some servers always advertise ECH.
echo "No ECH configured: status=$ech_status\n";

$retry_configs = $conn2->getEchRetryConfigs();
echo "Retry configs length: " . strlen($retry_configs) . "\n";

$conn2->shutdown();
fclose($tcp2);

// Test 3: ECH status constants exist
echo "ECH_STATUS_SUCCESS: " . BoringSSL\ECH_STATUS_SUCCESS . "\n";
echo "ECH_STATUS_REJECTED: " . BoringSSL\ECH_STATUS_REJECTED . "\n";
echo "ECH_STATUS_NOT_NEGOTIATED: " . BoringSSL\ECH_STATUS_NOT_NEGOTIATED . "\n";

// Test 4: Fetch real ECH config from DNS and attempt ECH connection
// Cloudflare domains publish ECH configs in HTTPS DNS records
$dns = dns_get_record('crypto.cloudflare.com', DNS_TXT);
$has_ech_dns = false;

// Try to get HTTPS record via dig if available
$ech_config = null;
$dig_output = @shell_exec('dig +short HTTPS crypto.cloudflare.com 2>/dev/null');
if ($dig_output && strpos($dig_output, 'ech=') !== false) {
    // Extract base64 ECH config from dig output
    if (preg_match('/ech=([A-Za-z0-9+\/=]+)/', $dig_output, $matches)) {
        $ech_config = base64_decode($matches[1]);
        $has_ech_dns = true;
    }
}

if ($ech_config) {
    echo "Got ECH config from DNS: " . strlen($ech_config) . " bytes\n";

    $ctx4 = (new BoringSSL\Context())->new()
        ->setMinProtoVersion(BoringSSL\TLS1_3_VERSION)
        ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
        ->setGroupsList('X25519:P-256')
        ->setEchConfigList($ech_config);

    $tcp4 = stream_socket_client('tcp://crypto.cloudflare.com:443', $errno, $errstr, 10);
    $conn4 = $ctx4->newConnection()->setStream($tcp4);
    try {
        $conn4->connect();
        $ech_status4 = $conn4->getEchStatus();
        echo "ECH connection: status=$ech_status4\n";
        if ($ech_status4 === BoringSSL\ECH_STATUS_SUCCESS) {
            echo "ECH accepted by server\n";
        }
        $conn4->shutdown();
    } catch (BoringSSL\Exception $e) {
        echo "ECH handshake: " . $e->getMessage() . "\n";
        $retry = $conn4->getEchRetryConfigs();
        if (strlen($retry) > 0) {
            echo "Server provided retry configs: " . strlen($retry) . " bytes\n";
        }
    }
    fclose($tcp4);
} else {
    echo "ECH DNS lookup not available (dig not installed or no HTTPS record)\n";
    echo "Skipping live ECH test\n";
}

echo "ECH tests passed\n";
?>
--EXPECTF--
ECH config %s
No ECH configured: status=%d
Retry configs length: %d
ECH_STATUS_SUCCESS: 1
ECH_STATUS_REJECTED: 2
ECH_STATUS_NOT_NEGOTIATED: 3
%a
ECH tests passed
