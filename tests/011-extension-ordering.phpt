--TEST--
TLS extension ordering - JA3/JA4 fingerprint basis, no control in PHP
--EXTENSIONS--
boringssl
--FILE--
<?php
// JA3/JA4 fingerprints are directly derived from TLS extension ordering.
// PHP's stream_socket_enable_crypto gives no control over extension order.
// BoringSSL produces a deterministic, known extension order when permutation
// is disabled, and supports all the extensions that Chrome includes.
//
// This test verifies that a full Chrome-like configuration successfully
// negotiates TLS, proving all extensions are being sent in a valid order.

// Chrome 131+ configuration
$ctx = (new BoringSSL\Context())->new()
    ->setMinProtoVersion(BoringSSL\TLS1_2_VERSION)
    ->setMaxProtoVersion(BoringSSL\TLS1_3_VERSION)
    // TLS 1.2 ciphers (Chrome order)
    ->setCipherList(
        'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:' .
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:' .
        'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:' .
        'ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:' .
        'AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA'
    )
    // Groups including post-quantum
    ->setGroupsList('X25519MLKEM768:X25519:P-256:P-384')
    // Signature algorithms (Chrome order)
    ->setVerifyAlgorithmPrefs([
        BoringSSL\SIGALG_ECDSA_SECP256R1_SHA256,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA256,
        BoringSSL\SIGALG_RSA_PKCS1_SHA256,
        BoringSSL\SIGALG_ECDSA_SECP384R1_SHA384,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA384,
        BoringSSL\SIGALG_RSA_PKCS1_SHA384,
        BoringSSL\SIGALG_RSA_PSS_RSAE_SHA512,
        BoringSSL\SIGALG_RSA_PKCS1_SHA512,
    ])
    // BoringSSL-specific extensions
    ->setGreaseEnabled(true)
    ->setPermuteExtensions(false)  // Deterministic order for this test
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_BROTLI)
    ->addCertCompressionAlg(BoringSSL\CERT_COMPRESS_ZLIB)
    ->addApplicationSettings('h2', '')
    ->setAlpsUseNewCodepoint(true)
    ->setEarlyDataEnabled(false);

// Connect to multiple servers to verify extension ordering works everywhere
$servers = [
    'www.google.com',
    'cloudflare.com',
    'www.microsoft.com',
];

foreach ($servers as $server) {
    $tcp = stream_socket_client("tcp://$server:443", $errno, $errstr, 10);
    if (!$tcp) {
        echo "$server: TCP failed\n";
        continue;
    }

    $conn = $ctx->newConnection()->setStream($tcp);
    try {
        if ($conn->connect()) {
            $cipher = $conn->getNegotiatedCipher();
            $group = $conn->getNegotiatedGroup();
            $version = '0x' . dechex($conn->getProtocolVersion());
            echo "$server: $cipher $group $version\n";
            $conn->shutdown();
        } else {
            echo "$server: handshake returned false\n";
        }
    } catch (BoringSSL\Exception $e) {
        echo "$server: " . $e->getMessage() . "\n";
    }
    fclose($tcp);
}

// Now with permutation enabled - same config should work with randomized order
$ctx->setPermuteExtensions(true);

$tcp = stream_socket_client('tcp://www.google.com:443', $errno, $errstr, 10);
$conn = $ctx->newConnection()->setStream($tcp);
$conn->connect();
echo "Permuted Chrome config: " . $conn->getNegotiatedCipher() . " " . $conn->getNegotiatedGroup() . "\n";
$conn->shutdown();
fclose($tcp);

echo "Extension ordering tests passed\n";
?>
--EXPECTF--
www.google.com: TLS_AES_128_GCM_SHA256 %s 0x304
cloudflare.com: TLS_AES_128_GCM_SHA256 %s 0x304
www.microsoft.com: TLS_AES_256_GCM_SHA384 %s 0x304
Permuted Chrome config: TLS_AES_128_GCM_SHA256 %s
Extension ordering tests passed
